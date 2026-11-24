// Admin > Settings > Files and chats: the largest file upload (spec 039) and how long unused chats and the files
// uploaded to them are kept (spec 040), with a Preview and Run now. The two numbers are saved with the other settings
// (PUT /api/admin/settings: maxUploadMb, retentionDays); `values()` gives them to the settings tab's Save button.
import { h, input, field, section, table, banner, confirmDialog, toast, fmtBytes, fmtDateTime, actionBtn } from '../ui.js';
import { GET, POST, qs } from '../api.js';

function lastText(last) {
  if (!last || !last.at) return 'No sweep has run yet.';
  return 'Last sweep ' + fmtDateTime(last.at) + (last.manual ? ' (Run now' + (last.by ? ' by ' + last.by : '') + ')' : '') + ': ' +
    (last.chats || 0) + ' chat(s), ' + (last.files || 0) + ' file(s), ' + fmtBytes(last.bytes || 0) + ' deleted' +
    (last.busy ? '; ' + last.busy + ' in use, kept' : '') + (last.more ? '; more in the next sweeps' : '') +
    ((last.errors || []).length ? '; problems: ' + last.errors.join('; ') : '') + '.';
}

function report(r, verb) {
  if (r.off) return banner('info', 'Retention is off (0 days): nothing is deleted.');
  const rows = (r.users || []).filter((u) => u.chats || u.files || u.busy || u.error);
  return h('div', { class: 'stack-sm' },
    h('div', null, h('strong', null, r.chats + ' chat(s), ' + r.files + ' file(s), ' + fmtBytes(r.bytes || 0)), ' ' + verb +
      ' (' + r.days + ' days without use' + (r.busy ? '; ' + r.busy + ' chat(s) in use now are kept' : '') + ').'),
    rows.length ? table([
      { label: 'User', key: 'username' },
      { label: 'Chats', key: 'chats', class: 'right' },
      { label: 'Files', key: 'files', class: 'right' },
      { label: 'Size', class: 'right', render: (u) => fmtBytes(u.bytes || 0) },
      { label: 'In use (kept)', key: 'busy', class: 'right' },
      { label: 'Note', render: (u) => u.error || '' },
    ], rows) : null,
    r.more || (r.perSweep && r.chats > r.perSweep && r.dryRun) ? h('div', { class: 'muted small' }, 'At most ' + r.perSweep + ' chats are deleted per sweep; the rest go in the next sweeps (hourly).') : null,
    (r.errors || []).length ? banner('warn', r.errors.join('\n')) : null);
}

export function filesAndChatsSection(s) {
  const maxMb = Number(s.maxUploadMbMax) || 5120;
  const daysMax = Number(s.retentionDaysMax) || 3650;
  const up = input({ type: 'number', min: '1', max: String(maxMb), step: '1', value: s.maxUploadMb ?? 25, class: 'inp inp-sm' });
  const days = input({ type: 'number', min: '0', max: String(daysMax), step: '1', value: s.retentionDays ?? 180, class: 'inp inp-sm' });
  const daysValue = () => (String(days.value).trim() === '' ? Number(s.retentionDays ?? 180) : Math.max(0, Math.min(daysMax, Math.floor(Number(days.value) || 0))));
  const out = h('div', { class: 'stack-sm' });
  const lastEl = h('div', { class: 'muted small' }, lastText(s.retentionLast));
  const first = s.retentionFirstAutoRun && s.retentionFirstAutoRun * 1000 > Date.now()
    ? h('div', { class: 'muted small' }, 'Automatic deletion starts ' + fmtDateTime(s.retentionFirstAutoRun) + ' (7 days after retention first applied, so the preview can be checked first). Run now does not wait.')
    : null;
  const preview = actionBtn('Preview', async () => {
    out.replaceChildren(h('div', { class: 'muted small' }, 'Counting…'));
    const r = await GET('/api/admin/retention/preview' + qs({ days: daysValue() }));
    out.replaceChildren(report(r, 'would be deleted now'));
  }, { size: 'sm', icon: 'eye' });
  const runNow = actionBtn('Run now', async () => {
    const cur = await GET('/api/admin/retention');
    if (daysValue() !== Number(cur.retentionDays)) { toast('Save the settings first: Run now uses the saved number of days (' + cur.retentionDays + ').', { kind: 'warn', timeout: 8000 }); return; }
    if (!cur.retentionDays) { out.replaceChildren(report({ off: true }, '')); return; }
    const p = await GET('/api/admin/retention/preview');
    out.replaceChildren(report(p, 'would be deleted now'));
    if (!p.chats && !p.files) { toast('Nothing to delete', { kind: 'success' }); return; }
    const ok = await confirmDialog({
      title: 'Delete unused chats now?', danger: true, confirmText: 'Delete now',
      message: Math.min(p.chats, p.perSweep || p.chats) + ' chat(s) unused for ' + p.days + ' days and their attachments, and files not linked to any chat, are deleted for good - in Goose Web, Goose Desktop and the goose CLI alike. This cannot be undone.',
    });
    if (!ok) return;
    const r = await POST('/api/admin/retention/run', {});
    out.replaceChildren(report(r, 'deleted'));
    lastEl.textContent = lastText({ ...r, manual: true });
  }, { size: 'sm', icon: 'trash', variant: 'danger' });
  const el = section('Files and chats', null, h('div', { class: 'card stack' },
    h('div', { class: 'grid2' },
      field('Largest file upload (MB)', up, 'From 1 to ' + maxMb + ' (5 GB). Files go up in resumable pieces; the server also needs that much free disk space plus 1 GB.' +
        (s.maxUploadMbStored ? '' : ' Until this is saved, the configuration\'s server.max_upload_mb (' + s.maxUploadMbConfig + ' MB) applies.')),
      field('Delete chats and their attachments after (days without use)', days, '0 = never. From 1 to ' + daysMax + '; default ' + (s.retentionDaysDefault || 180) + '. A chat counts as used when anybody opens or uses it - in Goose Web, Goose Desktop or the goose CLI. The files uploaded to a chat go with it; files never linked to a chat count from their upload. Chats that are running or open are never deleted. Checked hourly, at most 200 chats per sweep.')),
    first,
    h('div', { class: 'row' }, preview, runNow),
    lastEl, out));
  // Only what was stored before or changed here: saving another setting must not freeze the configuration's values.
  const upValue = () => Math.max(1, Math.min(maxMb, Math.floor(Number(up.value) || Number(s.maxUploadMb) || 25)));
  return {
    el,
    values: () => {
      const v = {};
      if (s.maxUploadMbStored || upValue() !== Number(s.maxUploadMb)) v.maxUploadMb = upValue();
      if (s.retentionDaysStored || daysValue() !== Number(s.retentionDays)) v.retentionDays = daysValue();
      return v;
    },
  };
}
