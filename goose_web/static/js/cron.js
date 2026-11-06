// Cron helpers: presets (Goose uses 6-field cron with seconds) and a small human-readable describer.
import { h, input, select, field } from './ui.js';

export const PRESETS = [
  { label: 'Every 15 minutes', cron: '0 */15 * * * *' },
  { label: 'Every hour', cron: '0 0 * * * *' },
  { label: 'Every day at 09:00', cron: '0 0 9 * * *' },
  { label: 'Every day at 14:00', cron: '0 0 14 * * *' },
  { label: 'Weekdays at 08:30', cron: '0 30 8 * * 1-5' },
  { label: 'Every Monday at 09:00', cron: '0 0 9 * * 1' },
  { label: 'First of the month at 06:00', cron: '0 0 6 1 * *' },
];

const DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const MON = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

export function validateCron(c) {
  const f = String(c || '').trim().split(/\s+/);
  if (f.length < 5 || f.length > 7) return 'Cron needs 5 or 6 fields (sec min hour day month weekday)';
  const re = /^(\*|\?|L|W|#|\d+|[A-Za-z]{3})([-/,#]?(\*|\d+|[A-Za-z]{3}|L|W)?)*$/;
  for (const x of f) if (!re.test(x)) return 'Invalid field: ' + x;
  return null;
}

function pad(n) { return String(n).padStart(2, '0'); }
function listDesc(v, names) {
  if (v === '*' || v === '?') return null;
  return v.split(',').map((p) => {
    const r = /^(\d+)-(\d+)$/.exec(p);
    if (r) return (names ? names[+r[1]] : r[1]) + '–' + (names ? names[+r[2]] : r[2]);
    return names && /^\d+$/.test(p) ? names[+p] : p;
  }).join(', ');
}

export function describeCron(c) {
  const err = validateCron(c);
  if (err) return err;
  let f = String(c).trim().split(/\s+/);
  if (f.length === 5) f = ['0', ...f];
  const [sec, min, hour, dom, mon, dow] = f;
  let time;
  const step = (v) => /^\*\/(\d+)$/.exec(v);
  if (step(sec)) time = 'every ' + step(sec)[1] + ' seconds';
  else if (min === '*' && hour === '*') time = 'every minute';
  else if (step(min) && hour === '*') time = 'every ' + step(min)[1] + ' minutes';
  else if (/^\d+$/.test(min) && hour === '*') time = 'every hour at :' + pad(min);
  else if (/^\d+$/.test(min) && step(hour)) time = 'every ' + step(hour)[1] + ' hours at :' + pad(min);
  else if (/^\d+$/.test(min) && /^[\d,]+$/.test(hour)) time = 'at ' + hour.split(',').map((x) => pad(x) + ':' + pad(min)).join(', ');
  else time = 'at minute ' + min + ', hour ' + hour;
  const parts = [time];
  const dowD = listDesc(dow, DOW);
  const domD = dom === '*' || dom === '?' ? null : dom;
  const monD = listDesc(mon, MON);
  if (dowD) parts.push(dow === '1-5' ? 'on weekdays' : 'on ' + dowD);
  if (domD) parts.push('on day ' + domD + ' of the month');
  if (monD) parts.push('in ' + monD);
  if (!dowD && !domD) parts.push('every day');
  const s = parts.join(' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Cron editor widget: preset select + text input + live description. Returns {el, get()}
export function cronEditor(initial = '0 0 9 * * *') {
  const inp = input({ value: initial || '', class: 'inp mono', 'aria-label': 'Cron expression', placeholder: 'sec min hour day month weekday' });
  const desc = h('div', { class: 'cron-desc' });
  const preset = select([{ value: '', label: 'Presets…' }, ...PRESETS.map((p) => ({ value: p.cron, label: p.label }))], '');
  const upd = () => { const e = validateCron(inp.value); desc.textContent = describeCron(inp.value); desc.classList.toggle('err', !!e); };
  preset.addEventListener('change', () => { if (preset.value) { inp.value = preset.value; upd(); } preset.value = ''; });
  inp.addEventListener('input', upd);
  upd();
  const el = h('div', { class: 'cron-ed' }, field('Schedule (cron)', h('div', { class: 'row' }, inp, preset), 'Format: second minute hour day-of-month month day-of-week. Times are server-local.'), desc);
  return { el, get: () => inp.value.trim(), valid: () => !validateCron(inp.value) };
}
