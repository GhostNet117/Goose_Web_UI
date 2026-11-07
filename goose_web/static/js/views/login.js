// Login (local + TOTP step, OIDC, LDAP label) and forced change-password screens.
import { h, btn, input, field, toastError } from '../ui.js';
import { icon, logo } from '../icons.js';
import { POST, setCsrf, ApiError } from '../api.js';
import { router } from '../router.js';

export function renderLogin(root, { authConfig, onLoggedIn }) {
  const cfg = authConfig || {};
  const brand = cfg.brand || {};
  const r = router.current();
  const user = input({ autocomplete: 'username', name: 'username', placeholder: 'Username', autofocus: true, 'aria-label': 'Username' });
  const pass = input({ type: 'password', autocomplete: 'current-password', name: 'password', placeholder: 'Password', 'aria-label': 'Password' });
  const totp = input({ inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '123 456', maxlength: 8, 'aria-label': 'Authentication code', class: 'inp totp-inp' });
  const remember = h('input', { type: 'checkbox', checked: true });
  const err = h('div', { class: 'auth-err', role: 'alert' });
  const submit = btn('Sign in', null, { variant: 'primary', type: 'submit', class: 'auth-submit' });
  let step = 'password';
  const totpField = field('Authentication code', totp, 'Enter the 6-digit code from your authenticator app.');
  totpField.hidden = true;
  const credFields = h('div', { class: 'stack' }, field(cfg.ldap && cfg.ldap.enabled ? (cfg.ldap.label || 'Directory') + ' username' : 'Username', user), field('Password', pass));

  const form = h('form', { class: 'auth-form', autocomplete: 'on' }, credFields, totpField,
    h('label', { class: 'chk' }, remember, h('span', null, 'Keep me signed in')), err, submit);

  if (r.query && r.query.error) err.textContent = decodeURIComponent(r.query.error);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    if (!user.value || !pass.value) { err.textContent = 'Enter your username and password.'; return; }
    submit.disabled = true; submit.classList.add('is-busy');
    try {
      const body = { username: user.value.trim(), password: pass.value, remember: remember.checked };
      if (step === 'totp') body.totp = totp.value.replace(/\s+/g, '');
      const res = await POST('/api/auth/login', body, { quiet: true });
      setCsrf(res.csrf);
      onLoggedIn(res);
    } catch (ex) {
      const code = ex instanceof ApiError ? ex.code : null;
      if (code === 'totp_required') {
        if (step === 'totp') err.textContent = 'Invalid code, try again.';
        step = 'totp'; credFields.hidden = true; totpField.hidden = false; totp.value = ''; totp.focus();
        submit.querySelector('span').textContent = 'Verify';
      } else if (code === 'invalid_credentials') { err.textContent = 'Invalid username or password.'; pass.select(); }
      else if (code === 'locked' || ex.status === 423) err.textContent = 'This account is temporarily locked. Try again later or ask an administrator.';
      else if (code === 'rate_limited' || ex.status === 429) err.textContent = 'Too many attempts. Please wait a minute.';
      else if (code === 'ip_blocked') err.textContent = 'Sign-in from your network address is blocked after too many failed attempts. Ask an administrator to unblock it.';
      else err.textContent = ex.message || 'Sign-in failed.';
    } finally { submit.disabled = false; submit.classList.remove('is-busy'); }
  });

  const oidc = (cfg.oidc || []).map((o) => h('a', { class: 'btn btn-secondary auth-sso', href: '/api/auth/oidc/' + encodeURIComponent(o.id) + '/start' }, icon('key', 15), h('span', null, 'Continue with ' + (o.label || o.id))));
  const showLocal = cfg.local !== false || (cfg.ldap && cfg.ldap.enabled);

  root.replaceChildren(h('div', { class: 'auth-screen' },
    h('div', { class: 'auth-glow' }),
    h('div', { class: 'auth-card' },
      h('div', { class: 'auth-brand' }, logo(44), h('div', null, h('h1', null, brand.name || 'Goose Web'), h('p', { class: 'muted' }, brand.tagline || 'Your AI agent, from any browser'))),
      showLocal ? form : null,
      oidc.length ? h('div', { class: 'auth-sep' }, h('span', null, showLocal ? 'or' : 'Sign in with')) : null,
      oidc.length ? h('div', { class: 'stack' }, oidc) : null,
      h('div', { class: 'auth-foot muted small' }, cfg.version ? 'v' + cfg.version : '', cfg.ldap && cfg.ldap.enabled ? ' · ' + (cfg.ldap.label || 'LDAP') + ' accounts supported' : ''))));
  setTimeout(() => user.focus(), 50);
}

export function strengthProblems(pw, username = '') {
  const p = [];
  if (pw.length < 12) p.push('At least 12 characters');
  if (!/[a-z]/.test(pw)) p.push('A lowercase letter');
  if (!/[A-Z]/.test(pw)) p.push('An uppercase letter');
  if (!/[0-9]/.test(pw)) p.push('A number');
  if (!/[^A-Za-z0-9]/.test(pw)) p.push('A symbol');
  // same rules as the server (security.password_problems): user names of 3+ characters only
  if (username && username.length >= 3 && pw.toLowerCase().includes(username.toLowerCase())) p.push('Must not contain your username');
  return p;
}
export function strengthScore(pw) {
  let s = 0;
  if (pw.length >= 8) s++; if (pw.length >= 12) s++; if (pw.length >= 16) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(5, Math.floor(s * 5 / 6));
}

// Reusable password change form. onDone() after success.
export function passwordForm({ username = '', onDone, forced = false }) {
  const cur = input({ type: 'password', autocomplete: 'current-password', placeholder: forced ? 'Temporary password' : 'Current password' });
  const nw = input({ type: 'password', autocomplete: 'new-password', placeholder: 'New password' });
  const conf = input({ type: 'password', autocomplete: 'new-password', placeholder: 'Repeat new password' });
  const meter = h('div', { class: 'pw-meter' }, ...Array.from({ length: 5 }, () => h('span')));
  const hints = h('ul', { class: 'pw-hints' });
  const err = h('div', { class: 'auth-err', role: 'alert' });
  const submit = btn('Change password', null, { variant: 'primary', type: 'submit' });
  const ALL = ['At least 12 characters', 'A lowercase letter', 'An uppercase letter', 'A number', 'A symbol'];
  const update = () => {
    const pw = nw.value;
    const probs = strengthProblems(pw, username);
    const score = pw ? strengthScore(pw) : 0;
    meter.dataset.score = String(score);
    [...meter.children].forEach((s, i) => s.classList.toggle('on', i < score));
    const items = ALL.map((t) => h('li', { class: probs.includes(t) ? 'bad' : 'good' }, icon(probs.includes(t) ? 'x' : 'check', 12), t));
    if (probs.includes('Must not contain your username')) items.push(h('li', { class: 'bad' }, icon('x', 12), 'Must not contain your username'));
    if (conf.value) items.push(h('li', { class: conf.value === pw ? 'good' : 'bad' }, icon(conf.value === pw ? 'check' : 'x', 12), 'Passwords match'));
    hints.replaceChildren(...items);
  };
  nw.addEventListener('input', update); conf.addEventListener('input', update);
  update();
  const form = h('form', { class: 'auth-form' }, field(forced ? 'Current (temporary) password' : 'Current password', cur), field('New password', nw), meter, hints, field('Confirm new password', conf), err, submit);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    if (nw.value !== conf.value) { err.textContent = 'The new passwords do not match.'; return; }
    const probs = strengthProblems(nw.value, username);
    if (probs.length) { err.textContent = 'Password is too weak: ' + probs.join(', ').toLowerCase() + '.'; return; }
    submit.disabled = true;
    try {
      await POST('/api/me/password', { current: cur.value, new: nw.value }, { quiet: true });
      onDone && onDone();
    } catch (ex) {
      if (ex.code === 'weak_password' && ex.data && ex.data.problems) err.textContent = 'Rejected: ' + ex.data.problems.join(', ');
      else if (ex.code === 'invalid_credentials' || ex.status === 401) err.textContent = 'Current password is incorrect.';
      else err.textContent = ex.message;
    } finally { submit.disabled = false; }
  });
  return form;
}

export function renderChangePassword(root, { me, authConfig, onDone, onLogout }) {
  const brand = (authConfig && authConfig.brand) || {};
  const u = (me && me.user) || {};
  root.replaceChildren(h('div', { class: 'auth-screen' }, h('div', { class: 'auth-glow' }),
    h('div', { class: 'auth-card' },
      h('div', { class: 'auth-brand' }, logo(40), h('div', null, h('h1', null, 'Choose a new password'), h('p', { class: 'muted' }, (brand.name || 'Goose Web') + ' requires you to change your password before continuing.'))),
      passwordForm({ username: u.username || '', forced: true, onDone }),
      h('div', { class: 'auth-foot' }, h('button', { type: 'button', class: 'linkbtn', onclick: onLogout }, 'Sign out')))));
}

export { toastError };
