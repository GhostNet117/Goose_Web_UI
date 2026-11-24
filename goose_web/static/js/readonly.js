// Read-only copy of a chat (FIX chat-open-readonly-fallback). When Goose cannot load a chat, the chat view's error card
// offers "Show a read-only copy": the conversation is read straight from the profile's Goose session database
// (GET /api/sessions/{id}/transcript, paged by message id) and shown here, read-only - a banner with Goose's reason,
// the messages oldest first, "Load more" for the next page, and "Try again" for the normal open.
// Safety: Goose's text and thinking go through the markdown pipeline (marked, then DOMPurify: markdown.js); everything
// else is set as text (h() makes text nodes). Nothing the server sends is ever put into innerHTML as it is.
import { h, btn, spinner, errMsg, fmtNum, shortPath, banner } from './ui.js';
import { icon, logo } from './icons.js';
import { GET, qs } from './api.js';
import { mdElement } from './markdown.js';
import { rpc } from './rpc.js';

export const PAGE_SIZE = 200;
const OPEN = new WeakMap();   // error card element -> the read-only copy shown in it

export function transcriptPath(sessionId, { after = 0, limit = PAGE_SIZE, profile = null } = {}) {
  return '/api/sessions/' + encodeURIComponent(sessionId) + '/transcript' + qs({ profile: profile || undefined, after: after || undefined, limit });
}

const timeOf = (sec) => (Number.isInteger(sec) ? new Date(sec * 1000) : null);
const firstLine = (s) => String(s || '').split('\n', 1)[0].slice(0, 160);

function cutNote(b) { return b.truncated ? h('div', { class: 'ro-cut muted small' }, '(shortened in the read-only copy)') : null; }

function toolBlock(b) {
  const result = b.type === 'toolResponse';
  const title = result ? 'Result' + (b.tool ? ': ' + b.tool : '') : (b.tool || 'Tool call');
  const body = b.text ? h('pre', { class: 'ro-pre' }, b.text) : h('div', { class: 'muted small' }, result ? '(no text)' : '(no arguments)');
  return h('details', { class: ['tool', 'ro-tool', b.error ? 'is-error' : ''] },
    h('summary', { class: 'tool-head' }, icon(result ? 'list' : 'tool', 14), h('span', { class: 'tool-title' }, title),
      b.error ? h('span', { class: 'badge badge-err' }, 'error') : null, h('span', { class: 'tool-tail' }, firstLine(b.text))),
    h('div', { class: 'tool-body' }, body, cutNote(b)));
}

function agentBlock(b) {
  if (b.type === 'text') return h('div', { class: 'agent-msg' }, mdElement(b.text), cutNote(b));
  if (b.type === 'thinking') {
    return h('details', { class: 'thought' },
      h('summary', null, icon('brain', 14), h('span', null, b.redacted ? 'Thinking (hidden by the model)' : 'Thinking'),
        b.text ? h('span', { class: 'thought-len muted' }, fmtNum(b.text.length) + ' chars') : null),
      b.text ? mdElement(b.text, 'thought-text md') : null, cutNote(b));
  }
  if (b.type === 'toolRequest' || b.type === 'toolResponse') return toolBlock(b);
  if (b.type === 'image') return h('div', { class: 'u-file' }, icon('image', 14), h('span', null, 'Image' + (b.mimeType ? ' (' + b.mimeType + ')' : '') + ' - not shown in the read-only copy'));
  return h('div', { class: 'tr-sys' }, icon('info', 14), h('span', null, b.text || '[' + (b.kind || 'notice') + ']'));
}

// One stored message: a user's words in a bubble; Goose's text, thinking and tools - and the tool results Goose
// stores as user messages - on the agent side, like the live transcript.
function renderMessage(m, state) {
  const out = [];
  const t = timeOf(m.created);
  const blocks = Array.isArray(m.blocks) ? m.blocks : [];
  if (m.role === 'user') {
    const words = blocks.filter((b) => b.type === 'text' || b.type === 'image');
    if (words.length) {
      out.push(h('div', { class: 'tr-item tr-user' },
        h('div', { class: 'tr-user-meta' }, t ? h('span', { class: 'tr-time', title: t.toLocaleString() }, t.toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })) : null),
        h('div', { class: 'bubble' }, words.map((b) => (b.type === 'text' ? h('div', { class: 'u-text' }, b.text) : agentBlock(b))), m.truncated ? h('div', { class: 'ro-cut muted small' }, '(shortened in the read-only copy)') : null)));
      state.agentShown = false;
    }
  }
  const side = m.role === 'user' ? blocks.filter((b) => b.type !== 'text' && b.type !== 'image') : blocks;
  if (side.length) {
    const el = h('div', { class: ['tr-item', 'tr-agent-side', state.agentShown ? '' : 'tr-first'] });
    if (!state.agentShown && m.role !== 'user') {
      el.appendChild(h('div', { class: 'tr-who' }, logo(20), h('span', { class: 'tr-name' }, 'Goose'), t ? h('span', { class: 'tr-time', title: t.toLocaleString() }, t.toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })) : null));
      state.agentShown = true;
    }
    for (const b of side) el.appendChild(agentBlock(b));
    if (m.truncated && m.role !== 'user') el.appendChild(h('div', { class: 'ro-cut muted small' }, '(shortened in the read-only copy)'));
    out.push(el);
  }
  return out;
}

// Render the read-only copy of `sessionId` into `container` (its content is replaced). `reason`: why Goose could not
// load the chat (shown in the banner); `onRetry`: "Try again" (the normal open); `profile`: an administrator's view of
// another profile (the server allows it to administrators only and audits it). Returns { root, setReason, close, more }.
export function renderReadOnly(container, sessionId, { reason = '', onRetry = null, profile = rpc.profileParam } = {}) {
  const reasonEl = h('span', null, reason || 'unknown error');
  const head = h('div', { class: 'ro-head' });
  const list = h('div', { class: 'ro-list tr-list' });
  const status = h('div', { class: 'ro-status muted small', role: 'status' });
  const moreBtn = btn('Load more', () => more(), { icon: 'chevronDown', variant: 'secondary' });
  moreBtn.hidden = true;
  const notice = banner('warn', h('span', null, h('b', null, 'Read-only copy'), ' - Goose could not load this chat: ', reasonEl));
  if (onRetry) notice.appendChild(btn('Try again', () => { view.close(); onRetry(); }, { icon: 'refresh', variant: 'secondary', size: 'sm' }));
  const root = h('div', { class: 'readonly', role: 'region', 'aria-label': 'Read-only copy of this chat' }, notice, head, list, h('div', { class: 'ro-foot' }, status, moreBtn));
  const state = { agentShown: false };
  let next = 0, shown = 0, busy = false, closed = false;

  const renderHead = (s) => {
    if (!s) return;
    const ts = Number(s.updated || s.created) || 0;
    const when = ts > 0 ? new Date(ts * 1000) : null;
    head.replaceChildren(h('div', { class: 'ro-title' }, s.name || 'Untitled'),
      h('div', { class: 'ro-meta muted small' }, s.workingDir ? h('span', { title: s.workingDir }, icon('folder', 13), ' ', shortPath(s.workingDir, 60)) : null,
        when ? h('span', null, ' - last changed ' + when.toLocaleString()) : null));
  };

  async function more() {
    if (busy || closed) return;
    busy = true; moreBtn.disabled = true;
    status.replaceChildren(spinner(14), h('span', null, ' Reading the conversation.'));
    try {
      const page = await GET(transcriptPath(sessionId, { after: next, profile }));
      if (closed) return;
      if (!shown) renderHead(page.session);
      const msgs = Array.isArray(page.messages) ? page.messages : [];
      for (const m of msgs) list.append(...renderMessage(m, state));
      shown += msgs.length;
      if (Number.isInteger(page.next)) next = page.next;
      moreBtn.hidden = !page.more;
      status.replaceChildren(h('span', null, shown ? fmtNum(shown) + ' of ' + fmtNum(page.total ?? shown) + ' messages shown.' : 'This chat has no messages to show.'));
    } catch (e) {
      if (closed) return;
      status.replaceChildren(h('span', { class: 'ro-error' }, 'Could not read the conversation: ' + errMsg(e)));
      moreBtn.hidden = false;
    } finally { busy = false; moreBtn.disabled = false; }
  }

  const view = {
    root, sessionId,
    setReason(r) { reasonEl.textContent = r || 'unknown error'; },
    close() { closed = true; if (OPEN.get(container) === view) OPEN.delete(container); },
    more,
  };
  container.replaceChildren(root);
  more();
  return view;
}

// The chat view's error card ("Could not open this session") calls this each time it draws the card: it adds "Show a
// read-only copy" to the card's buttons - or, when the copy is open for this chat, puts it back in place of the card
// (the view redraws the card on every state change; the copy keeps the pages it loaded). "Try again" closes the copy.
export function offerReadOnly(card, sessionId, error, onRetry) {
  const reason = errMsg(error);
  const open = OPEN.get(card);
  if (open && open.sessionId === sessionId) { open.setReason(reason); card.replaceChildren(open.root); return open; }
  const show = () => OPEN.set(card, renderReadOnly(card, sessionId, { reason, onRetry }));
  const b = btn('Show a read-only copy', show, { icon: 'eye', variant: 'secondary', title: 'Read this chat from Goose\'s session database, without opening it in Goose' });
  const actions = card.querySelector('.empty-actions');
  if (actions) actions.appendChild(b); else card.appendChild(h('div', { class: 'empty-actions' }, b));
  return null;
}
