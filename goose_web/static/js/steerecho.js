// Which bubble does Goose's echo of a steer belong to? (bug menu-steer-extension-2026-11-19)
//
// A steer is shown at once; its message id is known only from the answer to the steer call. Goose answers the
// call and reads the steer in two tasks, so when the agent is at a step boundary the echo (user_message_chunk
// with the id) can reach the tab BEFORE the answer. An echo with an unknown id used to make a second bubble.
// Rule: such an echo adopts this tab's own steer bubble that has no id yet and the same content - the oldest
// one, because Goose reads steers in the order they were sent. No DOM, no storage: run in node by
// tests/test_frontend_modules.py.

const norm = (s) => String(s ?? '').replace(/\r\n/g, '\n').trim();

// True when two content blocks are the same thing (text, a linked file, an image).
export function sameBlock(a, b) {
  if (!a || !b || a.type !== b.type) return false;
  if (a.type === 'text') return norm(a.text) === norm(b.text);
  if (a.type === 'resource_link') return !!a.uri && a.uri === b.uri;
  if (a.type === 'image') return !!a.data && a.data === b.data && (a.mimeType || '') === (b.mimeType || '');
  if (a.type === 'resource') return !!(a.resource && b.resource) && a.resource.uri === b.resource.uri && norm(a.resource.text) === norm(b.resource.text);
  return false;
}

// A steer bubble of this tab that still waits for its id: made by ChatSession.steer(), not yet answered.
export function awaitsId(item) {
  return !!item && item.kind === 'user' && !!item.steer && !item.messageId && item.local !== false
    && (item.steerState === 'sending' || item.steerState === 'pending');
}

// The bubble an echo (its first block(s)) belongs to, or null. `items`: the transcript's items, oldest first.
export function ownSteerFor(items, blocks) {
  const first = (blocks || [])[0];
  if (!first) return null;
  for (const it of items || []) {
    if (awaitsId(it) && sameBlock((it.blocks || [])[0], first)) return it;
  }
  return null;
}
