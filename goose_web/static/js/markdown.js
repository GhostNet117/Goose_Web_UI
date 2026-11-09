// Markdown -> sanitized DOM. Every untrusted string goes through DOMPurify before touching innerHTML.
import { Marked } from '../vendor/marked.esm.js';
import DOMPurify from '../vendor/purify.es.mjs';
import hljs from '../vendor/highlight.min.js';
import { iconSvg } from './icons.js';
import { copyText } from './ui.js';

const marked = new Marked({ gfm: true, breaks: false, async: false });

// Only <code class="language-xyz"> keeps a class (the fence language, read by decorate()). Every other class
// is dropped so model/tool output cannot reuse the app's own CSS (.overlay, .modal, .palette, .menu ...) to
// draw fake dialogs over the app or clobber the app's DOM queries (security assessment 2026-11-09 D-1, D-7).
// The classes the highlighter adds (hljs, hljs-*) are added after sanitizing, from escaped text.
const LANG_CLASS = /^language-[\w+#.-]{1,40}$/;
DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
  if (data.attrName !== 'class') return;
  const keep = node.nodeName === 'CODE' ? String(data.attrValue || '').split(/\s+/).find((c) => LANG_CLASS.test(c)) : null;
  if (keep) data.attrValue = keep;
  else data.keepAttr = false;
});

// Images may only load from this origin (root-relative paths), data:image/ or blob:. Protocol-relative
// //host/x, /\host/x and the like resolve to another origin, so they are treated as remote (D-6).
export function isLocalImageSrc(src) {
  const s = String(src || '');
  if (/^(data:image\/|blob:)/i.test(s)) return true;
  if (!/^\/(?![\/\\])/.test(s)) return false;
  try { return new URL(s, location.href).origin === location.origin; } catch { return false; }
}

DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    const href = node.getAttribute('href') || '';
    if (/^\s*javascript:/i.test(href)) node.removeAttribute('href');
    if (!href.startsWith('#')) { node.setAttribute('target', '_blank'); node.setAttribute('rel', 'noopener noreferrer nofollow'); }
  }
  if (node.tagName === 'IMG') {
    const src = node.getAttribute('src') || '';
    // CSP only allows self/data/blob images anyway; drop remote ones (no tracking pixels, no console noise)
    if (!isLocalImageSrc(src)) { node.setAttribute('data-src', src); node.removeAttribute('src'); node.setAttribute('alt', '[image: ' + src.slice(0, 80) + ']'); }
    node.removeAttribute('srcset');
    node.setAttribute('loading', 'lazy');
  }
});

// No inline style, no id/name (DOM clobbering of the app's ids), no hidden text (D-1, D-2, D-7).
const PURIFY_OPTS = {
  USE_PROFILES: { html: true },
  FORBID_TAGS: ['style', 'form', 'input', 'button', 'textarea', 'select', 'iframe', 'object', 'embed', 'link', 'meta', 'base', 'dialog'],
  FORBID_ATTR: ['style', 'id', 'name', 'hidden', 'srcset', 'popover', 'inert'],
};

export function sanitize(html) { return DOMPurify.sanitize(html, PURIFY_OPTS); }

export function renderMarkdown(text) {
  try { return sanitize(marked.parse(String(text || ''))); }
  catch (e) { console.warn('markdown failed', e); const d = document.createElement('div'); d.textContent = text; return d.innerHTML; }
}

// Render markdown into el; if final, highlight + add code toolbars.
export function setMarkdown(el, text, { final = true } = {}) {
  el.innerHTML = renderMarkdown(text); // sanitized
  decorate(el, final);
}

export function decorate(el, final = true) {
  el.querySelectorAll('pre > code').forEach((code) => {
    const pre = code.parentElement;
    if (pre.dataset.dec) return;
    const m = /language-([\w+#.-]+)/.exec(code.className || '');
    const lang = m ? m[1] : '';
    // Always flatten the block to plain text first, whatever its size and whether or not this render is
    // final: markup inside <pre><code> (hidden spans, ...) could otherwise show one command and copy
    // another (pastejacking, D-2). Highlighting below re-renders from this text only.
    code.textContent = code.textContent;
    if (final) {
      pre.dataset.dec = '1';
      try {
        if (lang && hljs.getLanguage(lang)) hljs.highlightElement(code);
        else if (code.textContent.length < 20000) { const r = hljs.highlightAuto(code.textContent); code.innerHTML = r.value; code.classList.add('hljs'); } // hljs output is escaped
      } catch { /* ignore */ }
    }
    const wrap = document.createElement('div');
    wrap.className = 'codeblock';
    const head = document.createElement('div');
    head.className = 'codeblock-head';
    const l = document.createElement('span'); l.className = 'codeblock-lang'; l.textContent = lang || 'text';
    const b = document.createElement('button'); b.type = 'button'; b.className = 'btn btn-ghost btn-sm btn-icon'; b.title = 'Copy code'; b.setAttribute('aria-label', 'Copy code');
    b.innerHTML = iconSvg('copy', 14); // trusted constant
    // copy exactly what is shown: the flattened text (highlighting only wraps it in escaped spans)
    b.addEventListener('click', () => copyText(code.innerText || code.textContent, 'Code copied'));
    head.append(l, b);
    pre.replaceWith(wrap);
    wrap.append(head, pre);
  });
}

export function highlightCode(el, code, lang) {
  el.textContent = code;
  try {
    if (lang && hljs.getLanguage(lang)) { el.innerHTML = hljs.highlight(code, { language: lang }).value; el.classList.add('hljs'); }
  } catch { el.textContent = code; }
}

export function mdElement(text, cls = 'md') {
  const d = document.createElement('div');
  d.className = cls;
  setMarkdown(d, text);
  return d;
}
