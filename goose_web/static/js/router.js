// Hash router: #/view/arg1/arg2?query
import { Emitter } from './store.js';

class Router extends Emitter {
  constructor() {
    super();
    window.addEventListener('hashchange', () => this._fire());
  }
  parse(hash = location.hash) {
    let s = hash.replace(/^#\/?/, '');
    let query = {};
    const qi = s.indexOf('?');
    if (qi >= 0) { query = Object.fromEntries(new URLSearchParams(s.slice(qi + 1))); s = s.slice(0, qi); }
    const parts = s.split('/').filter(Boolean).map(decodeURIComponent);
    return { view: parts[0] || '', args: parts.slice(1), query, path: '/' + parts.join('/') };
  }
  current() { return this.parse(); }
  go(path, { replace = false } = {}) {
    const target = '#' + (path.startsWith('/') ? path : '/' + path);
    if (location.hash === target) { this._fire(); return; }
    if (replace) { history.replaceState(null, '', target); this._fire(); }
    else location.hash = target;
  }
  _fire() { this.emit('route', this.parse()); }
  start() { this._fire(); }
}
export const router = new Router();
export function link(path) { return '#' + (path.startsWith('/') ? path : '/' + path); }
export function enc(s) { return encodeURIComponent(s); }
