// Goose Web service worker: caches the app shell only. Never caches /api/* or /ws.
const VERSION = 'gw-shell-v20';
const SHELL = [
  '/',
  '/manifest.webmanifest',
  '/static/css/app.css',
  '/static/icons/goose.svg',
  '/static/vendor/hljs-dark.css',
  '/static/vendor/hljs-light.css',
  '/static/vendor/marked.esm.js',
  '/static/vendor/purify.es.mjs',
  '/static/vendor/highlight.min.js',
  '/static/vendor/qrcode.esm.js',
  '/static/js/app.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL).catch(() => { /* offline install: best effort */ })).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/') || url.pathname === '/ws' || url.pathname.startsWith('/ws/')) return;
  const isShell = url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/manifest.webmanifest';
  const isStatic = url.pathname.startsWith('/static/');
  if (!isShell && !isStatic) return;
  if (isShell || url.pathname.startsWith('/static/js/') || url.pathname.startsWith('/static/css/')) {
    // network first so deployments show up immediately; cache as offline fallback
    // cache: 'no-cache' forces revalidation; otherwise heuristic HTTP caching can serve stale modules.
    // The shell is cached under its path only: '/?profile=bob' and other query variants are the same
    // index.html and must not leave one cache entry each (security assessment 2026-11-09 D-8).
    const key = isShell ? (url.pathname === '/index.html' ? '/' : url.pathname) : req;
    event.respondWith(fetch(req.mode === 'navigate' ? req : new Request(req, { cache: 'no-cache' })).then((res) => {
      if (res.ok && !res.redirected) { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(key, copy)); }
      return res;
    }).catch(() => caches.match(key).then((r) => r || (isShell ? caches.match('/') : Response.error()))));
    return;
  }
  // vendor + icons: cache first
  event.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((res) => {
    if (res.ok) { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(req, copy)); }
    return res;
  })));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const sid = event.notification.data && event.notification.data.sessionId;
  const target = '/#/' + (sid ? 'chat/' + encodeURIComponent(sid) : 'herd');
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) { if ('focus' in c) { c.navigate && c.navigate(target); return c.focus(); } }
    return self.clients.openWindow(target);
  }));
});
