// Folder picker dialog: /api/fs/roots + /api/fs/list, recent folders, create folder.
import { h, btn, iconBtn, modal, input, toastError, promptDialog, baseName, spinner, relTime } from '../ui.js';
import { icon } from '../icons.js';
import { GET, POST, qs } from '../api.js';
import { pref, addRecentFolder } from '../prefs.js';
import { joinPath } from '../composer.js';

let rootsCache = null;
export async function fsRoots() {
  if (!rootsCache) rootsCache = await GET('/api/fs/roots');
  return rootsCache;
}

export function pickFolder({ title = 'Choose a working folder', initial = '', confirmText = 'Use this folder', files = false } = {}) {
  return new Promise((resolve) => {
    let current = null; let entries = []; let parent = null; let filter = '';
    const pathInp = input({ placeholder: 'Type or paste a path and press Enter', 'aria-label': 'Path' });
    const listEl = h('div', { class: 'fp-list', role: 'listbox' });
    const rootsEl = h('div', { class: 'fp-roots' });
    const filterInp = input({ placeholder: 'Filter…', class: 'inp inp-sm', oninput: () => { filter = filterInp.value.toLowerCase(); renderList(); } });
    let selectedFile = null;
    const crumbs = h('div', { class: 'fp-crumbs' });

    const go = async (p) => {
      listEl.replaceChildren(h('div', { class: 'fp-loading' }, spinner(16)));
      try {
        const r = await GET('/api/fs/list' + qs({ path: p }));
        current = r.path; parent = r.parent; entries = r.entries || [];
        pathInp.value = current; filter = ''; filterInp.value = '';
        renderCrumbs(); renderList();
      } catch (e) { listEl.replaceChildren(h('div', { class: 'fp-err' }, icon('alert', 14), ' ', e.message)); }
    };
    const renderCrumbs = () => {
      const sep = current && current.includes('\\') ? '\\' : '/';
      const parts = String(current || '').split(/[\\/]+/).filter(Boolean);
      const nodes = [];
      let acc = current && current.startsWith('/') ? '' : '';
      parts.forEach((p, i) => {
        acc = i === 0 ? (current.startsWith('/') ? '/' + p : p + (/^[A-Za-z]:$/.test(p) ? sep : '')) : joinPath(acc, p);
        const target = acc;
        nodes.push(h('button', { type: 'button', class: 'crumb', onclick: () => go(target) }, p));
        if (i < parts.length - 1) nodes.push(h('span', { class: 'crumb-sep' }, '›'));
      });
      crumbs.replaceChildren(...nodes);
    };
    const renderList = () => {
      const items = entries.filter((e) => (files || e.dir) && (!filter || e.name.toLowerCase().includes(filter)))
        .sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name));
      listEl.replaceChildren(
        parent ? h('button', { type: 'button', class: 'fp-item fp-up', onclick: () => go(parent) }, icon('chevronUp', 14), h('span', null, '..')) : null,
        ...items.map((e) => h('button', {
          type: 'button', class: ['fp-item', selectedFile === e.path ? 'active' : ''], title: e.path,
          onclick: () => { if (e.dir) go(e.path); else { selectedFile = e.path; renderList(); } },
          ondblclick: () => { if (!e.dir && files) finish(e.path); },
        }, icon(e.dir ? 'folder' : 'file', 14), h('span', { class: 'fp-name' }, e.name), e.mtime ? h('span', { class: 'fp-meta' }, relTime(e.mtime)) : null)),
        !items.length ? h('div', { class: 'fp-empty' }, files ? 'Empty folder' : 'No subfolders') : null);
    };
    pathInp.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); go(pathInp.value.trim()); } });

    let m;
    const finish = (p) => { if (!files) addRecentFolder(p); m.close(p); };
    const recent = (pref('recentFolders') || []).slice(0, 8);
    m = modal({
      title, size: 'lg', className: 'fp-modal',
      body: h('div', { class: 'fp' },
        h('aside', { class: 'fp-side' }, h('div', { class: 'fp-side-head' }, 'Locations'), rootsEl,
          recent.length ? h('div', { class: 'fp-side-head' }, 'Recent') : null,
          ...recent.map((r) => h('button', { type: 'button', class: 'fp-root', title: r, onclick: () => go(r) }, icon('schedule', 13), h('span', null, baseName(r))))),
        h('div', { class: 'fp-main' },
          h('div', { class: 'fp-bar' }, pathInp, iconBtn('folderPlus', 'New folder', async () => {
            if (!current) return;
            const name = await promptDialog({ title: 'New folder', label: 'Folder name', confirmText: 'Create', validate: (v) => (!v.trim() ? 'Required' : /[\\/:*?"<>|]/.test(v) ? 'Invalid characters' : null) });
            if (!name) return;
            const p = joinPath(current, name.trim());
            try { await POST('/api/fs/mkdir', { path: p }); await go(p); } catch (e) { toastError(e, 'Create folder'); }
          })),
          h('div', { class: 'fp-bar2' }, crumbs, filterInp),
          listEl)),
      footer: [h('div', { class: 'fp-sel muted' }), btn('Cancel', () => m.close(null)), btn(confirmText, () => {
        if (files) { if (selectedFile) finish(selectedFile); return; }
        if (current) finish(current);
      }, { variant: 'primary', icon: 'check' })],
      onClose: (r) => resolve(r || null),
    });
    (async () => {
      try {
        const r = await fsRoots();
        rootsEl.replaceChildren(...(r.roots || []).map((x) => h('button', { type: 'button', class: 'fp-root', title: x.path, onclick: () => go(x.path) }, icon('folder', 13), h('span', null, x.label || baseName(x.path)))));
        if (r.home && !(r.roots || []).some((x) => x.path === r.home)) rootsEl.prepend(h('button', { type: 'button', class: 'fp-root', onclick: () => go(r.home) }, icon('user', 13), h('span', null, 'Home')));
        go(initial || pref('lastCwd') || r.defaultCwd || r.home || (r.roots && r.roots[0] && r.roots[0].path) || '');
      } catch (e) { toastError(e, 'Folders'); listEl.replaceChildren(h('div', { class: 'fp-err' }, e.message)); }
    })();
  });
}
