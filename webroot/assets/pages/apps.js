import { get, put, q, packageInfo } from '../api.js?v=__V__';
import { h, clear, card, btn, icon, searchField, loading, toast, errorText, empty } from '../ui.js?v=__V__';

const MODES = [
  ['all', '全部应用', '代理所选用户的应用（系统共享 UID、标准网络认证应用除外）'],
  ['include', '仅名单内', '只代理勾选的应用，其余直连'],
  ['exclude', '名单外', '代理除勾选应用以外的全部应用'],
];

export default function mount(view, ctx) {
  let alive = true;
  let data = null;
  let policy = null;
  let labels = {};
  let showSystem = false;
  const modeBox = h('div', { class: 'app-modes' }, loading());
  const usersBox = h('div', { class: 'row' });
  const listBox = h('div', null, loading());
  const countEl = h('span', { class: 'small muted' });
  const search = h('input', { type: 'search', placeholder: '搜索应用名或包名', oninput: () => renderList() });
  const sysToggle = h('input', { type: 'checkbox', onchange: () => { showSystem = sysToggle.checked; renderList(); } });
  const saveBtn = btn('保存', save, 'primary');

  view.append(
    card('代理范围', null, modeBox, h('div', { style: { marginTop: '10px' } }, h('div', { class: 'small muted' }, 'Android 用户'), usersBox)),
    card('应用名单', h('div', { class: 'row' }, countEl, saveBtn),
      h('div', { class: 'toolbar' }, searchField(search), h('label', { class: 'row small' }, sysToggle, '显示系统应用')),
      listBox),
  );

  async function save() {
    try {
      const r = await put(q('/api/v1/apps/policy', { rev: data.revision }), policy);
      if (r && r.warning) toast(r.warning, 'err');
      else toast('已保存并生效', 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
    await load();
  }

  function renderMode() {
    clear(modeBox);
    for (const [m, title, desc] of MODES) {
      const radio = h('input', { type: 'radio', name: 'app-mode', checked: policy.mode === m, onchange: () => { policy.mode = m; renderList(); } });
      modeBox.append(h('label', { class: 'app-mode' }, radio, h('div', null, h('div', null, title), h('div', { class: 'small muted' }, desc))));
    }
    clear(usersBox);
    for (const u of data.users) {
      const cb = h('input', { type: 'checkbox', checked: policy.users.includes(u), onchange: () => {
        policy.users = cb.checked ? [...new Set([...policy.users, u])].sort((a, b) => a - b) : policy.users.filter((x) => x !== u);
      } });
      usersBox.append(h('label', { class: 'row small' }, cb, u === 0 ? '机主 (0)' : `用户 ${u}`));
    }
  }

  function renderList() {
    if (!policy) return;
    clear(listBox);
    const selected = new Set(policy.packages);
    countEl.textContent = policy.mode === 'all' ? '' : `已选 ${selected.size} 个`;
    if (policy.mode === 'all') {
      listBox.append(empty('当前代理全部可接管应用，系统共享 UID 与标准网络认证应用直连'));
      return;
    }
    const kw = search.value.trim().toLowerCase();
    const installed = new Set(data.apps.map((a) => a.package));
    const missing = policy.packages.filter((p) => !installed.has(p));
    const apps = data.apps.filter((a) => {
      const info = labels[a.package] || {};
      const system = info.system ?? a.system ?? false;
      if (!showSystem && system && !selected.has(a.package)) return false;
      if (!kw) return true;
      return a.package.toLowerCase().includes(kw) || (info.label || '').toLowerCase().includes(kw);
    });
    apps.sort((a, b) => (selected.has(b.package) - selected.has(a.package)) || (labels[a.package]?.label || a.package).localeCompare(labels[b.package]?.label || b.package));
    const ul = h('ul', { class: 'list' });
    for (const p of missing) {
      ul.append(h('li', null, h('div', { class: 'grow' }, h('div', { class: 'title' }, p), h('div', { class: 'sub' }, '未安装')),
        btn('移除', () => { policy.packages = policy.packages.filter((x) => x !== p); renderList(); }, 'small')));
    }
    for (const a of apps.slice(0, 800)) {
      const cb = h('input', { type: 'checkbox', checked: !a.protectedReason && selected.has(a.package), disabled: !!a.protectedReason, onchange: () => {
        policy.packages = cb.checked ? [...policy.packages, a.package] : policy.packages.filter((x) => x !== a.package);
        countEl.textContent = `已选 ${policy.packages.length} 个`;
      } });
      const label = labels[a.package]?.label;
      ul.append(h('li', null, h('label', { class: 'row grow', style: { flexWrap: 'nowrap' } }, cb, icon('smartphone'),
        h('div', { class: 'grow' }, h('div', { class: 'title ellipsis' }, label || a.package), h('div', { class: 'sub ellipsis' }, `${a.package} · UID ${a.uid}${a.protectedReason ? ' · ' + a.protectedReason + '（直连）' : ''}`)))));
    }
    if (!apps.length && !missing.length) ul.append(h('li', { class: 'muted' }, '没有匹配的应用'));
    listBox.append(ul);
  }

  async function load() {
    const r = await get('/api/v1/apps');
    if (!alive) return;
    data = r;
    policy = structuredClone(r.policy);
    policy.packages = policy.packages || [];
    const protectedPackages = new Set(r.apps.filter((a) => a.protectedReason).map((a) => a.package));
    policy.packages = policy.packages.filter((p) => !protectedPackages.has(p));
    policy.users = policy.users || [0];
    if (!Object.keys(labels).length) labels = packageInfo(r.apps.map((a) => a.package));
    renderMode();
    renderList();
    ctx.refreshStatus().catch(() => {});
  }
  load().catch((e) => {
    clear(listBox).append(empty(errorText(e)));
  });
  return () => { alive = false; };
}
