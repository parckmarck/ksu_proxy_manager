import { get, put, q, packageInfo } from '../api.js?v=__V__';
import { h, clear, card, btn, icon, searchField, loading, toast, errorText, empty } from '../ui.js?v=__V__';

const MODES = [
  ['all', '全部应用', '代理所选用户的应用（系统共享 UID、标准网络认证应用除外）'],
  ['include', '仅名单内', '只代理勾选的应用，其余直连'],
  ['exclude', '名单外', '代理除勾选应用以外的全部应用'],
];
const FOLLOW = '跟随分流规则';

function targetLabel(groups, ref) {
  if (ref === 'DIRECT') return '直连';
  if (ref === 'REJECT') return '拒绝';
  const g = groups.find((x) => 'group:' + x.id === ref);
  return g ? '代理组：' + g.name : ref;
}

const routesKey = (routes) => JSON.stringify(routes.map((r) => [r.package, r.target]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)));

export default function mount(view, ctx) {
  let alive = true;
  let data = null;
  let policy = null;
  let groups = [];
  let savedRoutes = '[]';
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
    card('应用名单与出口', h('div', { class: 'row' }, countEl, saveBtn),
      h('div', { class: 'toolbar' }, searchField(search), h('label', { class: 'row small' }, sysToggle, '显示系统应用')),
      listBox),
  );

  async function save() {
    try {
      // "routes" is only sent when used, so the request keeps its previous shape otherwise.
      const body = { mode: policy.mode, packages: policy.packages, users: policy.users };
      if (policy.routes.length) body.routes = policy.routes;
      const routesChanged = routesKey(policy.routes) !== savedRoutes;
      const r = await put(q('/api/v1/apps/policy', { rev: data.revision }), body);
      if (r && r.warning) toast(r.warning, 'err');
      else if (r && r.pending && routesChanged) toast('已保存；应用出口的变更在重启核心后生效', 'ok');
      else toast('已保存并生效', 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
    await load();
  }

  function updateCount() {
    const parts = [];
    if (policy.mode !== 'all') parts.push(`已选 ${policy.packages.length} 个`);
    if (policy.routes.length) parts.push(`指定出口 ${policy.routes.length} 个`);
    countEl.textContent = parts.join(' · ');
  }

  function setRoute(pkg, target) {
    policy.routes = policy.routes.filter((r) => r.package !== pkg);
    if (target) policy.routes.push({ package: pkg, target });
    updateCount();
  }

  function routeTemplate() {
    const sel = h('select', { class: 'app-route' }, h('option', { value: '' }, FOLLOW));
    for (const g of groups) sel.append(h('option', { value: 'group:' + g.id }, '代理组：' + g.name));
    sel.append(h('option', { value: 'DIRECT' }, '直连'), h('option', { value: 'REJECT' }, '拒绝'));
    return sel;
  }

  function routeSelect(template, pkg, name, current, disabled) {
    const sel = template.cloneNode(true);
    if (current && ![...sel.options].some((o) => o.value === current)) sel.append(h('option', { value: current }, targetLabel(groups, current)));
    sel.value = current || '';
    sel.disabled = disabled;
    sel.setAttribute('aria-label', `${name} 的出口`);
    sel.classList.toggle('set', !!sel.value);
    sel.addEventListener('change', () => {
      setRoute(pkg, sel.value);
      sel.classList.toggle('set', !!sel.value);
    });
    return sel;
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
    const all = policy.mode === 'all';
    const selected = new Set(all ? [] : policy.packages);
    const routes = new Map(policy.routes.map((r) => [r.package, r.target]));
    updateCount();
    listBox.append(h('div', { class: 'small muted app-hint' },
      all ? '当前代理全部可接管应用，系统共享 UID 与标准网络认证应用直连。' : '勾选决定应用是否计入名单。',
      '右侧可为单个应用指定出口：规则模式下优先于分流页的全部规则，只对被代理的应用生效，修改后需重启核心。'));
    const kw = search.value.trim().toLowerCase();
    const installed = new Set(data.apps.map((a) => a.package));
    const missing = [...new Set([...selected, ...routes.keys()])].filter((p) => !installed.has(p));
    const apps = data.apps.filter((a) => {
      const info = labels[a.package] || {};
      const system = info.system ?? a.system ?? false;
      if (!showSystem && system && !selected.has(a.package) && !routes.has(a.package)) return false;
      if (!kw) return true;
      return a.package.toLowerCase().includes(kw) || (info.label || '').toLowerCase().includes(kw);
    });
    apps.sort((a, b) => (selected.has(b.package) - selected.has(a.package)) || (routes.has(b.package) - routes.has(a.package))
      || (labels[a.package]?.label || a.package).localeCompare(labels[b.package]?.label || b.package));
    const template = routeTemplate();
    const ul = h('ul', { class: 'list' });
    for (const p of missing) {
      const target = routes.get(p);
      ul.append(h('li', null, h('div', { class: 'grow' }, h('div', { class: 'title' }, p), h('div', { class: 'sub' }, target ? `未安装 · 出口：${targetLabel(groups, target)}` : '未安装')),
        btn('移除', () => {
          if (policy.mode !== 'all') policy.packages = policy.packages.filter((x) => x !== p);
          policy.routes = policy.routes.filter((r) => r.package !== p);
          renderList();
        }, 'small')));
    }
    for (const a of apps.slice(0, 800)) {
      const cb = all ? null : h('input', { type: 'checkbox', checked: !a.protectedReason && selected.has(a.package), disabled: !!a.protectedReason, onchange: () => {
        policy.packages = cb.checked ? [...policy.packages, a.package] : policy.packages.filter((x) => x !== a.package);
        updateCount();
      } });
      const label = labels[a.package]?.label;
      ul.append(h('li', null, h(all ? 'div' : 'label', { class: 'row grow', style: { flexWrap: 'nowrap' } }, cb, icon('smartphone'),
        h('div', { class: 'grow' }, h('div', { class: 'title ellipsis' }, label || a.package), h('div', { class: 'sub ellipsis' }, `${a.package} · UID ${a.uid}${a.protectedReason ? ' · ' + a.protectedReason + '（直连）' : ''}`))),
        routeSelect(template, a.package, label || a.package, a.protectedReason ? '' : routes.get(a.package), !!a.protectedReason)));
    }
    if (!apps.length && !missing.length) ul.append(h('li', { class: 'muted' }, '没有匹配的应用'));
    listBox.append(ul);
  }

  async function load() {
    // The app list stays usable when the groups cannot be read; only DIRECT / REJECT are offered then.
    const [r, g] = await Promise.all([get('/api/v1/apps'), get('/api/v1/groups').catch(() => null)]);
    if (!alive) return;
    data = r;
    groups = (g && g.groups) || [];
    policy = structuredClone(r.policy);
    policy.packages = policy.packages || [];
    policy.routes = policy.routes || [];
    savedRoutes = routesKey(policy.routes);
    const protectedPackages = new Set(r.apps.filter((a) => a.protectedReason).map((a) => a.package));
    policy.packages = policy.packages.filter((p) => !protectedPackages.has(p));
    policy.routes = policy.routes.filter((x) => !protectedPackages.has(x.package));
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
