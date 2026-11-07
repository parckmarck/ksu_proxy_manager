import { get, post, ApiError, hasBridge, startDaemon, setWebKey } from './api.js?v=__V__';
import { h, clear, card, toast, modal, errorText, btn, toolBtn, icon, poller, loading } from './ui.js?v=__V__';
import overview from './pages/overview.js?v=__V__';
import proxies from './pages/proxies.js?v=__V__';
import subscriptions from './pages/subscriptions.js?v=__V__';
import routing from './pages/routing.js?v=__V__';
import apps from './pages/apps.js?v=__V__';
import cores from './pages/cores.js?v=__V__';
import connections from './pages/connections.js?v=__V__';
import logs from './pages/logs.js?v=__V__';
import settings from './pages/settings.js?v=__V__';

export const PAGES = [
  ['overview', '概览', overview, 'layoutDashboard'],
  ['proxies', '节点', proxies, 'network'],
  ['subscriptions', '订阅', subscriptions, 'rss'],
  ['routing', '分流', routing, 'route'],
  ['apps', '应用', apps, 'smartphone'],
  ['cores', '核心', cores, 'cpu'],
  ['connections', '连接', connections, 'activity'],
  ['logs', '日志', logs, 'scrollText'],
  ['settings', '设置', settings, 'settings'],
];

const STATE_NAMES = {
  running: '运行中', starting: '启动中', restarting: '重启中', stopping: '停止中',
  stopped: '已停止', failed: '异常', disabled: '已禁用',
};

const state = { status: null, listeners: new Set(), unmount: null, page: 'overview' };
let statusRequest = null;
let pendingNotice, configNotice, connectionNotice, connectionMessage;

export const ctx = {
  get status() { return state.status; },
  onStatus(fn) {
    state.listeners.add(fn);
    return () => state.listeners.delete(fn);
  },
  refreshStatus,
  stateName: (s) => STATE_NAMES[s] || s || '未知',
};

function refreshStatus() {
  if (statusRequest) return statusRequest;
  statusRequest = (async () => {
    try {
      state.status = await get('/api/v1/status');
      renderHeader(null);
      for (const fn of state.listeners) {
        try { fn(state.status); } catch (e) { console.error(e); }
      }
      return state.status;
    } catch (e) {
      renderHeader(e);
      throw e;
    }
  })().finally(() => { statusRequest = null; });
  return statusRequest;
}

function renderHeader(err) {
  const chipEl = document.getElementById('hdr-state');
  if (err) {
    chipEl.className = 'chip status-chip err';
    chipEl.textContent = err.code === 'DAEMON_DOWN' ? '服务未运行' : '连接失败';
    pendingNotice.hidden = true;
    connectionNotice.hidden = !started;
    connectionMessage.textContent = errorText(err);
    document.getElementById('banner').hidden = connectionNotice.hidden && configNotice.hidden;
    return;
  }
  const s = state.status;
  const core = s.core || {};
  connectionNotice.hidden = true;
  chipEl.textContent = ctx.stateName(core.state);
  chipEl.className = 'chip status-chip ' + ({ running: 'ok', failed: 'err', stopped: '', disabled: '' }[core.state] ?? 'warn');
  configNotice.hidden = !s.daemon?.configError;
  configNotice.textContent = s.daemon?.configError
    ? '配置文件无法读取，当前使用默认配置（原文件未被覆盖，可在设置中恢复备份）：' + s.daemon.configError : '';
  pendingNotice.hidden = !core.pending;
  document.getElementById('banner').hidden = configNotice.hidden && pendingNotice.hidden;
  document.getElementById('page-meta').textContent = `修订 ${s.revision}`;
}

function navigate() {
  const id = (location.hash.replace(/^#\/?/, '') || 'overview').split(/[/?]/)[0];
  const page = PAGES.find((p) => p[0] === id) || PAGES[0];
  if (state.unmount) {
    try { state.unmount(); } catch (e) { console.error(e); }
    state.unmount = null;
  }
  state.page = page[0];
  for (const a of document.querySelectorAll('#nav a, #mobile-nav a')) {
    const active = a.dataset.id === page[0];
    a.classList.toggle('active', active);
    if (active) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  const more = document.getElementById('nav-more');
  const moreActive = PAGES.findIndex((p) => p[0] === page[0]) >= 4;
  more.classList.toggle('active', moreActive);
  more.setAttribute('aria-label', moreActive ? '更多，当前页面：' + page[1] : '更多');
  document.getElementById('page-title').textContent = page[1];
  document.title = `${page[1]} · KSU Proxy Manager`;
  const view = document.getElementById('view');
  clear(view);
  try {
    state.unmount = page[2](view, ctx) || null;
  } catch (e) {
    view.append(h('div', { class: 'banner err' }, errorText(e)));
  }
  window.scrollTo(0, 0);
}

async function askKey() {
  const input = h('input', { type: 'password', placeholder: '访问密钥', 'aria-label': '访问密钥', autocomplete: 'off' });
  const v = await modal('需要访问密钥', h('div', null,
    h('p', { class: 'small muted' }, '请输入设备上生成的浏览器访问密钥。'), input), [
    { label: '取消', value: false },
    { label: '确定', value: true, cls: 'primary' },
  ], { compact: true });
  if (v && input.value.trim()) {
    setWebKey(input.value.trim());
    return true;
  }
  return false;
}

function showDown(err) {
  const view = document.getElementById('view');
  clear(view);
  const retry = btn('重试', () => connect(), 'primary');
  view.append(card('无法连接管理服务', null,
    h('p', { class: 'muted' }, errorText(err)),
    h('p', { class: 'small muted' }, '可在终端执行 /data/adb/modules/ksu_proxy_manager/proxyctl doctor 查看原因；启动日志位于 /data/adb/ksu_proxy_manager/logs/daemon-start.log。'),
    h('div', { class: 'row' }, retry)));
}

let started = false;

async function connect() {
  let triedStart = false;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      await refreshStatus();
      break;
    } catch (e) {
      if (e instanceof ApiError && e.code === 'DAEMON_DOWN' && hasBridge() && !triedStart) {
        triedStart = true;
        const view = document.getElementById('view');
        clear(view).append(loading('正在启动管理服务…'));
        try {
          await startDaemon();
        } catch (se) {
          showDown(se);
          return;
        }
        continue;
      }
      if (e instanceof ApiError && e.status === 401 && !hasBridge()) {
        if (await askKey()) continue;
      }
      showDown(e);
      return;
    }
  }
  if (!state.status) return;
  if (!started) {
    started = true;
    window.addEventListener('hashchange', navigate);
    poller(() => refreshStatus(), 4000);
  }
  navigate();
}

function boot() {
  const nav = document.getElementById('nav');
  const mobileNav = document.getElementById('mobile-nav');
  const link = ([id, title, , symbol]) => h('a', { href: '#/' + id, dataset: { id } }, icon(symbol), h('span', null, title));
  for (const page of PAGES) nav.append(link(page));
  for (const page of PAGES.slice(0, 4)) mobileNav.append(link(page));
  const more = h('button', { id: 'nav-more', type: 'button', 'aria-label': '更多', 'aria-haspopup': 'dialog', 'aria-expanded': 'false', onclick: async () => {
    if (more.getAttribute('aria-expanded') === 'true') return;
    more.setAttribute('aria-expanded', 'true');
    let closeMenu;
    const menu = h('nav', { class: 'more-menu', 'aria-label': '更多页面' }, PAGES.slice(4).map((page) => {
      const a = link(page);
      if (page[0] === state.page) { a.classList.add('active'); a.setAttribute('aria-current', 'page'); }
      a.append(icon('chevronRight'));
      a.addEventListener('click', () => closeMenu?.(page[0]));
      return a;
    }));
    await modal('更多', menu, [], { compact: true, onOpen: ({ close }) => { closeMenu = close; } });
    more.setAttribute('aria-expanded', 'false');
  } }, icon('ellipsis'), h('span', null, '更多'));
  mobileNav.append(more);
  for (const mark of document.querySelectorAll('.brand-mark')) mark.append(icon('network'));
  document.getElementById('connection-kind').textContent = hasBridge() ? 'KernelSU WebUI' : '本机浏览器';

  const themes = [['auto', '跟随系统', 'monitor'], ['light', '浅色', 'sun'], ['dark', '深色', 'moon']];
  const themeButton = toolBtn('外观', 'monitor', async () => {
    const current = document.documentElement.dataset.themePreference || 'auto';
    const choices = h('div', { class: 'theme-options', role: 'group', 'aria-label': '外观' }, themes.map(([value, label, symbol]) =>
      h('label', { class: 'theme-option' }, icon(symbol), h('span', null, label),
        h('input', { type: 'radio', name: 'theme', value, checked: value === current, onchange: () => {
          document.dispatchEvent(new window.CustomEvent('kpm-theme-change', { detail: value }));
        } }))));
    await modal('外观', choices, [{ label: '完成', value: true, cls: 'primary' }], { compact: true });
  }, 'ghost');
  themeButton.setAttribute('aria-haspopup', 'dialog');
  const updateThemeIcon = () => {
    const selected = themes.find(([value]) => value === document.documentElement.dataset.themePreference) || themes[0];
    themeButton.querySelector('.icon').replaceWith(icon(selected[2]));
    themeButton.title = `外观：${selected[1]}`;
  };
  updateThemeIcon();
  document.addEventListener('kpm-theme-applied', updateThemeIcon);
  document.getElementById('header-tools').append(toolBtn('刷新状态', 'refreshCw', refreshStatus, 'ghost refresh-tool'), themeButton);
  configNotice = h('div', { class: 'banner err', role: 'alert', hidden: true });
  connectionMessage = h('span', { class: 'grow' });
  connectionNotice = h('div', { class: 'banner err', role: 'alert', hidden: true }, icon('unplug'), connectionMessage,
    btn('重新连接', connect, 'small'));
  pendingNotice = h('div', { class: 'banner info', hidden: true },
    icon('circleCheck'), h('span', { class: 'grow' }, '配置已修改，重启核心后生效'),
    btn('立即应用', async () => {
      await post('/api/v1/core/restart');
      toast('已应用新配置', 'ok');
      await refreshStatus();
    }, 'primary small'));
  document.getElementById('banner').append(connectionNotice, configNotice, pendingNotice);
  // Hash navigation remains the single source of truth on both layouts.
  for (const a of document.querySelectorAll('#nav a, #mobile-nav a')) {
    a.addEventListener('click', () => { if (started && location.hash === a.hash) navigate(); });
  }
  connect();
}

if (typeof document !== 'undefined' && document.getElementById('nav')) boot();
