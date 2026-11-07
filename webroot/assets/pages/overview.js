import { get, post, put } from '../api.js?v=__V__';
import { h, clear, card, btn, icon, chip, setDisabled, segmented, toast, errorText, fmtRate, fmtBytes, fmtDuration, poller } from '../ui.js?v=__V__';

const MODES = [['rule', '规则'], ['global', '全局'], ['direct', '直连']];

export function drawChart(canvas, history = []) {
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.clientWidth || 600;
  const height = canvas.clientHeight || 172;
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  const g = canvas.getContext?.('2d');
  if (!g) return;
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, width, height);
  const style = getComputedStyle(document.documentElement);
  const color = (key, fallback) => style.getPropertyValue(key).trim() || fallback;
  const points = history.length > 1 ? history : [history[0] || { up: 0, down: 0 }, history[0] || { up: 0, down: 0 }];
  const max = Math.max(1024, ...points.map((p) => Math.max(p.up || 0, p.down || 0))) * 1.15;
  const right = Math.max(80, width - 68);
  const top = 12, bottom = height - 8;
  g.font = '10px system-ui, sans-serif';
  g.textAlign = 'right';
  g.lineWidth = 1;
  for (let i = 0; i < 4; i++) {
    const y = top + ((bottom - top) * i) / 3;
    g.beginPath();
    g.moveTo(0, y);
    g.lineTo(right, y);
    g.strokeStyle = color('--line', '#e3e8e8');
    g.stroke();
    g.fillStyle = color('--muted', '#697375');
    g.fillText(fmtRate(max * (1 - i / 3)), width - 1, y + 3);
  }
  for (const [key, stroke] of [['down', color('--blue', '#3279c7')], ['up', color('--accent', '#087f72')]]) {
    const path = () => {
      g.beginPath();
      points.forEach((p, i) => {
        const x = (i / (points.length - 1)) * right;
        const y = bottom - (Math.max(0, p[key] || 0) / max) * (bottom - top);
        if (i === 0) g.moveTo(x, y); else g.lineTo(x, y);
      });
    };
    path();
    g.lineTo(right, bottom);
    g.lineTo(0, bottom);
    g.closePath();
    g.globalAlpha = .07;
    g.fillStyle = stroke;
    g.fill();
    g.globalAlpha = 1;
    path();
    g.strokeStyle = stroke;
    g.lineWidth = 1.8;
    g.stroke();
  }
}

function metric(label, value = '—', cls = '', symbol) {
  const output = h('div', { class: 'metric-value' }, value);
  return {
    el: h('div', { class: cls }, h('div', { class: 'metric-label' }, symbol ? icon(symbol) : null, label), output),
    set(value) { output.textContent = value; },
  };
}

export default function mount(view, ctx) {
  let alive = true;
  let privateDNS = false;
  let updatingMode = false;
  let traffic = null;
  let lastNotes = '';
  const stateChip = chip('连接中', '');
  stateChip.classList.add('status-chip');
  const coreName = h('div', { class: 'core-name' }, '—');
  const coreVersion = h('div', { class: 'small muted' }, '—');
  const duration = metric('运行时长');
  const capture = metric('流量接管');
  const process = metric('核心进程');
  const restarts = metric('自动重启', '0 次');
  const act = (label, path, message, cls = '') => btn(label, async () => {
    await post(path);
    toast(message, 'ok');
    await ctx.refreshStatus();
  }, cls);
  const start = act('启动核心', '/api/v1/core/start', '核心已启动', 'primary');
  const restart = act('重启核心', '/api/v1/core/restart', '核心已重启');
  const stop = act('停止', '/api/v1/core/stop', '核心已停止', 'danger');
  const disabled = h('span', { class: 'small muted', hidden: true }, '模块已在管理器中禁用');
  const detailBody = h('dl', { class: 'kv' });
  const mode = segmented(MODES, ctx.status?.mode || 'rule', async (value) => {
    updatingMode = true;
    try {
      await put('/api/v1/routing/mode', { mode: value });
      await ctx.refreshStatus();
    } finally { updatingMode = false; }
  }, '路由模式');

  const resources = h('div', { class: 'overview-resources' });
  const counts = {};
  for (const [key, label, page, symbol] of [['nodes', '节点', 'proxies', 'network'], ['groups', '代理组', 'proxies', 'route'], ['subscriptions', '订阅', 'subscriptions', 'rss']]) {
    counts[key] = h('b', null, '0');
    resources.append(h('a', { class: 'resource-link', href: '#/' + page }, icon(symbol),
      h('div', null, counts[key], h('span', null, label)), icon('chevronRight', 'chevron')));
  }
  const down = metric('下载速度', '0 B/s', 'down', 'arrowDown');
  const up = metric('上传速度', '0 B/s', 'up', 'arrowUp');
  const downTotal = metric('累计下载', '0 B', 'traffic-total');
  const upTotal = metric('累计上传', '0 B', 'traffic-total');
  const trafficState = h('span', { class: 'small muted' }, '等待数据');
  const canvas = h('canvas', { class: 'chart', role: 'img', 'aria-label': '上传和下载流量曲线' });
  const chartStart = h('span');
  const chartEnd = h('span');
  const notes = h('div', { class: 'overview-notes' });
  view.append(
    card('运行状态', stateChip,
      h('div', { class: 'runtime-heading' },
        h('div', { class: 'core-identity' }, h('div', { class: 'core-symbol' }, icon('cpu')),
          h('div', { class: 'grow' }, coreName, coreVersion)),
        h('div', { class: 'row' }, start, restart, stop, disabled)),
      h('div', { class: 'runtime-metrics' }, duration.el, capture.el, process.el, restarts.el),
      h('details', { class: 'overview-details' }, h('summary', null, '服务详情'), detailBody)),
    h('section', { class: 'section mode-band', 'aria-label': '路由模式' }, h('h2', null, '路由模式'), mode.el),
    resources,
    card('实时流量', trafficState,
      h('div', { class: 'traffic-stats' }, down.el, up.el, downTotal.el, upTotal.el),
      h('div', { class: 'chart-wrap' }, canvas, h('div', { class: 'chart-caption' }, chartStart, chartEnd))),
    notes,
  );

  function render(s) {
    if (!alive) return;
    const core = s.core || {};
    const daemon = s.daemon || {};
    const running = core.state === 'running';
    const transition = ['starting', 'restarting', 'stopping'].includes(core.state);
    stateChip.textContent = ctx.stateName(core.state);
    stateChip.className = 'chip status-chip ' + (running ? 'ok' : core.state === 'failed' ? 'err' : transition ? 'warn' : '');
    coreName.textContent = (core.engine || s.engine) === 'mihomo' ? 'Mihomo' : core.engine || s.engine || '未选择核心';
    coreVersion.textContent = core.version || '尚未运行';
    duration.set(running && core.startedAt ? fmtDuration((Date.now() - new Date(core.startedAt)) / 1000) : '—');
    capture.set(running ? core.captureActive ? '已生效' : '未生效' : '未接管');
    capture.el.classList.toggle('delay-good', running && !!core.captureActive);
    process.set(running ? `PID ${core.pid}` : '—');
    restarts.set(`${core.restarts || 0} 次`);
    start.hidden = running || transition || core.state === 'disabled';
    restart.hidden = !running && !transition;
    stop.hidden = !running && !transition;
    disabled.hidden = core.state !== 'disabled';
    setDisabled(restart, transition);
    setDisabled(stop, transition);
    restart.classList.toggle('primary', !!core.pending);
    restart.querySelector('.btn-label').textContent = core.pending ? '应用配置并重启' : '重启核心';
    if (!updatingMode) mode.setValue(s.mode);
    for (const [key, output] of Object.entries(counts)) output.textContent = String(s.counts?.[key] || 0);
    clear(detailBody).append(
      h('dt', null, '管理服务'), h('dd', null, `${daemon.version || '—'} · ${daemon.build || '—'}`),
      h('dt', null, '设备架构'), h('dd', null, daemon.abi || '—'),
      h('dt', null, '配置修订'), h('dd', null, String(s.revision)),
      h('dt', null, '自动重启窗口'), h('dd', null, '10 分钟'));

    const items = [];
    if (core.lastError) items.push(['err', '最近错误：' + core.lastError]);
    if (core.lastExit && !running) items.push(['warn', '上次退出：' + core.lastExit]);
    for (const warning of core.warnings || []) items.push(['warn', warning]);
    if (core.missingRulesets?.length) items.push(['warn', '规则集缺失，相关规则暂未生效：' + core.missingRulesets.map((r) => `${r.kind}:${r.name}`).join('、')]);
    if (core.unknownPackages?.length) items.push(['warn', '应用名单中有未安装的应用：' + core.unknownPackages.join('、')]);
    for (const notice of daemon.notices || []) items.push(['info', notice]);
    if (privateDNS) items.push(['warn', '系统“私人 DNS”指定了主机名，DNS 查询可能绕过代理。建议关闭或改为“自动”。']);
    const key = JSON.stringify(items);
    if (key !== lastNotes) {
      lastNotes = key;
      clear(notes);
      if (items.length) notes.append(card('需要留意', null, items.map(([kind, text]) => h('div', { class: 'banner ' + kind }, text))));
    }
  }

  const redraw = () => { if (alive) drawChart(canvas, traffic?.history || []); };
  function renderTraffic(t) {
    if (!alive) return;
    traffic = t;
    down.set(fmtRate(t.down));
    up.set(fmtRate(t.up));
    downTotal.set(fmtBytes(t.downTotal));
    upTotal.set(fmtBytes(t.upTotal));
    trafficState.textContent = `${t.connections || 0} 个活动连接`;
    canvas.setAttribute('aria-label', `流量曲线：下载 ${fmtRate(t.down)}，上传 ${fmtRate(t.up)}`);
    const history = t.history || [];
    const localTime = (time) => time ? new Date(`2000-01-01T${time}Z`).toLocaleTimeString('zh-CN', { hour12: false }) : '';
    chartStart.textContent = localTime(history[0]?.t);
    chartEnd.textContent = localTime(history[history.length - 1]?.t);
    redraw();
  }

  get('/api/v1/diagnostics').then((dg) => {
    if (!alive) return;
    privateDNS = !!dg.privateDnsWarning;
    if (ctx.status) render(ctx.status);
  }).catch(() => {});
  const off = ctx.onStatus(render);
  if (ctx.status) render(ctx.status);
  const observer = window.ResizeObserver ? new window.ResizeObserver(redraw) : null;
  observer?.observe(canvas);
  window.addEventListener('resize', redraw);
  document.addEventListener('kpm-theme-applied', redraw);
  redraw();
  const poll = poller(async () => {
    try { renderTraffic(await get('/api/v1/traffic')); }
    catch (e) { if (alive) trafficState.textContent = errorText(e); }
  }, 2000);
  return () => {
    alive = false;
    off();
    poll.stop();
    observer?.disconnect();
    window.removeEventListener('resize', redraw);
    document.removeEventListener('kpm-theme-applied', redraw);
  };
}
