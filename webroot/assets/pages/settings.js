import { get, post, put, q, hasBridge } from '../api.js?v=__V__';
import { h, clear, card, btn, loading, toast, modal, form, confirmDialog, errorText, empty, fmtBytes, fmtTime } from '../ui.js?v=__V__';

const SETTINGS_FIELDS = [
  { section: '启动与恢复' },
  { key: 'autoStart', label: '开机自动启动核心', type: 'switch' },
  { key: 'autoRestart', label: '核心异常退出时自动重启', type: 'switch', hint: '10 分钟内最多重启 3 次' },
  { key: 'failClosed', label: '防泄漏（失败关闭）', type: 'switch', hint: '开启后核心异常时被代理的应用将断网而不是直连；关闭时自动恢复直连' },
  { section: '网络' },
  { key: 'ipv6', label: '代理 IPv6', type: 'switch', hint: '关闭时被代理应用的 IPv6 连接会被拒绝，以便回退 IPv4' },
  { key: 'bypassLan', label: '局域网地址直连', type: 'switch' },
  { key: 'bypassCidrs', label: '额外直连网段（每行一个 CIDR）', type: 'lines', rows: 3 },
  { key: 'mtu', label: 'TUN MTU', type: 'number', min: 1280, max: 65535 },
  { key: 'tunStack', label: 'TUN 协议栈', type: 'select', options: [['', '默认'], ['system', 'system'], ['gvisor', 'gvisor'], ['mixed', 'mixed']] },
  { key: 'logLevel', label: '核心日志级别', type: 'select', options: [['debug', 'debug'], ['info', 'info'], ['warn', 'warn'], ['error', 'error'], ['silent', 'silent']] },
  { section: '热点共享' },
  { key: 'hotspot.enabled', label: '代理热点 / USB 共享的设备', type: 'switch' },
  { key: 'hotspot.interfaces', label: '共享网卡（每行一个，支持 * 结尾通配）', type: 'lines', rows: 3, show: (v) => v.hotspot && v.hotspot.enabled },
  { section: '下载' },
  { key: 'download.mode', label: '下载方式', type: 'select', options: [['auto', '自动（先直连，失败经代理）'], ['direct', '仅直连'], ['proxy', '仅经代理']] },
  { key: 'download.githubMirror', label: 'GitHub 下载镜像（可选）', type: 'url', placeholder: 'https://mirror.example/', hint: '仅用于下载核心文件，仍会校验官方 SHA-256 摘要' },
  { key: 'rulesetAutoUpdate', label: '每周自动更新规则集', type: 'switch' },
  { section: '浏览器访问' },
  { key: 'webAccess.enabled', label: '允许本机浏览器访问', type: 'switch', hint: '仅监听 127.0.0.1，需要访问密钥' },
  { key: 'webAccess.port', label: '端口', type: 'number', min: 1024, max: 65535, show: (v) => v.webAccess && v.webAccess.enabled },
];

export default function mount(view, ctx) {
  let alive = true;
  const settingsBox = h('div', null, loading());
  const webBox = h('div', null, loading());
  const backupBox = h('div', null, loading());
  const systemBox = h('div', null, loading());
  const aboutBox = h('div');
  view.append(
    card('常规设置', null, settingsBox),
    card('浏览器访问', null, webBox),
    card('备份与恢复', null, backupBox),
    card('卸载与诊断', null, systemBox),
    card('关于', null, aboutBox),
  );

  async function loadSettings() {
    const s = await get('/api/v1/settings');
    if (!alive) return;
    const f = form(SETTINGS_FIELDS, s.settings);
    clear(settingsBox).append(f.el, h('div', { class: 'form-actions' }, btn('保存', async () => {
      try {
        const r = await put(q('/api/v1/settings', { rev: s.revision }), f.values);
        toast(r.pending ? '已保存，重启核心后生效' : '已保存', 'ok');
      } catch (e) {
        toast(errorText(e), 'err');
      }
      await loadSettings();
      await loadSystem();
      ctx.refreshStatus().catch(() => {});
    }, 'primary')));
  }

  async function loadSystem() {
    const s = await get('/api/v1/system');
    if (!alive) return;
    let webState = '未开启（在上方设置中开启）';
    if (s.webAccess.enabled && !s.hasWebKey) webState = '已开启，但还没有访问密钥：请先生成密钥';
    else if (s.webAccessActive) webState = `已开启：在本机浏览器打开 ${s.webAccessUrl}`;
    else if (s.webAccess.enabled) webState = '已开启，但端口监听失败（可能被占用），请查看日志';
    clear(webBox).append(
      h('p', null, webState),
      h('div', { class: 'row' },
        btn(s.hasWebKey ? '重新生成密钥' : '生成密钥', async () => {
          if (s.hasWebKey && !(await confirmDialog('旧密钥将立即失效，继续？'))) return;
          const r = await post('/api/v1/system/web-key');
          await modal('访问密钥', h('div', null, h('p', { class: 'small muted' }, '密钥只显示这一次，请妥善保存：'), h('p', { class: 'mono break' }, r.key)));
          await loadSystem();
        }, 'small')),
      h('p', { class: 'small muted' }, '浏览器访问只接受来自 127.0.0.1 / localhost 的请求，并校验来源与密钥。'));
    const del = h('input', { type: 'checkbox', checked: s.deleteDataOnUninstall, onchange: async () => {
      try {
        await put('/api/v1/system', { deleteDataOnUninstall: del.checked });
        toast('已保存', 'ok');
      } catch (e) {
        toast(errorText(e), 'err');
      }
    } });
    clear(systemBox).append(
      h('label', { class: 'row' }, del, h('span', null, '卸载模块时同时删除数据（配置、核心、日志）')),
      h('p', { class: 'small muted' }, `数据目录：${s.dataDir}。默认卸载时保留，以便重新安装后继续使用。`),
      h('div', { class: 'row' }, btn('查看诊断信息', async () => {
        const d = await get('/api/v1/diagnostics');
        await modal('诊断信息', h('pre', { class: 'mono break', style: { whiteSpace: 'pre-wrap' } }, JSON.stringify(d, null, 2)));
      }, 'small')),
      h('p', { class: 'small muted' }, '网络异常时可在终端执行 proxyctl cleanup：停止服务并移除本模块的全部路由规则。'));
  }

  async function loadBackups() {
    const [b, files] = await Promise.all([get('/api/v1/backups'), hasBridge() ? get('/api/v1/backup/files') : Promise.resolve({ files: [] })]);
    if (!alive) return;
    const restore = async (label, body) => {
      if (!(await confirmDialog(`用「${label}」覆盖当前配置？当前配置会先自动备份。`, '恢复', true))) return;
      try {
        const r = await post('/api/v1/backup/restore', body);
        toast(r.pending ? '已恢复，重启核心后生效' : '已恢复', 'ok');
      } catch (e) {
        toast(errorText(e), 'err');
      }
      ctx.refreshStatus().catch(() => {});
      await loadSettings();
    };
    const exportBtn = (label, secrets) => btn(label, async () => {
      if (secrets && !(await confirmDialog('备份文件将包含节点密码与订阅地址，请勿分享。继续？'))) return;
      const r = await post('/api/v1/backup/export', { secrets });
      await modal('已导出', h('p', { class: 'break' }, '备份已保存到 ' + r.path));
      await loadBackups();
    }, 'small');
    const fileList = h('ul', { class: 'list' }, files.files.map((f) => h('li', null,
      h('div', { class: 'grow' }, h('div', { class: 'title ellipsis' }, f.name), h('div', { class: 'sub' }, `${fmtBytes(f.size)} · ${fmtTime(f.modTime)}`)),
      btn('恢复', () => restore(f.name, { path: f.path }), 'small'))));
    const backupLabel = (x) => x.kind === 'legacy' ? '旧版配置' : x.kind === 'rejected' ? '异常配置原件' : `修订 ${x.revision}`;
    const autoList = h('ul', { class: 'list' }, b.backups.slice().reverse().map((x) => h('li', null,
      h('div', { class: 'grow' }, h('div', { class: 'title' }, backupLabel(x)), h('div', { class: 'sub' }, fmtTime(x.time))),
      btn('恢复', () => restore(backupLabel(x), { backup: x.name }), 'small'))));
    clear(backupBox).append(
      h('div', { class: 'row' }, exportBtn('导出（不含凭据）', false), hasBridge() ? exportBtn('导出（含凭据）', true) : null),
      h('p', { class: 'small muted' }, '导出文件保存在内部存储 Download 目录。恢复不含凭据的备份时，会沿用当前已保存的凭据。'),
      hasBridge() ? h('details', { open: files.files.length > 0 }, h('summary', null, `下载目录中的备份文件（${files.files.length}）`), files.files.length ? fileList : empty('没有找到 ksu_proxy_manager-*.json')) : null,
      h('details', null, h('summary', null, `本机恢复点（${b.backups.length}）`), b.backups.length ? autoList : empty('暂无')));
  }

  function renderAbout() {
    const s = ctx.status;
    if (!s) return;
    clear(aboutBox).append(h('dl', { class: 'kv' },
      h('dt', null, '版本'), h('dd', null, `${s.daemon.version}（${s.daemon.versionCode}）`),
      h('dt', null, '构建'), h('dd', null, s.daemon.build),
      h('dt', null, '架构'), h('dd', null, s.daemon.abi),
      h('dt', null, '连接方式'), h('dd', null, hasBridge() ? 'KernelSU WebUI' : '浏览器'),
      h('dt', null, '管理服务启动于'), h('dd', null, fmtTime(s.daemon.startedAt))));
  }

  Promise.all([loadSettings(), loadSystem(), loadBackups()]).catch((e) => {
    if (!alive) return;
    for (const box of [settingsBox, webBox, backupBox, systemBox]) {
      if (box.querySelector('.loading')) clear(box).append(empty(errorText(e)));
    }
  });
  renderAbout();
  return () => { alive = false; };
}
