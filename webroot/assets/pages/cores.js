import { get, post, put, del, q, waitTask, hasBridge } from '../api.js?v=__V__';
import { h, clear, card, btn, toolBtn, icon, loading, chip, toast, confirmDialog, errorText, empty, fmtBytes, fmtTime, progressDialog } from '../ui.js?v=__V__';

const ENGINES = [['mihomo', 'Mihomo'], ['sing-box', 'sing-box']];
const VERIFY = {
  'github-digest': ['官方 · 已校验', 'ok'],
  'local-unverified': ['本地导入', 'warn'],
  // Entries recorded by 1.x releases.
  'official-digest+elf+version': ['官方 · 已校验', 'ok'],
  'sha256+elf+root-executed-version+user-confirmed': ['本地导入', 'warn'],
};

async function runTask(title, start) {
  const pd = progressDialog(title);
  try {
    const task = await start();
    return await waitTask(task, (t) => pd.update(t), { signal: pd.signal });
  } finally {
    pd.close();
  }
}

export default function mount(view, ctx) {
  let alive = true;
  let info = null;
  let settings = null;
  let revision = 0;
  const activeBox = h('div', null, loading());
  const installedBox = h('div', null, loading());
  const downloadBox = h('div', null, loading());
  const importBox = h('div', null, loading());
  const rulesetBox = h('div', null, loading());
  view.append(
    card('使用的核心', null, activeBox),
    card('已安装', null, installedBox),
    card('下载官方核心', null, downloadBox),
    ...(hasBridge() ? [card('导入本地文件', toolBtn('刷新', 'refreshCw', () => loadFiles(), 'ghost'), importBox)] : []),
    card('规则集', null, rulesetBox),
  );

  async function saveSettings(patch) {
    try {
      await put(q('/api/v1/settings', { rev: revision }), { ...settings, ...patch });
      toast('已保存，重启核心后生效', 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
    await load();
  }

  function renderActive() {
    clear(activeBox);
    const engineSel = h('select', { id: 'active-engine', onchange: () => saveSettings({ engine: engineSel.value }) }, ENGINES.map(([v, l]) => h('option', { value: v }, l)));
    engineSel.value = settings.engine;
    const versions = info.installed.filter((i) => i.engine === settings.engine && i.abi === info.abi);
    const verSel = h('select', { id: 'active-version', onchange: () => saveSettings({ coreVersions: { ...settings.coreVersions, [settings.engine]: verSel.value } }) },
      h('option', { value: '' }, '自动（最新已安装版本）'), versions.map((i) => h('option', { value: i.version }, i.version)));
    verSel.value = settings.coreVersions[settings.engine] || '';
    activeBox.append(h('div', { class: 'form' },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'active-engine' }, '核心类型'), engineSel),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'active-version' }, '版本'), verSel),
      versions.length ? null : h('div', { class: 'banner warn' }, `尚未安装 ${settings.engine}，请在下方下载或导入。`),
      info.running.engine ? h('div', { class: 'small muted' }, `正在运行：${info.running.engine} ${info.running.version}`) : null));
  }

  function renderInstalled() {
    clear(installedBox);
    if (!info.installed.length) {
      installedBox.append(empty('还没有安装任何核心'));
      return;
    }
    const ul = h('ul', { class: 'list' });
    for (const it of info.installed) {
      const [vtext, vcls] = VERIFY[it.verification] || [it.verification, ''];
      const running = info.running.engine === it.engine && info.running.version === it.version && it.abi === info.abi;
      const foreign = it.abi !== info.abi;
      ul.append(h('li', null,
        icon('cpu'),
        h('div', { class: 'grow' },
          h('div', { class: 'title' }, `${it.engine} ${it.version} `, chip(vtext, vcls), running ? [' ', chip('运行中', 'ok')] : null,
            foreign ? [' ', chip(`架构不符（${it.abi}），不可用`, 'err')] : null),
          h('div', { class: 'sub ellipsis' }, `${it.releaseAsset || ''} · 安装于 ${fmtTime(it.installedAt)} · SHA-256 ${String(it.sha256).slice(0, 16)}…`)),
        toolBtn('删除', 'trash2', async () => {
          if (!(await confirmDialog(`删除 ${it.engine} ${it.version}？`, '删除', true))) return;
          try {
            await del(q(`/api/v1/cores/${encodeURIComponent(it.engine)}/${encodeURIComponent(it.version)}`, { abi: it.abi }));
            toast('已删除', 'ok');
          } catch (e) {
            toast(errorText(e), 'err');
          }
          await load();
        }, 'ghost danger')));
    }
    installedBox.append(ul);
  }

  function renderDownload() {
    clear(downloadBox);
    const engineSel = h('select', { 'aria-label': '下载核心类型' }, ENGINES.map(([v, l]) => h('option', { value: v }, l)));
    engineSel.value = settings.engine;
    const pre = h('input', { type: 'checkbox' });
    const list = h('div');
    const fetchBtn = btn('获取版本列表', async () => {
      clear(list).append(h('p', { class: 'muted small' }, '正在查询 GitHub…'));
      const r = await get(q('/api/v1/cores/releases', { engine: engineSel.value, pre: pre.checked ? 1 : '' }));
      clear(list);
      if (!r.releases.length) {
        list.append(empty('没有找到适用于本设备的版本'));
        return;
      }
      const ul = h('ul', { class: 'list' });
      for (const rel of r.releases.slice(0, 15)) {
        ul.append(h('li', null,
          h('div', { class: 'grow' }, h('div', { class: 'title' }, rel.tag, rel.prerelease ? [' ', chip('预发布', 'warn')] : null),
            h('div', { class: 'sub' }, `${fmtTime(rel.publishedAt)} · ${fmtBytes(rel.asset.size)}`)),
          btn('下载安装', async () => {
            const res = await runTask(`下载 ${engineSel.value} ${rel.tag}`, () => post('/api/v1/cores/download', { engine: engineSel.value, tag: rel.tag }));
            toast(`已安装 ${res.engine} ${res.version}`, 'ok');
            await load();
          }, 'small primary')));
      }
      list.append(ul);
    }, 'primary');
    downloadBox.append(h('div', { class: 'toolbar' }, engineSel, h('label', { class: 'row small' }, pre, '包含预发布'), fetchBtn), list,
      h('p', { class: 'small muted' }, '只从官方 GitHub 发布页下载，并用 GitHub 提供的 SHA-256 摘要校验；设置中可配置下载镜像（同样校验摘要）。'));
  }

  async function loadFiles() {
    if (!hasBridge()) return;
    clear(importBox).append(h('p', { class: 'muted small' }, '正在扫描…'));
    const r = await get('/api/v1/cores/files');
    if (!alive) return;
    clear(importBox);
    const pathInput = h('input', { type: 'text', 'aria-label': '本地核心路径', placeholder: '/sdcard/Download/mihomo-android-arm64-v8.gz' });
    const doImport = async (path) => {
      const res = await runTask('导入核心', () => post('/api/v1/cores/import', { path }));
      toast(`已导入 ${res.engine} ${res.version}`, 'ok');
      await load();
    };
    if (r.files.length) {
      const ul = h('ul', { class: 'list' });
      for (const f of r.files) {
        ul.append(h('li', null, h('div', { class: 'grow' }, h('div', { class: 'title ellipsis' }, f.name), h('div', { class: 'sub' }, `${fmtBytes(f.size)} · ${fmtTime(f.modTime)}`)),
          btn('导入', () => doImport(f.path), 'small')));
      }
      importBox.append(ul);
    } else {
      importBox.append(h('p', { class: 'small muted' }, '下载目录中没有找到核心文件（文件名需包含 mihomo 或 sing-box）。'));
    }
    importBox.append(h('div', { class: 'row', style: { marginTop: '8px' } }, h('div', { class: 'grow' }, pathInput),
      btn('按路径导入', () => (pathInput.value.trim() ? doImport(pathInput.value.trim()) : null), 'small')),
    h('p', { class: 'small muted' }, '支持 .gz / .tar.gz / .zip 或可执行文件，会检查架构并运行版本命令识别类型；本地文件来源无法校验，请只导入可信文件。'));
  }

  async function renderRulesets() {
    const r = await get('/api/v1/rulesets');
    if (!alive) return;
    clear(rulesetBox);
    const have = new Set(r.installed.filter((x) => x.engine === r.engine).map((x) => x.kind + ':' + x.name));
    const ul = h('ul', { class: 'list' });
    for (const id of r.needed) {
      const ok = have.has(id.kind + ':' + id.name);
      const ent = r.installed.find((x) => x.engine === r.engine && x.kind === id.kind && x.name === id.name);
      ul.append(h('li', null, h('div', { class: 'grow' }, h('div', { class: 'title' }, `${id.kind}:${id.name}`),
        h('div', { class: 'sub' }, ent ? `${fmtBytes(ent.size)} · 更新于 ${fmtTime(ent.updatedAt)}` : '未下载')), chip(ok ? '就绪' : '缺失', ok ? 'ok' : 'warn')));
    }
    const auto = h('input', { type: 'checkbox', checked: !!r.autoUpdate, onchange: () => saveSettings({ rulesetAutoUpdate: auto.checked }) });
    rulesetBox.append(
      r.needed.length ? ul : empty('当前配置不需要规则集'),
      h('div', { class: 'row', style: { marginTop: '8px' } },
        btn('下载缺失', async () => { await runTask('下载规则集', () => post('/api/v1/rulesets/update', { missingOnly: true })); toast('完成', 'ok'); await renderRulesets(); }, 'small'),
        btn('全部更新', async () => { await runTask('更新规则集', () => post('/api/v1/rulesets/update', {})); toast('完成', 'ok'); await renderRulesets(); }, 'small primary'),
        h('label', { class: 'row small' }, auto, '每周自动更新')),
      h('p', { class: 'small muted' }, `规则集来自 MetaCubeX/meta-rules-dat（${r.engine === 'sing-box' ? '.srs' : '.mrs'} 格式）。缺失时相关规则会被暂时跳过，下载完成后自动生效。`));
  }

  async function load() {
    const [c, s] = await Promise.all([get('/api/v1/cores'), get('/api/v1/settings')]);
    if (!alive) return;
    info = c;
    settings = s.settings;
    revision = s.revision;
    renderActive();
    renderInstalled();
    renderRulesets().catch((e) => toast(errorText(e), 'err'));
    ctx.refreshStatus().catch(() => {});
  }

  load().then(() => { if (!alive) return; renderDownload(); return loadFiles(); }).catch((e) => {
    if (!alive) return;
    for (const box of [activeBox, installedBox, downloadBox, importBox]) {
      if (box.querySelector('.loading')) clear(box).append(empty(errorText(e)));
    }
    toast(errorText(e), 'err');
  });
  return () => { alive = false; };
}
