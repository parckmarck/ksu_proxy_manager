import { get, put, q, randomHex } from '../api.js?v=__V__';
import { h, clear, card, btn, toolBtn, setDisabled, loading, chip, toast, modal, form, confirmDialog, errorText, empty } from '../ui.js?v=__V__';

export const RULE_TYPES = [
  ['domain_suffix', '域名后缀'], ['domain', '完整域名'], ['domain_keyword', '域名关键字'], ['domain_regex', '域名正则'],
  ['ip_cidr', 'IP 段'], ['geosite', '域名规则集 (geosite)'], ['geoip', 'IP 规则集 (geoip)'], ['package', '应用包名'],
  ['port', '目标端口'], ['network', '网络 (tcp/udp)'],
];
const typeName = (t) => (RULE_TYPES.find(([v]) => v === t) || [t, t])[1];
const PRESETS = [
  ['cn', '中国大陆直连：国内域名与 IP 直连，其余走兜底出口'],
  ['global', '全部走兜底出口（仍应用自定义规则）'],
  ['custom', '仅使用自定义规则'],
];

function targetOptions(groups) {
  return [...groups.map((g) => ['group:' + g.id, '代理组：' + g.name]), ['DIRECT', '直连'], ['REJECT', '拒绝']];
}

export function targetName(groups, ref) {
  if (ref === 'DIRECT') return '直连';
  if (ref === 'REJECT') return '拒绝';
  const g = groups.find((x) => 'group:' + x.id === ref);
  return g ? g.name : ref;
}

async function editRule(groups, rule) {
  const initial = rule ? structuredClone(rule) : { id: 'r' + randomHex(4), enabled: true, type: 'domain_suffix', values: [], target: groups[0] ? 'group:' + groups[0].id : 'DIRECT', note: '' };
  const f = form([
    { key: 'type', label: '类型', type: 'select', options: RULE_TYPES },
    { key: 'values', label: '匹配值（每行一个）', type: 'lines', rows: 5, placeholder: 'example.com', hint: 'geosite/geoip 填规则集名，如 google、telegram、geolocation-!cn；端口支持 443 或 8000-9000' },
    { key: 'target', label: '出口', type: 'select', options: targetOptions(groups) },
    { key: 'note', label: '备注' },
    { key: 'enabled', label: '启用', type: 'switch' },
  ], initial);
  const v = await modal(rule ? '编辑规则' : '添加规则', f.el, [
    { label: '取消', value: null },
    { label: '确定', value: 'ok', cls: 'primary', onclick: () => {
      if (!f.values.values.length) {
        toast('请填写匹配值', 'err');
        return false;
      }
      return true;
    } },
  ]);
  return v === 'ok' ? f.values : null;
}

export default function mount(view) {
  let data = null;
  let groups = [];
  let alive = true;
  const settingsBox = h('div', null, loading());
  const rulesBox = h('div', null, loading());
  const dnsBox = h('div', null, loading());
  view.append(
    card('分流设置', null, settingsBox),
    card('自定义规则', btn('添加', async () => {
      const r = await editRule(groups, null);
      if (r) {
        data.routing.rules.push(r);
        await saveRouting();
      }
    }, 'small primary'), rulesBox),
    card('DNS', null, dnsBox),
  );

  async function saveRouting() {
    try {
      await put(q('/api/v1/routing', { rev: data.routingRevision }), data.routing);
      toast('已保存', 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
    await load();
  }

  function renderSettings() {
    const r = data.routing;
    const f = form([
      { key: 'preset', label: '预设', type: 'select', options: PRESETS },
      { key: 'final', label: '兜底出口', type: 'select', options: targetOptions(groups) },
      { key: 'blockAds', label: '拦截广告（geosite:category-ads-all）', type: 'switch' },
      { key: 'blockQuic', label: '阻止 QUIC（UDP 443），促使应用回退 TCP', type: 'switch' },
    ], { preset: r.preset, final: r.final, blockAds: r.blockAds, blockQuic: r.blockQuic });
    clear(settingsBox).append(f.el, h('div', { class: 'form-actions' }, btn('保存', async () => {
      Object.assign(data.routing, f.values);
      await saveRouting();
    }, 'primary')));
  }

  function move(i, d) {
    const rules = data.routing.rules;
    const j = i + d;
    if (j < 0 || j >= rules.length) return;
    [rules[i], rules[j]] = [rules[j], rules[i]];
    return saveRouting();
  }

  function renderRules() {
    clear(rulesBox);
    const rules = data.routing.rules;
    if (!rules.length) {
      rulesBox.append(empty('没有自定义规则'));
      return;
    }
    const ul = h('ul', { class: 'list' });
    rules.forEach((r, i) => {
      ul.append(h('li', { class: 'rule-row' },
        h('div', { class: 'grow' },
          h('div', { class: 'title' }, typeName(r.type), ' → ', targetName(groups, r.target), r.enabled ? null : [' ', chip('已停用', 'warn')]),
          h('div', { class: 'sub ellipsis' }, r.values.join(', ') + (r.note ? ` · ${r.note}` : ''))),
        h('div', { class: 'row-actions' },
        setDisabled(toolBtn('上移', 'arrowUp', () => move(i, -1)), i === 0),
        setDisabled(toolBtn('下移', 'arrowDown', () => move(i, 1)), i === rules.length - 1),
        toolBtn('编辑', 'pencil', async () => {
          const nr = await editRule(groups, r);
          if (nr) {
            rules[i] = nr;
            await saveRouting();
          }
        }),
        toolBtn('删除', 'trash2', async () => {
          if (!(await confirmDialog('删除这条规则？', '删除', true))) return;
          rules.splice(i, 1);
          await saveRouting();
        }, 'danger'))));
    });
    rulesBox.append(ul);
  }

  function renderDNS() {
    const d = data.dns;
    const f = form([
      { key: 'mode', label: '模式', type: 'select', options: [['fakeip', 'Fake-IP（推荐，域名分流最准确）'], ['realip', '真实 IP']] },
      { key: 'direct', label: '直连 DNS（每行一个，至少一个 IP）', type: 'lines', rows: 3, hint: '支持 223.5.5.5、tls://、https://、quic://；用于解析直连域名与节点服务器' },
      { key: 'proxy', label: '代理 DNS（每行一个）', type: 'lines', rows: 3, hint: '经代理出口查询，用于境外域名' },
      { key: 'fakeipFilter', label: 'Fake-IP 排除（每行一个，支持 +. 与 * 通配）', type: 'lines', rows: 5, show: (v) => v.mode === 'fakeip' },
    ], d);
    clear(dnsBox).append(f.el, h('div', { class: 'form-actions' },
      btn('保存', async () => {
        try {
          await put(q('/api/v1/dns', { rev: data.dnsRevision }), f.values);
          toast('已保存', 'ok');
        } catch (e) {
          toast(errorText(e), 'err');
        }
        await load();
      }, 'primary'),
      btn('恢复默认排除列表', async () => {
        f.values.fakeipFilter = [...data.defaultFakeipFilter];
        try {
          await put(q('/api/v1/dns', { rev: data.dnsRevision }), f.values);
          toast('已恢复', 'ok');
        } catch (e) {
          toast(errorText(e), 'err');
        }
        await load();
      })));
  }

  async function load() {
    const [r, d, g] = await Promise.all([get('/api/v1/routing'), get('/api/v1/dns'), get('/api/v1/groups')]);
    if (!alive) return;
    groups = g.groups;
    data = { routing: r.routing, routingRevision: r.revision, dnsRevision: d.revision, dns: d.dns, defaultFakeipFilter: d.defaultFakeipFilter || [] };
    data.dns.fakeipFilter = data.dns.fakeipFilter || [];
    renderSettings();
    renderRules();
    renderDNS();
  }
  load().catch((e) => {
    if (!alive) return;
    for (const box of [settingsBox, rulesBox, dnsBox]) clear(box).append(empty(errorText(e)));
  });
  return () => { alive = false; };
}
