import { get, post, put, del } from '../api.js?v=__V__';
import { h, clear, card, btn, toolBtn, icon, searchField, loading, chip, toast, modal, form, confirmDialog, errorText, empty, delayClass, lines } from '../ui.js?v=__V__';

export const NODE_TYPES = [
  ['shadowsocks', 'Shadowsocks'], ['vmess', 'VMess'], ['vless', 'VLESS'], ['trojan', 'Trojan'],
  ['hysteria2', 'Hysteria2'], ['tuic', 'TUIC'], ['anytls', 'AnyTLS'], ['socks', 'SOCKS5'], ['http', 'HTTP(S)'], ['wireguard', 'WireGuard'],
];
const SS_CIPHERS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305', 'aes-192-gcm', 'none'];
const SECRET_FIELDS = {
  shadowsocks: ['password'], vmess: ['uuid'], vless: ['uuid'], trojan: ['password'], hysteria2: ['password', 'obfsPassword'],
  tuic: ['uuid', 'password'], anytls: ['password'], socks: ['username', 'password'], http: ['username', 'password'], wireguard: ['privateKey', 'preSharedKey'],
};
const SECRET_LABELS = { password: '密码', uuid: 'UUID', obfsPassword: '混淆密码', username: '用户名', privateKey: '私钥', preSharedKey: '预共享密钥' };
const TRANSPORT_TYPES = new Set(['vmess', 'vless', 'trojan']);
const TLS_TYPES = new Set(['vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'anytls', 'http']);
const TLS_REQUIRED = new Set(['trojan', 'hysteria2', 'tuic', 'anytls']);
const FINGERPRINTS = ['', 'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random'];

const typeLabel = (t) => (NODE_TYPES.find(([v]) => v === t) || [t, t])[1];
const is = (...types) => (v) => types.includes(v.type);

function kvText(m) {
  return Object.entries(m || {}).map(([k, v]) => `${k}=${v}`).join('\n');
}

function parseKV(text) {
  const out = {};
  for (const line of lines(text)) {
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

// buildNode converts form values into the API node shape for its type.
export function buildNode(v) {
  const n = { id: v.id || '', name: String(v.name || '').trim(), type: v.type, server: String(v.server || '').trim(), port: Number(v.port) || 0, udp: v.type === 'http' ? false : !!v.udp };
  if (v.upstream) n.upstream = v.upstream;
  switch (v.type) {
    case 'shadowsocks':
      n.cipher = v.cipher;
      if (v.plugin) {
        n.plugin = v.plugin;
        n.pluginOpts = parseKV(v.pluginOptsText);
      }
      break;
    case 'vmess':
      n.security = v.security || 'auto';
      n.alterId = Number(v.alterId) || 0;
      break;
    case 'vless':
      if (v.flow) n.flow = v.flow;
      break;
    case 'hysteria2':
      if (v.obfs) n.obfs = v.obfs;
      if (v.ports) n.ports = String(v.ports).replace(/\s+/g, '');
      n.upMbps = Number(v.upMbps) || 0;
      n.downMbps = Number(v.downMbps) || 0;
      break;
    case 'tuic':
      if (v.congestionControl) n.congestionControl = v.congestionControl;
      if (v.udpRelayMode) n.udpRelayMode = v.udpRelayMode;
      break;
    case 'wireguard':
      n.localAddress = v.localAddress || [];
      n.peerPublicKey = String(v.peerPublicKey || '').trim();
      if ((v.reserved || []).length) n.reserved = v.reserved.map(Number);
      if (Number(v.wgMtu)) n.wgMtu = Number(v.wgMtu);
      break;
  }
  const t = v.transport || {};
  if (TRANSPORT_TYPES.has(v.type) && t.type && t.type !== 'tcp') {
    n.transport = { type: t.type };
    if (t.path) n.transport.path = t.path;
    if (t.host) n.transport.host = t.host;
    if (t.type === 'grpc' && t.serviceName) n.transport.serviceName = t.serviceName;
    if (t.headers && Object.keys(t.headers).length) n.transport.headers = { ...t.headers };
  }
  const tls = v.tls || {};
  if (TLS_TYPES.has(v.type) && (tls.enabled || TLS_REQUIRED.has(v.type))) {
    n.tls = { enabled: true };
    if (tls.sni) n.tls.sni = tls.sni.trim();
    if ((tls.alpn || []).length) n.tls.alpn = tls.alpn;
    if (tls.insecure) n.tls.insecure = true;
    if (tls.fingerprint) n.tls.fingerprint = tls.fingerprint;
    if (v.type === 'vless' && tls.realityPublicKey) {
      n.tls.realityPublicKey = tls.realityPublicKey.trim();
      n.tls.realityShortId = (tls.realityShortId || '').trim();
    }
  }
  return n;
}

function nodeFields(nodes, editing) {
  const secretHint = (f) => (editing && editing.secrets && editing.secrets[f] ? '已设置，留空表示不修改' : '');
  const others = () => [['', '无（直接连接）'], ...nodes.filter((n) => !editing || n.id !== editing.id).map((n) => [n.id, n.name])];
  const fields = [
    { key: 'name', label: '名称' },
    { key: 'type', label: '类型', type: 'select', options: NODE_TYPES },
    { key: 'server', label: '服务器', placeholder: '域名或 IP' },
    { key: 'port', label: '端口', type: 'number', min: 1, max: 65535 },
    { key: 'udp', label: '允许 UDP', type: 'switch', show: (v) => v.type !== 'http' },
    { key: 'cipher', label: '加密方式', type: 'select', options: SS_CIPHERS.map((c) => [c, c]), show: is('shadowsocks') },
    { key: 'plugin', label: '插件', type: 'select', options: [['', '无'], ['obfs', 'obfs'], ['v2ray-plugin', 'v2ray-plugin']], show: is('shadowsocks') },
    { key: 'pluginOptsText', label: '插件参数', type: 'textarea', rows: 3, placeholder: 'mode=http\nhost=example.com', show: (v) => v.type === 'shadowsocks' && !!v.plugin },
    { key: 'security', label: '加密', type: 'select', options: [['auto', 'auto'], ['aes-128-gcm', 'aes-128-gcm'], ['chacha20-poly1305', 'chacha20-poly1305'], ['none', 'none'], ['zero', 'zero']], show: is('vmess') },
    { key: 'alterId', label: 'alterId', type: 'number', min: 0, show: is('vmess') },
    { key: 'flow', label: '流控', type: 'select', options: [['', '无'], ['xtls-rprx-vision', 'xtls-rprx-vision']], show: is('vless') },
    { key: 'obfs', label: '混淆', type: 'select', options: [['', '无'], ['salamander', 'salamander']], show: is('hysteria2') },
    { key: 'ports', label: '端口跳跃', placeholder: '20000-30000,40000', show: is('hysteria2') },
    { key: 'upMbps', label: '上行带宽 (Mbps)', type: 'number', min: 0, show: is('hysteria2') },
    { key: 'downMbps', label: '下行带宽 (Mbps)', type: 'number', min: 0, show: is('hysteria2') },
    { key: 'congestionControl', label: '拥塞控制', type: 'select', options: [['', '默认'], ['bbr', 'bbr'], ['cubic', 'cubic'], ['new_reno', 'new_reno']], show: is('tuic') },
    { key: 'udpRelayMode', label: 'UDP 中继', type: 'select', options: [['', '默认'], ['native', 'native'], ['quic', 'quic']], show: is('tuic') },
    { key: 'localAddress', label: '本地地址', csv: true, placeholder: '10.0.0.2/32, fd00::2/128', show: is('wireguard') },
    { key: 'peerPublicKey', label: '对端公钥', show: is('wireguard') },
    { key: 'reserved', label: 'reserved', csv: true, placeholder: '0, 0, 0', show: is('wireguard') },
    { key: 'wgMtu', label: 'MTU', type: 'number', show: is('wireguard') },
  ];
  for (const f of ['username', 'password', 'uuid', 'obfsPassword', 'privateKey', 'preSharedKey']) {
    fields.push({
      key: 'secrets.' + f, label: SECRET_LABELS[f], type: f === 'uuid' || f === 'username' ? 'text' : 'password',
      placeholder: secretHint(f) || (f === 'preSharedKey' || ((f === 'username' || f === 'password')) ? '可选' : ''),
      show: (v) => (SECRET_FIELDS[v.type] || []).includes(f) && (f !== 'obfsPassword' || !!v.obfs),
    });
  }
  fields.push(
    { key: 'transport.type', label: '传输方式', type: 'select', options: [['tcp', 'TCP'], ['ws', 'WebSocket'], ['grpc', 'gRPC'], ['http', 'HTTP/2'], ['httpupgrade', 'HTTPUpgrade'], ['xhttp', 'XHTTP（仅 Mihomo）']], show: (v) => TRANSPORT_TYPES.has(v.type) },
    { key: 'transport.path', label: '路径', show: (v) => TRANSPORT_TYPES.has(v.type) && ['ws', 'http', 'httpupgrade', 'xhttp'].includes((v.transport || {}).type) },
    { key: 'transport.host', label: 'Host', show: (v) => TRANSPORT_TYPES.has(v.type) && ['ws', 'http', 'httpupgrade', 'xhttp'].includes((v.transport || {}).type) },
    { key: 'transport.serviceName', label: 'gRPC 服务名', show: (v) => TRANSPORT_TYPES.has(v.type) && (v.transport || {}).type === 'grpc' },
    { key: 'tls.enabled', label: '启用 TLS', type: 'switch', show: (v) => TLS_TYPES.has(v.type) && !TLS_REQUIRED.has(v.type) },
    { key: 'tls.sni', label: 'SNI', show: (v) => TLS_TYPES.has(v.type) && (TLS_REQUIRED.has(v.type) || (v.tls || {}).enabled) },
    { key: 'tls.alpn', label: 'ALPN', csv: true, placeholder: 'h2, http/1.1', show: (v) => TLS_TYPES.has(v.type) && (TLS_REQUIRED.has(v.type) || (v.tls || {}).enabled) },
    { key: 'tls.fingerprint', label: 'uTLS 指纹', type: 'select', options: FINGERPRINTS.map((f) => [f, f || '默认']), show: (v) => ['vmess', 'vless', 'trojan', 'anytls', 'http'].includes(v.type) && (TLS_REQUIRED.has(v.type) || (v.tls || {}).enabled) },
    { key: 'tls.insecure', label: '跳过证书验证（不安全）', type: 'switch', show: (v) => TLS_TYPES.has(v.type) && (TLS_REQUIRED.has(v.type) || (v.tls || {}).enabled) },
    { key: 'tls.realityPublicKey', label: 'Reality 公钥', show: (v) => v.type === 'vless' && (v.tls || {}).enabled },
    { key: 'tls.realityShortId', label: 'Reality shortId', show: (v) => v.type === 'vless' && (v.tls || {}).enabled && !!(v.tls || {}).realityPublicKey },
    { key: 'upstream', label: '前置节点（链式代理）', type: 'select', options: others },
  );
  return fields;
}

export async function editNode(nodes, node, onSaved) {
  const editing = node || null;
  const initial = editing
    ? { ...structuredClone(editing), pluginOptsText: kvText(editing.pluginOpts), secrets: {}, transport: editing.transport || { type: 'tcp' }, tls: editing.tls || { enabled: false } }
    : { name: '', type: 'shadowsocks', server: '', port: 443, udp: true, cipher: 'aes-128-gcm', security: 'auto', secrets: {}, transport: { type: 'tcp' }, tls: { enabled: false } };
  const f = form(nodeFields(nodes, editing), initial);
  const note = editing && editing.subscriptionId ? h('p', { class: 'banner warn small' }, '该节点来自订阅，订阅更新时修改会被覆盖（自行设置的前置节点会保留；订阅自带前置节点时以订阅为准）。') : null;
  await modal(editing ? '编辑节点' : '添加节点', h('div', null, note, f.el), [
    { label: '取消', value: null },
    { label: '保存', cls: 'primary', onclick: async () => {
      const v = f.values;
      const payload = { node: buildNode(v) };
      const secrets = {};
      for (const k of SECRET_FIELDS[v.type] || []) {
        const val = (v.secrets || {})[k];
        if (val) secrets[k] = val;
      }
      if (Object.keys(secrets).length) payload.secrets = secrets;
      try {
        if (editing) await put('/api/v1/nodes/' + encodeURIComponent(editing.id), payload);
        else await post('/api/v1/nodes', payload);
      } catch (e) {
        toast(errorText(e), 'err');
        return false;
      }
      toast('已保存', 'ok');
      onSaved();
      return true;
    } },
  ]);
}

async function importNodes(onDone) {
  const ta = h('textarea', { rows: 8, 'aria-label': '节点内容', placeholder: '分享链接 / Clash YAML / sing-box JSON / Base64', spellcheck: 'false' });
  await modal('导入节点', ta, [
    { label: '取消', value: null },
    { label: '导入', cls: 'primary', onclick: async () => {
      if (!ta.value.trim()) return false;
      try {
        const r = await post('/api/v1/nodes/import', { text: ta.value });
        const issues = r.issues || [];
        toast(`已导入 ${r.added} 个节点` + (issues.length ? `，${issues.length} 条未能识别` : ''), r.added ? 'ok' : 'err');
        if (issues.length) {
          await modal('未导入的条目', h('ul', { class: 'small' }, issues.slice(0, 50).map((i) => h('li', null, `${i.name ? i.name + '：' : ''}${i.message}`))));
        }
      } catch (e) {
        toast(errorText(e), 'err');
        return false;
      }
      onDone();
      return true;
    } },
  ]);
}

function groupFields(cfg, group) {
  const nodeOpts = () => cfg.nodes.map((n) => [n.id, n.name + (n.subscriptionName ? ` · ${n.subscriptionName}` : '')]);
  const groupOpts = () => cfg.groups.filter((g) => !group || g.id !== group.id).map((g) => [g.id, g.name]);
  const subOpts = () => cfg.subscriptions.map((s) => [s.id, s.name]);
  return [
    { key: 'name', label: '名称' },
    { key: 'type', label: '类型', type: 'select', options: [['select', '手动选择'], ['urltest', '自动测速选优']] },
    { key: 'includeAll', label: '包含全部节点', type: 'switch' },
    { key: 'subscriptions', label: '包含订阅的全部节点', type: 'checks', options: subOpts, show: (v) => !v.includeAll },
    { key: 'nodes', label: '包含节点', type: 'checks', options: nodeOpts, show: (v) => !v.includeAll },
    { key: 'groups', label: '包含代理组', type: 'checks', options: groupOpts },
    { key: 'filter', label: '名称包含（正则）', placeholder: '例如 香港|HK', hint: '只保留名称匹配的节点' },
    { key: 'excludeFilter', label: '名称排除（正则）', placeholder: '例如 剩余|过期' },
    { key: 'includeDirect', label: '包含“直连”选项', type: 'switch', show: (v) => v.type === 'select' },
    { key: 'testUrl', label: '测速地址', placeholder: 'https://www.gstatic.com/generate_204', show: (v) => v.type === 'urltest' },
    { key: 'intervalSec', label: '测速间隔（秒）', type: 'number', min: 30, show: (v) => v.type === 'urltest' },
    { key: 'toleranceMs', label: '切换容差（毫秒）', type: 'number', min: 0, show: (v) => v.type === 'urltest' },
  ];
}

async function editGroup(cfg, group, onSaved) {
  const initial = group ? structuredClone(group) : { name: '', type: 'select', nodes: [], groups: [], subscriptions: [], includeAll: false, includeDirect: true, intervalSec: 300, toleranceMs: 50 };
  const f = form(groupFields(cfg, group), initial);
  await modal(group ? '编辑代理组' : '添加代理组', f.el, [
    { label: '取消', value: null },
    { label: '保存', cls: 'primary', onclick: async () => {
      const g = structuredClone(f.values);
      g.name = String(g.name || '').trim();
      if (g.includeAll) { g.nodes = []; g.subscriptions = []; }
      if (g.type !== 'urltest') { delete g.testUrl; delete g.intervalSec; delete g.toleranceMs; }
      try {
        if (group) await put('/api/v1/groups/' + encodeURIComponent(group.id), g);
        else await post('/api/v1/groups', g);
      } catch (e) {
        toast(errorText(e), 'err');
        return false;
      }
      toast('已保存', 'ok');
      onSaved();
      return true;
    } },
  ]);
}

export default function mount(view, ctx) {
  const runtime = h('div', null, loading());
  const nodesBox = h('div', null, loading());
  const groupsBox = h('div', null, loading());
  const search = h('input', { type: 'search', placeholder: '搜索节点', oninput: () => renderNodes() });
  const typeFilter = h('select', { 'aria-label': '节点类型', onchange: () => renderNodes() },
    h('option', { value: '' }, '全部类型'), NODE_TYPES.map(([value, label]) => h('option', { value }, label)));
  const count = h('div', { class: 'result-count', role: 'status' });
  let cfg = { nodes: [], groups: [], subscriptions: [] };
  let delays = {};
  let alive = true;
  const groupOpen = new Map();
  const selecting = new Set();

  view.append(
    card('代理组', toolBtn('刷新', 'refreshCw', () => loadRuntime(), 'ghost'), runtime),
    card('节点', [btn('导入', () => importNodes(loadAll), 'small'), btn('添加', () => editNode(cfg.nodes, null, loadAll), 'small primary')],
      h('div', { class: 'toolbar' }, searchField(search), typeFilter), count, nodesBox),
    card('代理组设置', btn('添加', () => editGroup(cfg, null, loadAll), 'small primary'), groupsBox),
  );

  async function testDelay(ids) {
    if (!ids.length) return;
    toast(`正在测速 ${ids.length} 个节点…`);
    const r = await post('/api/v1/nodes/delay', { ids: ids.slice(0, 500), timeout: 5000 });
    if (!alive) return;
    for (const [id, res] of Object.entries(r.results || {})) delays[id] = res;
    renderNodes();
    await loadRuntime();
  }

  function delayText(id) {
    const d = delays[id];
    if (!d) return '未测速';
    return d.error ? '超时' : d.delay + ' ms';
  }

  async function loadRuntime() {
    const p = await get('/api/v1/proxies');
    if (!alive) return;
    for (const detail of runtime.querySelectorAll('details[data-group]')) groupOpen.set(detail.dataset.group, detail.open);
    const focused = document.activeElement?.dataset.member;
    const focusedGroup = document.activeElement?.dataset.group;
    clear(runtime);
    if (!p.groups.length) {
      runtime.append(empty('没有代理组'));
      return;
    }
    if (!p.running) runtime.append(h('p', { class: 'small muted' }, '核心未运行：显示的是配置中的选择，启动后可实时切换。'));
    for (const [index, g] of p.groups.entries()) {
      const nodeIds = g.members.filter((m) => m.ref.startsWith('node:')).map((m) => m.ref.slice(5));
      const grid = h('div', { class: 'members', role: 'group', 'aria-label': g.name });
      for (const m of g.members) {
        const id = m.ref.startsWith('node:') ? m.ref.slice(5) : '';
        const ms = (id && delays[id] && !delays[id].error) ? delays[id].delay : m.delay;
        const timeout = id && delays[id]?.error;
        const label = timeout ? '超时' : ms ? ms + ' ms' : '未测速';
        grid.append(h('button', {
          type: 'button', class: 'member' + (g.now === m.ref ? ' on' : ''), title: m.name, 'aria-pressed': g.now === m.ref,
          disabled: g.type !== 'select', dataset: { member: m.ref, group: g.id },
          onclick: g.type === 'select' ? async () => {
            if (selecting.has(g.id)) return;
            selecting.add(g.id);
            grid.setAttribute('aria-busy', 'true');
            try {
              await post('/api/v1/groups/' + encodeURIComponent(g.id) + '/select', { member: m.ref });
              await loadRuntime();
            } catch (e) { toast(errorText(e), 'err'); }
            finally { selecting.delete(g.id); grid.removeAttribute('aria-busy'); }
          } : null,
        }, h('span', { class: 'member-head' }, h('span', { class: 'name' }, m.name || m.ref), icon('circleCheck', 'selected-icon')),
        h('span', { class: 'meta' }, h('span', null, m.ref.startsWith('group:') ? '代理组' : m.type || '直连'), h('span', { class: timeout ? 'delay-bad' : delayClass(ms) }, label))));
      }
      runtime.append(h('details', { class: 'runtime-group', open: groupOpen.has(g.id) ? groupOpen.get(g.id) : index === 0, dataset: { group: g.id } },
        h('summary', null, icon('chevronRight'),
          h('div', { class: 'row grow' }, h('b', { class: 'break' }, g.name), chip(g.type === 'select' ? '手动' : '自动'),
            h('span', { class: 'group-selection ellipsis' }, (g.members.find((m) => m.ref === g.now) || {}).name || g.now || '未选择'))),
        h('div', { class: 'group-tools' }, h('span', { class: 'small muted' }, `${g.members.length} 个成员`),
          nodeIds.length ? toolBtn('测速', 'gauge', () => testDelay(nodeIds), 'ghost') : null),
        g.members.length ? grid : h('div', { class: 'small muted' }, '没有成员（将使用直连）')));
    }
    if (focused) [...runtime.querySelectorAll('[data-member]')].find((el) => el.dataset.member === focused && el.dataset.group === focusedGroup)?.focus({ preventScroll: true });
  }

  function renderNodes() {
    clear(nodesBox);
    const kw = search.value.trim().toLowerCase();
    const list = cfg.nodes.filter((n) => (!typeFilter.value || typeFilter.value === n.type)
      && (!kw || n.name.toLowerCase().includes(kw) || n.server.toLowerCase().includes(kw)));
    count.textContent = list.length === cfg.nodes.length ? `共 ${cfg.nodes.length} 个节点` : `匹配 ${list.length} / ${cfg.nodes.length} 个节点`;
    if (!list.length) {
      nodesBox.append(empty(cfg.nodes.length ? '没有匹配的节点' : '还没有节点', 'network'));
      return;
    }
    const ul = h('ul', { class: 'list' });
    for (const n of list.slice(0, 500)) {
      ul.append(h('li', { class: 'node-row' },
        h('div', { class: 'grow node-main' },
          h('div', { class: 'title ellipsis', title: n.name }, n.name),
          h('div', { class: 'sub ellipsis' }, `${typeLabel(n.type)} · ${n.server}:${n.port}` + (n.subscriptionName ? ` · ${n.subscriptionName}` : '') + (n.upstream ? ' · 链式' : ''))),
        h('span', { class: 'node-delay ' + (delays[n.id]?.error ? 'delay-bad' : delayClass(delays[n.id]?.delay)) }, delayText(n.id)),
        h('div', { class: 'row-actions' },
        toolBtn('测速', 'gauge', () => testDelay([n.id])),
        toolBtn('编辑', 'pencil', () => editNode(cfg.nodes, n, loadAll)),
        toolBtn('复制', 'copy', async () => { await post('/api/v1/nodes/' + encodeURIComponent(n.id) + '/copy'); toast('已复制', 'ok'); await loadAll(); }),
        toolBtn('删除', 'trash2', async () => {
          if (!(await confirmDialog(`删除节点“${n.name}”？`, '删除', true))) return;
          const r = await del('/api/v1/nodes/' + encodeURIComponent(n.id));
          for (const note of r.notes || []) toast(note);
          await loadAll();
        }, 'danger'))));
    }
    if (list.length > 500) ul.append(h('li', { class: 'muted small' }, `仅显示前 500 个，共 ${list.length} 个，请使用搜索`));
    nodesBox.append(ul);
  }

  function renderGroups() {
    clear(groupsBox);
    const ul = h('ul', { class: 'list' });
    const names = Object.fromEntries(cfg.groups.map((g) => [g.id, g.name]));
    for (const g of cfg.groups) {
      const parts = [];
      if (g.includeAll) parts.push('全部节点');
      if (g.subscriptions.length) parts.push(`${g.subscriptions.length} 个订阅`);
      if (g.nodes.length) parts.push(`${g.nodes.length} 个节点`);
      if (g.groups.length) parts.push('组：' + g.groups.map((x) => names[x] || x).join('、'));
      if (g.filter) parts.push('包含 /' + g.filter + '/');
      ul.append(h('li', null,
        h('div', { class: 'grow' }, h('div', { class: 'title' }, g.name, ' ', chip(g.type === 'select' ? '手动' : '自动')),
          h('div', { class: 'sub' }, `${(cfg.members[g.id] || []).length} 个成员 · ` + (parts.join(' · ') || '无成员'))),
        h('div', { class: 'row-actions' },
        toolBtn('编辑', 'pencil', () => editGroup(cfg, g, loadAll)),
        toolBtn('删除', 'trash2', async () => {
          if (!(await confirmDialog(`删除代理组“${g.name}”？`, '删除', true))) return;
          await del('/api/v1/groups/' + encodeURIComponent(g.id));
          await loadAll();
        }, 'danger'))));
    }
    groupsBox.append(cfg.groups.length ? ul : empty('没有代理组'));
  }

  async function loadAll() {
    const [n, g, s] = await Promise.all([get('/api/v1/nodes'), get('/api/v1/groups'), get('/api/v1/subscriptions')]);
    if (!alive) return;
    cfg = { nodes: n.nodes, groups: g.groups, members: g.members || {}, subscriptions: s.subscriptions };
    renderNodes();
    renderGroups();
    await loadRuntime();
    ctx.refreshStatus().catch(() => {});
  }

  loadAll().catch((e) => {
    if (!alive) return;
    for (const box of [runtime, nodesBox, groupsBox]) clear(box).append(empty(errorText(e)));
  });
  return () => { alive = false; };
}
