import { get, del } from '../api.js?v=__V__';
import { h, clear, card, btn, toolBtn, searchField, loading, toast, confirmDialog, errorText, empty, fmtBytes, poller } from '../ui.js?v=__V__';

export default function mount(view) {
  const box = h('div', null, loading());
  const search = h('input', { type: 'search', placeholder: '按域名、应用、规则或出口筛选', oninput: () => render() });
  let last = null;
  let alive = true;
  view.append(card('活动连接', btn('全部断开', async () => {
    if (!(await confirmDialog('断开全部活动连接？', '全部断开', true))) return;
    await del('/api/v1/connections');
    toast('已断开全部连接', 'ok');
    await load();
  }, 'small danger'), searchField(search), box));

  function render() {
    clear(box);
    if (!last) return;
    if (!last.running) {
      box.append(empty('核心未运行'));
      return;
    }
    const kw = search.value.trim().toLowerCase();
    const list = last.connections.filter((c) => !kw || [c.host, c.dest, c.process, c.rule, (c.chains || []).join(' ')].join(' ').toLowerCase().includes(kw));
    list.sort((a, b) => (b.download + b.upload) - (a.download + a.upload));
    box.append(h('div', { class: 'connection-totals' },
      h('span', null, `${kw ? `匹配 ${list.length} / ` : '共 '}${last.connections.length} 个连接`),
      h('span', null, `下载 ${fmtBytes(last.downloadTotal)}`), h('span', null, `上传 ${fmtBytes(last.uploadTotal)}`)));
    if (!list.length) {
      box.append(empty('没有连接'));
      return;
    }
    const tbody = h('tbody');
    for (const c of list.slice(0, 300)) {
      tbody.append(h('tr', null,
        h('td', { class: 'break' }, h('div', null, c.host || c.dest), h('div', { class: 'muted' }, `${c.network} ${c.host ? c.dest : ''}`),
          c.process ? h('div', { class: 'muted' }, `应用 ${c.process}`) : null),
        h('td', { class: 'break' }, h('div', null, (c.chains || []).slice().reverse().join(' → ')), h('div', { class: 'muted' }, c.rule)),
        h('td', null, h('span', null, `↓ ${fmtBytes(c.download)}`), h('br'), h('span', null, `↑ ${fmtBytes(c.upload)}`)),
        h('td', null, toolBtn('断开', 'unplug', async () => {
          await del('/api/v1/connections/' + encodeURIComponent(c.id));
          await load();
        }, 'ghost'))));
    }
    box.append(h('div', { class: 'scroll-x' }, h('table', { class: 'table' },
      h('thead', null, h('tr', null, h('th', null, '目标'), h('th', null, '出口 / 规则'), h('th', null, '流量'), h('th', { 'aria-label': '操作' }))), tbody)));
  }

  async function load() {
    const response = await get('/api/v1/connections');
    if (!alive) return;
    last = response;
    render();
  }
  const p = poller(() => load().catch((e) => { if (alive) clear(box).append(empty(errorText(e))); }), 2500);
  return () => { alive = false; p.stop(); };
}
