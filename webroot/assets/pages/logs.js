import { get, del, q } from '../api.js?v=__V__';
import { h, clear, card, toolBtn, segmented, toast, confirmDialog, errorText, poller } from '../ui.js?v=__V__';

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

export default function mount(view) {
  let source = 'daemon';
  let after = 0;
  let minLevel = 'info';
  let follow = true;
  let alive = true;
  let generation = 0;
  const pending = new Set();
  const box = h('div', { class: 'logbox', tabindex: 0, 'aria-label': '日志内容' });
  const status = h('div', { class: 'small muted', role: 'status' }, '正在读取…');
  const seg = segmented([['daemon', '管理服务'], ['core', '核心']], source, async (value) => {
    source = value;
    await reset();
  }, '日志来源');
  const levelSel = h('select', { 'aria-label': '日志级别', onchange: () => { minLevel = levelSel.value; reset(); } },
    [['debug', '全部级别'], ['info', '信息及以上'], ['warn', '警告及以上'], ['error', '仅错误']].map(([v, label]) => h('option', { value: v }, label)));
  levelSel.value = minLevel;
  const followCb = h('input', { type: 'checkbox', checked: true, onchange: () => {
    follow = followCb.checked;
    if (follow) box.scrollTop = box.scrollHeight;
  } });

  function reset() {
    generation++;
    after = 0;
    clear(box);
    return load();
  }

  async function load() {
    const requestGeneration = generation;
    if (pending.has(requestGeneration)) return;
    pending.add(requestGeneration);
    try {
      const r = await get(q('/api/v1/logs', { source, after, limit: 1000 }));
      if (!alive || requestGeneration !== generation) return;
      if (r.last < after) { after = 0; clear(box); }
      const frag = document.createDocumentFragment();
      for (const line of r.lines) {
        if ((LEVELS[line.level] ?? 1) < LEVELS[minLevel]) continue;
        const time = new Date(line.time);
        const timestamp = isNaN(time) ? '' : time.toTimeString().slice(0, 8);
        frag.append(h('div', { class: 'l-' + line.level }, h('span', { class: 'log-time' }, timestamp), line.text));
      }
      box.querySelector('.log-empty')?.remove();
      box.append(frag);
      while (box.childElementCount > 3000) box.firstElementChild.remove();
      const count = box.childElementCount;
      status.textContent = `${count} 条日志`;
      if (!count) box.append(h('div', { class: 'log-empty' }, '暂无符合条件的日志'));
      after = r.last;
      if (follow && r.lines.length) box.scrollTop = box.scrollHeight;
    } catch (e) {
      if (alive && requestGeneration === generation) status.textContent = errorText(e);
    } finally {
      pending.delete(requestGeneration);
    }
  }

  view.append(card('运行日志', seg.el,
    h('div', { class: 'toolbar' }, levelSel, h('label', { class: 'row small' }, followCb, '自动滚动'),
      h('span', { class: 'grow' }),
      toolBtn('清空', 'trash2', async () => {
        if (!(await confirmDialog('清空当前日志？', '清空', true))) return;
        await del(q('/api/v1/logs', { source }));
        toast('已清空', 'ok');
        await reset();
      }, 'ghost')),
    box, status));
  const poll = poller(load, 1500);
  return () => { alive = false; generation++; poll.stop(); };
}
