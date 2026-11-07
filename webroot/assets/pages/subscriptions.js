import { get, post, put, del, waitTask } from '../api.js?v=__V__';
import { h, clear, card, btn, toolBtn, loading, chip, toast, modal, form, confirmDialog, errorText, empty, fmtBytes, fmtAgo, fmtTime, progressDialog } from '../ui.js?v=__V__';

function subFields(isNew) {
  return [
    { key: 'name', label: '名称' },
    { key: 'url', label: '订阅地址', type: 'url', wide: true, placeholder: isNew ? 'https://…' : '留空表示不修改', hint: '地址不会再次显示。HTTP 地址可能泄露凭据，建议使用 HTTPS。' },
    { key: 'userAgent', label: 'User-Agent', placeholder: 'clash.meta（默认）' },
    { key: 'viaProxy', label: '通过代理更新', type: 'switch', hint: '需要核心正在运行；关闭时先直连，失败再尝试代理' },
    { key: 'autoUpdateHours', label: '自动更新间隔（小时，0 为不自动更新）', type: 'number', min: 0, max: 720 },
    { key: 'filter', label: '只保留名称匹配（正则）', placeholder: '例如 香港|日本' },
    { key: 'excludeFilter', label: '排除名称匹配（正则）', placeholder: '例如 剩余|到期|官网' },
  ];
}

async function editSub(sub, onSaved) {
  const initial = sub ? { ...structuredClone(sub), url: '' } : { name: '', url: '', userAgent: '', viaProxy: false, autoUpdateHours: 24, filter: '', excludeFilter: '' };
  const f = form(subFields(!sub), initial);
  let createdId = '';
  let createdName = '';
  await modal(sub ? '编辑订阅' : '添加订阅', f.el, [
    { label: '取消', value: null },
    { label: '保存', cls: 'primary', onclick: async () => {
      const v = f.values;
      const s = { name: String(v.name || '').trim(), userAgent: v.userAgent || '', viaProxy: !!v.viaProxy, autoUpdateHours: Number(v.autoUpdateHours) || 0, filter: v.filter || '', excludeFilter: v.excludeFilter || '' };
      const body = { subscription: s };
      if (String(v.url || '').trim()) body.url = String(v.url).trim();
      try {
        if (sub) await put('/api/v1/subscriptions/' + encodeURIComponent(sub.id), body);
        else {
          createdId = (await post('/api/v1/subscriptions', body)).id;
          createdName = s.name;
        }
      } catch (e) {
        toast(errorText(e), 'err');
        return false;
      }
      return true;
    } },
  ]);
  if (createdId) await refresh({ id: createdId, name: createdName }, onSaved);
  else onSaved();
}

function usageLine(u) {
  if (!u) return null;
  const used = (u.upload || 0) + (u.download || 0);
  const parts = [];
  if (u.total) parts.push(`已用 ${fmtBytes(used)} / ${fmtBytes(u.total)}`);
  else if (used) parts.push(`已用 ${fmtBytes(used)}`);
  if (u.expire) {
    const d = new Date(u.expire * 1000);
    parts.push('到期 ' + (Number.isFinite(d.getTime()) ? fmtTime(d.toISOString()) : '未知'));
  }
  const pct = u.total ? Math.min(100, Math.round((used / u.total) * 100)) : 0;
  return h('div', { class: 'subscription-usage' },
    h('div', { class: 'small muted' }, parts.join(' · ')),
    u.total ? h('div', { class: 'progress', role: 'progressbar', 'aria-label': '订阅已用流量', 'aria-valuenow': pct, 'aria-valuemin': 0, 'aria-valuemax': 100, style: { marginTop: '6px' } }, h('i', { style: { width: pct + '%' } })) : null);
}

function nameList(title, names) {
  if (!names.length) return null;
  return h('details', null, h('summary', null, `${title}（${names.length}）`),
    h('div', { class: 'small break' }, names.slice(0, 300).join('、') + (names.length > 300 ? ' …' : '')));
}

// refresh downloads a subscription, shows the difference and commits on confirmation.
async function refresh(sub, onDone) {
  const pd = progressDialog('正在更新订阅');
  let preview;
  try {
    const task = await post('/api/v1/subscriptions/' + encodeURIComponent(sub.id) + '/refresh');
    preview = await waitTask(task, (t) => pd.update(t), { signal: pd.signal });
  } catch (e) {
    pd.close();
    toast('更新失败：' + errorText(e), 'err');
    onDone();
    return;
  }
  pd.close();
  const d = preview.diff;
  const body = h('div', null,
    h('p', null, `识别格式：${preview.format}，共 ${preview.count} 个节点。`),
    h('p', null, `新增 ${d.added.length}，删除 ${d.removed.length}，变更 ${d.changed.length}，未变 ${d.unchanged}。`),
    nameList('新增', d.added), nameList('删除', d.removed), nameList('变更', d.changed),
    preview.issues.length ? nameList('未能识别的条目', preview.issues.map((i) => (i.name ? i.name + '：' : '') + i.message)) : null,
    usageLine(preview.usage));
  const ok = await modal('确认更新「' + sub.name + '」', body, [
    { label: '取消', value: false },
    { label: '应用', value: true, cls: 'primary' },
  ]);
  if (ok) {
    try {
      const r = await post('/api/v1/subscriptions/' + encodeURIComponent(sub.id) + '/commit', { previewId: preview.previewId });
      for (const n of r.notes || []) toast(n);
      toast('订阅已更新', 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
  onDone();
}

export default function mount(view, ctx) {
  const box = h('div', null, loading());
  let alive = true;
  view.append(card('订阅', [
    btn('全部更新', async () => {
      const pd = progressDialog('正在更新全部订阅');
      try {
        const task = await post('/api/v1/subscriptions/update-all');
        const r = await waitTask(task, (t) => pd.update(t), { signal: pd.signal });
        pd.close();
        toast(r.failed ? `${r.failed} 个订阅更新失败` : '全部订阅已更新', r.failed ? 'err' : 'ok');
      } catch (e) {
        pd.close();
        throw e;
      }
      await load();
    }, 'small'),
    btn('添加', () => editSub(null, load), 'small primary'),
  ], box));

  async function load() {
    const r = await get('/api/v1/subscriptions');
    if (!alive) return;
    clear(box);
    if (!r.subscriptions.length) {
      box.append(empty('还没有订阅'));
      return;
    }
    const ul = h('ul', { class: 'list' });
    for (const s of r.subscriptions) {
      ul.append(h('li', { class: 'subscription-row', style: { alignItems: 'flex-start' } },
        h('div', { class: 'grow' },
          h('div', { class: 'title' }, s.name, ' ', s.viaProxy ? chip('经代理') : null, ' ', s.autoUpdateHours ? chip(`每 ${s.autoUpdateHours} 小时`) : null),
          h('div', { class: 'sub' }, `${s.urlHost || '—'} · ${s.nodeCount} 个节点 · 更新于 ${fmtAgo(s.updatedAt)}`),
          s.lastError ? h('div', { class: 'small', style: { color: 'var(--err)' } }, '上次失败：' + s.lastError) : null,
          usageLine(s.usage)),
        h('div', { class: 'row-actions' },
          toolBtn('更新', 'refreshCw', () => refresh(s, load)),
          toolBtn('编辑', 'pencil', () => editSub(s, load)),
          toolBtn('删除', 'trash2', async () => {
            if (!(await confirmDialog(`删除订阅“${s.name}”及其 ${s.nodeCount} 个节点？`, '删除', true))) return;
            const res = await del('/api/v1/subscriptions/' + encodeURIComponent(s.id));
            for (const n of res.notes || []) toast(n);
            await load();
          }, 'danger'))));
    }
    box.append(ul);
    ctx.refreshStatus().catch(() => {});
  }
  load().catch((e) => { if (alive) clear(box).append(empty(errorText(e))); });
  return () => { alive = false; };
}
