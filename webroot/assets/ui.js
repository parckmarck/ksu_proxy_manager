// Small DOM helpers. All dynamic text is inserted as text nodes; nothing here
// interprets data as HTML.
import { icon } from './icons.js?v=__V__';
export { icon };

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || (v === false && !k.startsWith('aria-'))) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true && !k.startsWith('aria-') ? '' : String(v));
    }
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const c of [children].flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function card(title, actions, ...body) {
  return h('section', { class: 'section' },
    title || actions ? h('header', null, title ? h('h2', null, title) : h('span'), actions ? h('div', { class: 'row' }, actions) : null) : null,
    body);
}

const ACTION_ICONS = {
  '添加': 'plus', '保存': 'save', '导入': 'upload', '更新': 'refreshCw', '全部更新': 'refreshCw',
  '启动核心': 'power', '停止': 'square', '重启核心': 'rotateCcw', '立即应用': 'check',
  '应用配置并重启': 'rotateCcw', '应用': 'check', '重试': 'refreshCw', '删除': 'trash2',
  '重新连接': 'refreshCw',
  '恢复': 'archiveRestore', '下载安装': 'download', '获取版本列表': 'download',
  '生成密钥': 'keyRound', '重新生成密钥': 'keyRound', '查看诊断信息': 'stethoscope',
  '导出（不含凭据）': 'download', '导出（含凭据）': 'download', '全部断开': 'unplug',
  '下载缺失': 'download', '按路径导入': 'upload', '恢复默认排除列表': 'rotateCcw',
};

export function btn(label, onclick, cls = '', iconName = ACTION_ICONS[label]) {
  const b = h('button', { class: 'btn ' + cls, type: 'button' },
    iconName ? icon(iconName) : null, h('span', { class: 'btn-label' }, label));
  b.addEventListener('click', async (ev) => {
    if (b.disabled) return;
    b.disabled = true;
    b.classList.add('busy');
    b.setAttribute('aria-busy', 'true');
    try {
      await onclick(ev);
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      b.classList.remove('busy');
      b.removeAttribute('aria-busy');
      b.disabled = b.dataset.blocked === 'true';
    }
  });
  return b;
}

export function toolBtn(label, iconName, onclick, cls = '') {
  const b = btn(label, onclick, 'icon-only ' + cls, iconName);
  b.setAttribute('aria-label', label);
  b.setAttribute('data-tooltip', label);
  b.title = label;
  return b;
}

export function setDisabled(button, disabled) {
  button.dataset.blocked = String(disabled);
  button.disabled = disabled || button.getAttribute('aria-busy') === 'true';
  return button;
}

export function searchField(input) {
  input.setAttribute('aria-label', input.getAttribute('aria-label') || input.placeholder || '搜索');
  input.autocomplete = 'off';
  return h('div', { class: 'search-field' }, icon('search'), input);
}

let controlID = 0;
export function segmented(options, value, onChange, label) {
  const name = 'seg-' + ++controlID;
  const inputs = [];
  let current = value;
  const el = h('div', { class: 'seg', role: 'group', 'aria-label': label });
  const setValue = (next) => {
    current = next;
    for (const input of inputs) input.checked = input.value === next;
  };
  const setDisabled = (disabled) => { for (const input of inputs) input.disabled = disabled; };
  for (const [v, text] of options) {
    const input = h('input', { type: 'radio', name, value: v, checked: v === value, onchange: async () => {
      if (!input.checked) return;
      const previous = current;
      setDisabled(true);
      try {
        await onChange(v);
        setValue(v);
      } catch (e) {
        setValue(previous);
        toast(errorText(e), 'err');
      } finally {
        setDisabled(false);
      }
    } });
    inputs.push(input);
    el.append(h('label', null, input, h('span', null, text)));
  }
  return { el, setValue, setDisabled };
}

export function chip(text, kind = '') {
  return h('span', { class: 'chip ' + kind }, text);
}

export function empty(text, iconName = 'inbox') {
  return h('div', { class: 'empty' }, icon(iconName), h('span', null, text));
}

export function loading(text = '正在加载…') {
  const el = empty(text, 'loaderCircle');
  el.classList.add('loading');
  el.setAttribute('role', 'status');
  return el;
}

const FIELD_NAMES = {
  name: '名称', server: '服务器', port: '端口', cipher: '加密方式', password: '密码', uuid: 'UUID', url: '地址',
  mtu: 'MTU', filter: '包含过滤', excludeFilter: '排除过滤', testUrl: '测速地址', values: '规则值', target: '目标',
  final: '兜底出口', direct: '直连 DNS', proxy: '代理 DNS', packages: '应用', ports: '端口跳跃', sni: 'SNI',
};

export function fieldLabel(path) {
  const last = String(path).split('.').pop().replace(/\[\d+\]$/, '');
  return FIELD_NAMES[last] || path;
}

export function errorText(e) {
  if (!e) return '未知错误';
  if (e.field) return `${e.message}（${fieldLabel(e.field)}）`;
  return e.message || String(e);
}

export function toast(msg, kind = '') {
  const box = document.getElementById('toasts');
  if (!box) return;
  while (box.childElementCount >= 2) box.firstElementChild.remove();
  const t = h('div', { class: 'toast ' + kind, role: kind === 'err' ? 'alert' : 'status' },
    h('span', { class: 'grow' }, msg), toolBtn('关闭提示', 'x', () => t.remove(), 'ghost'));
  box.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 6000 : 3000);
}

const dialogStack = [];
let inertBackground = [];

function openDialog(title, body, dismiss, compact = false) {
  const returnFocus = document.activeElement;
  const titleID = 'dialog-' + ++controlID;
  const overlay = h('div', { class: 'overlay' });
  const closeButton = toolBtn('关闭', 'x', dismiss, 'ghost');
  const dialog = h('div', { class: 'dialog' + (compact ? ' compact' : ''), role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleID, tabindex: -1 },
    h('header', null, h('h2', { class: 'dialog-title', id: titleID }, title), closeButton),
    h('div', { class: 'body' }, body));
  overlay.append(dialog);
  if (!dialogStack.length) {
    inertBackground = [...document.body.children].filter((el) => !['SCRIPT', 'NOSCRIPT'].includes(el.tagName) && el.id !== 'toasts')
      .map((el) => [el, el.hasAttribute('inert')]);
    for (const [el] of inertBackground) el.setAttribute('inert', '');
    document.body.classList.add('modal-open');
  } else {
    dialogStack[dialogStack.length - 1].setAttribute('inert', '');
  }
  dialogStack.push(overlay);

  const onKey = (e) => {
    if (dialogStack[dialogStack.length - 1] !== overlay) return;
    if (e.key === 'Escape') { e.preventDefault(); dismiss(); }
    if (e.key !== 'Tab') return;
    const focusable = [...dialog.querySelectorAll('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]')]
      .filter((el) => !el.closest('[hidden], [inert]') && el.type !== 'hidden' && getComputedStyle(el).display !== 'none');
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (!first) { e.preventDefault(); dialog.focus(); return; }
    if (e.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
      e.preventDefault(); last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
      e.preventDefault(); first.focus();
    }
  };
  const viewport = window.visualViewport;
  const fit = () => {
    if (!viewport) return;
    overlay.style.top = viewport.offsetTop + 'px';
    overlay.style.height = viewport.height + 'px';
    overlay.style.bottom = 'auto';
  };
  viewport?.addEventListener('resize', fit);
  viewport?.addEventListener('scroll', fit);
  fit();
  overlay.addEventListener('click', (e) => { if (e.target === overlay) dismiss(); });
  document.addEventListener('keydown', onKey);
  document.body.append(overlay);
  dialog.focus({ preventScroll: true });

  let closed = false;
  return {
    dialog,
    close() {
      if (closed) return;
      closed = true;
      overlay.remove();
      dialogStack.splice(dialogStack.indexOf(overlay), 1);
      document.removeEventListener('keydown', onKey);
      viewport?.removeEventListener('resize', fit);
      viewport?.removeEventListener('scroll', fit);
      if (dialogStack.length) dialogStack[dialogStack.length - 1].removeAttribute('inert');
      else {
        for (const [el, wasInert] of inertBackground) if (!wasInert) el.removeAttribute('inert');
        inertBackground = [];
        document.body.classList.remove('modal-open');
      }
      const target = returnFocus?.isConnected && !returnFocus.disabled && !returnFocus.closest('[inert]')
        ? returnFocus : dialogStack[dialogStack.length - 1]?.querySelector('.dialog') || document.getElementById('page-title');
      target?.focus({ preventScroll: true });
    },
  };
}

// Returning false from an action keeps the dialog open for validation feedback.
export function modal(title, body, buttons = [{ label: '关闭', value: null }], options = {}) {
  return new Promise((resolve) => {
    let busy = false;
    const close = (value) => { shell.close(); resolve(value); };
    const shell = openDialog(title, body, () => { if (!busy) close(null); }, options.compact);
    const footer = h('footer', { hidden: !buttons.length });
    for (const b of buttons) {
      footer.append(btn(b.label, async () => {
        if (busy) return;
        busy = true;
        shell.dialog.setAttribute('aria-busy', 'true');
        try {
          if (b.onclick && await b.onclick() === false) return;
          close(b.value);
        } finally {
          busy = false;
          shell.dialog.removeAttribute('aria-busy');
        }
      }, b.cls || ''));
    }
    shell.dialog.append(footer);
    options.onOpen?.({ close });
  });
}

export async function confirmDialog(text, okLabel = '确定', danger = false) {
  const v = await modal('确认', h('p', null, text), [
    { label: '取消', value: false },
    { label: okLabel, value: true, cls: danger ? 'danger' : 'primary' },
  ]);
  return v === true;
}

// progressDialog shows task progress; returns {update(task), close(), signal}.
// The cancel button aborts `signal`, which waitTask turns into a task cancel.
export function progressDialog(title) {
  const bar = h('i');
  const progress = h('div', { class: 'progress indeterminate', role: 'progressbar', 'aria-label': title, 'aria-valuemin': 0, 'aria-valuemax': 100 }, bar);
  const msg = h('div', { class: 'small muted', role: 'status' }, '处理中…');
  const ctl = new AbortController();
  const abort = () => { ctl.abort(); setDisabled(cancel, true); msg.textContent = '正在取消…'; };
  const cancel = btn('取消', abort, 'small');
  const shell = openDialog(title, h('div', null, progress, msg), abort, true);
  shell.dialog.append(h('footer', null, cancel));
  return {
    signal: ctl.signal,
    update(t) {
      if (!t) return;
      msg.textContent = t.message || '处理中…';
      if (t.total > 0) {
        const percent = Math.max(0, Math.min(100, Math.round((t.done / t.total) * 100)));
        progress.classList.remove('indeterminate');
        progress.setAttribute('aria-valuenow', percent);
        bar.style.width = percent + '%';
        msg.textContent += `（${fmtBytes(t.done)} / ${fmtBytes(t.total)}）`;
      }
    },
    close() { shell.close(); },
  };
}

export function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i === 0 || n >= 100 ? 0 : 1) + ' ' + u[i];
}

export const fmtRate = (n) => fmtBytes(n) + '/s';

export function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function fmtAgo(iso) {
  if (!iso) return '从未';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return '刚刚';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return Math.floor(s / 86400) + ' 天前';
}

export function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} 天 ${hh} 小时`;
  if (hh) return `${hh} 小时 ${m} 分`;
  return `${m} 分 ${sec % 60} 秒`;
}

export function delayClass(ms) {
  if (!ms) return '';
  return ms < 300 ? 'delay-good' : ms < 800 ? 'delay-mid' : 'delay-bad';
}

// ---- forms ----

export function getPath(obj, path) {
  return String(path).split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

export function setPath(obj, path, value) {
  const keys = String(path).split('.');
  let o = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (o[keys[i]] == null || typeof o[keys[i]] !== 'object') o[keys[i]] = {};
    o = o[keys[i]];
  }
  o[keys[keys.length - 1]] = value;
}

export const lines = (text) => String(text || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

function control(f, value, onChange) {
  const id = 'f-' + Math.random().toString(36).slice(2);
  switch (f.type) {
    case 'switch': {
      const input = h('input', { type: 'checkbox', id, checked: !!value, onchange: () => onChange(input.checked) });
      return { el: h('label', { class: 'switch' }, input, h('span')), input };
    }
    case 'select': {
      const input = h('select', { id, onchange: () => onChange(input.value) },
        (typeof f.options === 'function' ? f.options() : f.options).map(([v, label]) => h('option', { value: v }, label)));
      input.value = value ?? '';
      return { el: input, input };
    }
    case 'number': {
      const input = h('input', { type: 'number', id, value: value ?? '', min: f.min, max: f.max, placeholder: f.placeholder,
        oninput: () => onChange(input.value === '' ? 0 : Number(input.value)) });
      return { el: input, input };
    }
    case 'textarea':
    case 'lines': {
      const v = f.type === 'lines' ? (value || []).join('\n') : value ?? '';
      const input = h('textarea', { id, rows: f.rows || 4, placeholder: f.placeholder, spellcheck: 'false',
        oninput: () => onChange(f.type === 'lines' ? lines(input.value) : input.value) });
      input.value = v;
      return { el: input, input };
    }
    case 'checks': {
      const selected = new Set(value || []);
      const opts = typeof f.options === 'function' ? f.options() : f.options;
      const box = h('div', { class: 'checks', id, role: 'group', 'aria-label': f.label }, opts.length ? opts.map(([v, label]) => {
        const cb = h('input', { type: 'checkbox', checked: selected.has(v), onchange: () => {
          if (cb.checked) selected.add(v); else selected.delete(v);
          onChange(opts.map(([x]) => x).filter((x) => selected.has(x)));
        } });
        return h('label', null, cb, h('span', { class: 'ellipsis' }, label));
      }) : h('span', { class: 'muted small' }, '无可选项'));
      return { el: box, input: box };
    }
    case 'password': {
      const input = h('input', { type: 'password', id, value: value ?? '', placeholder: f.placeholder, autocomplete: 'off', spellcheck: 'false',
        oninput: () => onChange(input.value) });
      const toggle = toolBtn('显示密码', 'eye', () => {
        const visible = input.type === 'password';
        input.type = visible ? 'text' : 'password';
        const label = visible ? '隐藏密码' : '显示密码';
        toggle.setAttribute('aria-label', label);
        toggle.setAttribute('data-tooltip', label);
        toggle.setAttribute('aria-pressed', String(visible));
        toggle.title = label;
        toggle.querySelector('.btn-label').textContent = label;
        toggle.querySelector('.icon').replaceWith(icon(visible ? 'eyeOff' : 'eye'));
      }, 'ghost');
      toggle.setAttribute('aria-controls', id);
      toggle.setAttribute('aria-pressed', 'false');
      return { el: h('div', { class: 'password-field' }, input, toggle), input };
    }
    default: {
      const input = h('input', { type: f.type === 'url' ? 'url' : 'text', id, value: value ?? '', placeholder: f.placeholder, autocomplete: 'off', spellcheck: 'false',
        oninput: () => onChange(f.csv ? input.value.split(',').map((s) => s.trim()).filter(Boolean) : input.value) });
      if (f.csv) input.value = (value || []).join(', ');
      return { el: input, input };
    }
  }
}

// form renders fields bound to a deep copy of initial; read values from .values.
export function form(fields, initial) {
  const values = structuredClone(initial || {});
  const rows = [];
  for (const f of fields) {
    if (f.section) {
      rows.push({ f, row: h('h3', { class: 'form-section' }, f.section) });
      continue;
    }
    const c = control(f, getPath(values, f.key), (v) => {
      setPath(values, f.key, v);
      if (f.onchange) f.onchange(v, values);
      refresh();
    });
    const cls = (f.type === 'switch' ? 'field inline' : 'field') + (f.wide || ['lines', 'textarea', 'checks'].includes(f.type) ? ' wide' : '');
    const hintID = c.input.id + '-hint';
    if (f.hint) c.input.setAttribute('aria-describedby', hintID);
    const row = h('div', { class: cls },
      h('label', { class: 'label', for: c.input.id || undefined }, f.label),
      c.el,
      f.hint ? h('small', { class: 'hint', id: hintID }, f.hint) : null);
    rows.push({ f, row });
  }
  function refresh() {
    for (const { f, row } of rows) row.hidden = f.show ? !f.show(values) : false;
  }
  refresh();
  return { el: h('div', { class: 'form' }, rows.map((r) => r.row)), values, refresh };
}

// Poller runs fn every ms while the page is visible; stop() ends it.
export function poller(fn, ms) {
  let stopped = false;
  let timer = null;
  const tick = async () => {
    if (stopped) return;
    if (!document.hidden) {
      try { await fn(); } catch { /* shown elsewhere */ }
    }
    if (!stopped) timer = setTimeout(tick, ms);
  };
  tick();
  return { stop() { stopped = true; clearTimeout(timer); } };
}

export function download(name, text) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'application/json' })), download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

export function pickFile(accept = '.json,application/json') {
  return new Promise((resolve) => {
    const input = h('input', { type: 'file', accept, class: 'hidden', onchange: async () => {
      const f = input.files && input.files[0];
      input.remove();
      resolve(f ? await f.text() : null);
    } });
    document.body.append(input);
    input.click();
  });
}
