// WebUI tests: unit checks of the bridge encoding plus an end-to-end run of the
// real WebUI (jsdom) against the real daemon through a simulated `ksu.exec`.
//
// usage: node scripts/test-webui.mjs <module-dir-with-binaries>
//   NODE_PATH must contain jsdom. The module dir needs bin/arm64-v8a/{proxyctl,proxy-managerd}
//   built for the host and a webroot copy.
import assert from 'node:assert/strict';
import { exec as cpExec, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const { JSDOM, VirtualConsole } = require('jsdom');

const moduleDir = path.resolve(process.argv[2] || '');
assert.ok(fs.existsSync(path.join(moduleDir, 'webroot/index.html')), 'module dir with webroot required');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kpm-webui-'));
const PROXYCTL = '/data/adb/modules/ksu_proxy_manager/proxyctl';
const realCtl = path.join(moduleDir, 'bin/arm64-v8a/proxyctl');
const env = { ...process.env, KPM_MODULE_DIR: moduleDir, KPM_DATA_DIR: dataDir, KPM_IMPORT_ROOT: dataDir, KPM_PACKAGES_LIST: path.join(dataDir, 'packages.list') };

let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log('ok   ' + name);
  } catch (e) {
    failures++;
    console.log('FAIL ' + name + '\n     ' + (e && e.stack ? e.stack.split('\n').slice(0, 4).join('\n     ') : e));
    if (toastsErr.length) console.log('     error toasts: ' + JSON.stringify(toastsErr));
  }
  if (typeof document !== 'undefined') {
    for (const overlay of [...document.querySelectorAll('.overlay')].reverse()) {
      overlay.querySelector('header button')?.click();
    }
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, what, timeout = 15000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) { last = e; }
    await sleep(50);
  }
  throw new Error('timeout waiting for ' + what + (last ? ': ' + last.message : ''));
}

// ---- DOM environment ----
const html = fs.readFileSync(path.join(moduleDir, 'webroot/index.html'), 'utf8').replace(/<script[^>]*><\/script>/g, '');
const vc = new VirtualConsole();
const domErrors = [];
vc.on('jsdomError', (e) => {
  if (!/Not implemented/.test(e.message)) domErrors.push(e.message);
});
const dom = new JSDOM(html, { url: 'http://localhost/', pretendToBeVisual: true, virtualConsole: vc });
const w = dom.window;
for (const k of ['window', 'document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent', 'location', 'getComputedStyle', 'localStorage', 'sessionStorage', 'Blob', 'requestAnimationFrame']) {
  globalThis[k] = k === 'window' ? w : w[k];
}
globalThis.devicePixelRatio = 1;
w.scrollTo = () => {};
w.HTMLElement.prototype.scrollIntoView = function () {};
let systemDark = false;
const themeListeners = new Set();
w.matchMedia = () => ({ get matches() { return systemDark; }, addEventListener(_type, fn) { themeListeners.add(fn); } });

const toastsErr = [];
new w.MutationObserver((muts) => {
  for (const m of muts) for (const n of m.addedNodes) {
    if (n.classList && n.classList.contains('err')) toastsErr.push(n.textContent);
  }
}).observe(w.document.getElementById('toasts'), { childList: true });
const rejections = [];
process.on('unhandledRejection', (e) => rejections.push(String(e && e.stack || e)));

// Simulated KernelSU bridge running the real proxyctl.
const commands = [];
globalThis.ksu = {
  exec(cmd, _opts, cb) {
    commands.push(cmd);
    assert.ok(cmd.startsWith(PROXYCTL + ' '), 'unexpected command ' + cmd.slice(0, 80));
    assert.ok(cmd.length < 128 * 1024, 'command exceeds single-argument limit');
    cpExec(realCtl + cmd.slice(PROXYCTL.length), { env, maxBuffer: 64 << 20 }, (err, stdout, stderr) => {
      const fn = globalThis[cb];
      if (typeof fn === 'function') fn(err ? (err.code ?? 1) : 0, stdout, stderr);
    });
  },
  toast() {},
  getPackagesInfo(json) {
    return JSON.stringify(JSON.parse(json).map((p) => ({ packageName: p, appLabel: 'App ' + p.split('.').pop(), isSystem: p.startsWith('com.android') })));
  },
};

const api = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/api.js')).href + '?v=__V__');
const ui = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/ui.js')).href + '?v=__V__');
await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/theme.js')).href + '?v=__V__');

await test('theme follows the system and persists an explicit preference', () => {
  assert.equal(document.documentElement.dataset.theme, 'light');
  systemDark = true;
  for (const listener of themeListeners) listener();
  assert.equal(document.documentElement.dataset.theme, 'dark');
  document.dispatchEvent(new w.CustomEvent('kpm-theme-change', { detail: 'light' }));
  assert.equal(localStorage.getItem('kpm-theme'), 'light');
  for (const listener of themeListeners) listener();
  assert.equal(document.documentElement.dataset.theme, 'light');
  assert.equal(document.querySelector('meta[name="theme-color"]').content, '#ffffff');
  systemDark = false;
  document.dispatchEvent(new w.CustomEvent('kpm-theme-change', { detail: 'auto' }));
});

await test('icon buttons preserve names and reject duplicate async actions', async () => {
  let release, calls = 0;
  const b = ui.toolBtn('编辑', 'pencil', () => { calls++; return new Promise((resolve) => { release = resolve; }); });
  document.body.append(b);
  assert.equal(b.getAttribute('aria-label'), '编辑');
  assert.equal(b.querySelector('svg').getAttribute('aria-hidden'), 'true');
  assert.equal(b.textContent, '编辑');
  b.click();
  b.click();
  assert.equal(calls, 1);
  assert.equal(b.getAttribute('aria-busy'), 'true');
  ui.setDisabled(b, true);
  release();
  await sleep(0);
  assert.equal(b.disabled, true);
  assert.equal(b.hasAttribute('aria-busy'), false);
  b.remove();
});

await test('dialogs trap focus, stack safely and restore the trigger', async () => {
  const trigger = ui.h('button', null, 'open');
  document.body.append(trigger);
  trigger.focus();
  const result = ui.modal('编辑测试', ui.h('input', { 'aria-label': '名称' }), [
    { label: '取消', value: false }, { label: '保存', value: true },
  ]);
  const first = document.querySelector('.overlay .dialog');
  assert.equal(document.activeElement, first);
  assert.equal(document.getElementById(first.getAttribute('aria-labelledby')).textContent, '编辑测试');
  assert.ok(document.getElementById('app').hasAttribute('inert'));
  const controls = [...first.querySelectorAll('button, input')];
  controls[controls.length - 1].focus();
  document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }));
  assert.equal(document.activeElement, controls[0]);
  document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true, cancelable: true }));
  assert.equal(document.activeElement, controls[controls.length - 1]);
  const nested = ui.modal('确认', ui.h('p', null, 'test'));
  assert.ok(first.closest('.overlay').hasAttribute('inert'));
  document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  await nested;
  assert.equal(document.querySelectorAll('.overlay').length, 1);
  assert.ok(!first.closest('.overlay').hasAttribute('inert'));
  document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  await result;
  assert.equal(document.activeElement, trigger);
  assert.ok(!document.getElementById('app').hasAttribute('inert'));
  assert.ok(!document.body.classList.contains('modal-open'));
  trigger.remove();
});

await test('conditional fields, hints and password controls remain accessible', async () => {
  const f = ui.form([
    { key: 'tls', label: 'TLS', type: 'switch', hint: 'test hint' },
    { key: 'host', label: 'SNI', show: (v) => v.tls },
    { key: 'password', label: '密码', type: 'password' },
  ], { tls: false, password: 'sample' });
  document.body.append(f.el);
  const fields = f.el.querySelectorAll('.field');
  assert.equal(fields[1].hidden, true);
  const tls = fields[0].querySelector('input');
  assert.equal(document.getElementById(tls.getAttribute('aria-describedby')).textContent, 'test hint');
  tls.click();
  assert.equal(fields[1].hidden, false);
  const toggle = fields[2].querySelector('button');
  toggle.click();
  await sleep(0);
  assert.equal(fields[2].querySelector('input').type, 'text');
  assert.equal(toggle.getAttribute('aria-label'), '隐藏密码');
  assert.equal(toggle.getAttribute('aria-pressed'), 'true');
  f.el.remove();
});

await test('node edits preserve custom transport headers', async () => {
  const { buildNode } = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/pages/proxies.js')).href + '?v=__V__');
  const original = { id: 'headers', name: 'renamed', type: 'vless', server: 'example.com', port: 443, udp: true,
    transport: { type: 'ws', host: 'example.com', path: '/ws', headers: { 'X-Test': 'required' } }, tls: { enabled: true } };
  assert.deepEqual(buildNode(original).transport.headers, original.transport.headers);
});

await test('shQuote / base64 / commands', () => {
  assert.equal(api.shQuote("a'b"), `'a'\\''b'`);
  assert.equal(Buffer.from(api.toBase64('节点 ✓'), 'base64').toString(), '节点 ✓');
  const small = api.buildCommands('POST', '/api/v1/nodes', { a: 1 });
  assert.equal(small.uploads.length, 0);
  assert.match(small.call, / --body-b64 [A-Za-z0-9+/=]+$/);
  const big = api.buildCommands('POST', '/api/v1/nodes/import', { text: 'x'.repeat(300000) }, () => 'deadbeefdeadbeef');
  assert.ok(big.uploads.length >= 4);
  assert.match(big.call, / --chunks deadbeefdeadbeef \d+$/);
  for (const c of [...big.uploads, big.call]) assert.ok(c.length < 100000);
  assert.throws(() => api.buildCommands('GET', "/api/v1/x'; rm -rf /"), /路径/);
  assert.throws(() => api.buildCommands('GET', '/etc/passwd'), /路径/);
  assert.throws(() => api.buildCommands('GET', '/api/v1/../x'), /路径/);
  for (const p of ['/api/v1/%2e%2e/nodes', '/api/v1/x%2f..%2fnodes', '/api/v1/%5cetc', '/api/v1/%GG']) {
    assert.throws(() => api.buildCommands('GET', p), /路径/);
  }
  assert.equal(api.validPath('/api/v1/nodes/hk..1'), true);
  assert.equal(api.validPath('/api/v1/nodes/hk%2e%2e1'), true);
  assert.throws(() => api.buildCommands('EVIL', '/api/v1/x'), /方法/);
  assert.equal(api.q('/api/v1/logs', { a: 1, b: '', c: 'x y' }), '/api/v1/logs?a=1&c=x%20y');
});

await test('bridge output parsing', () => {
  assert.deepEqual(api.parseBridgeOutput({ stdout: '{"status":200,"body":{"x":1}}\n' }), { status: 200, body: { x: 1 } });
  assert.throws(() => api.parseBridgeOutput({ stdout: '{"status":0,"error":"down"}' }), (e) => e.code === 'DAEMON_DOWN');
  for (const code of ['TIMEOUT', 'RESPONSE_ERROR', 'CONNECTION_ERROR', 'BAD_REQUEST']) {
    assert.throws(() => api.parseBridgeOutput({ stdout: JSON.stringify({ status: 0, code, error: 'test' }) }), (e) => e.code === code);
  }
  assert.throws(() => api.parseBridgeOutput({ stdout: '', stderr: 'sh: not found' }), (e) => e.code === 'BRIDGE' && /not found/.test(e.message));
});

await test('ui helpers never interpret HTML', () => {
  const el = ui.h('div', null, '<img src=x onerror=alert(1)>', ui.h('b', { title: '"><script>' }, 'ok'));
  assert.equal(el.querySelector('img'), null);
  assert.equal(el.firstChild.nodeType, 3);
  const f = ui.form([{ key: 'a.b', label: 'x' }, { key: 'l', label: 'y', type: 'lines' }], { a: { b: 'v' } });
  const input = f.el.querySelector('input');
  input.value = 'changed';
  input.dispatchEvent(new w.Event('input'));
  assert.equal(f.values.a.b, 'changed');
  assert.deepEqual(ui.lines(' a \n\n b '), ['a', 'b']);
  assert.equal(ui.fmtBytes(1536), '1.5 KB');
});

await test('traffic chart keeps idle and low-rate axis labels compact', async () => {
  assert.equal(ui.fmtBytes(785.0666666666667), '785 B');
  assert.equal(ui.fmtRate(392.53333333333336), '393 B/s');
  const { drawChart } = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/pages/overview.js')).href + '?v=__V__');
  const labels = [];
  const noop = () => {};
  const context = { setTransform: noop, clearRect: noop, beginPath: noop,
    moveTo: noop, lineTo: noop, closePath: noop, fill: noop, stroke: noop,
    fillText: (text) => labels.push(text) };
  const canvas = { clientWidth: 320, clientHeight: 172, getContext: () => context };
  for (const history of [[], [{ up: 12.5, down: 785.0666666666667 }]]) {
    labels.length = 0;
    drawChart(canvas, history);
    assert.deepEqual(labels, ['1.1 KB/s', '785 B/s', '393 B/s', '0 B/s']);
  }
});

// ---- end to end ----
const subServer = http.createServer((req, res) => {
  res.setHeader('Subscription-Userinfo', 'upload=0; download=1048576; total=10737418240; expire=1900000000');
  res.end('trojan://pw@s1.example.com:443#订阅节点1\ntrojan://pw@s2.example.com:443#订阅节点2\n');
});
await new Promise((r) => subServer.listen(0, '127.0.0.1', r));
const subURL = `http://127.0.0.1:${subServer.address().port}/sub?token=secret-token`;
fs.writeFileSync(path.join(dataDir, 'packages.list'), 'com.example.browser 10123 0 /x\ncom.android.chrome 10050 0 /x\n');

const $ = (sel) => w.document.querySelector(sel);
const $$ = (sel) => [...w.document.querySelectorAll(sel)];
const byText = (sel, text) => $$(sel).find((e) => e.textContent.trim() === text);
const click = (el) => { assert.ok(el, 'element to click'); el.dispatchEvent(new w.MouseEvent('click', { bubbles: true })); };
async function go(page) {
  const hash = '#/' + page;
  if (w.location.hash === hash) w.dispatchEvent(new w.HashChangeEvent('hashchange'));
  else w.location.hash = hash;
  await waitFor(() => $(`#nav a.active[data-id="${page}"]`), 'page ' + page);
  await sleep(300);
}
function setInput(el, value) {
  el.value = value;
  el.dispatchEvent(new w.Event('input', { bubbles: true }));
  el.dispatchEvent(new w.Event('change', { bubbles: true }));
}
const dialog = () => $$('.overlay .dialog').pop();
const inDialog = (sel) => { const d = dialog(); return d ? [...d.querySelectorAll(sel)] : []; };
async function dialogButton(text) {
  const b = await waitFor(() => inDialog('footer button').find((x) => x.textContent === text), 'dialog button ' + text);
  click(b);
}

const main = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/main.js')).href + '?v=__V__');

await test('boot starts the daemon and renders the overview', async () => {
  await waitFor(() => $('#view .section h2') && $('#view .section h2').textContent === '运行状态', 'overview', 30000);
  assert.ok(commands.some((c) => c.endsWith(' daemon start')), 'daemon was started through the bridge');
  assert.equal($$('#nav a').length, 9);
  assert.equal($$('#mobile-nav a').length, 4);
  assert.equal($('#nav a.active').getAttribute('aria-current'), 'page');
});

await test('overview keeps its controls during polling and mode changes', async () => {
  const start = byText('button', '启动核心');
  const modes = $('#view .seg');
  await main.ctx.refreshStatus();
  assert.equal(byText('button', '启动核心'), start);
  assert.equal($('#view .seg'), modes);
  const global = modes.querySelector('input[value="global"]');
  global.click();
  await waitFor(async () => (await api.get('/api/v1/status')).mode === 'global', 'global mode');
  await waitFor(() => !global.disabled, 'mode controls enabled');
  assert.equal(global.checked, true);
  const rule = modes.querySelector('input[value="rule"]');
  rule.click();
  await waitFor(() => !rule.disabled, 'rule mode restored');
  assert.equal((await api.get('/api/v1/status')).mode, 'rule');
});

await test('mobile More exposes all secondary pages and preserves route state', async () => {
  click($('#nav-more'));
  await waitFor(dialog, 'More dialog');
  assert.equal(inDialog('.more-menu a').length, 5);
  assert.equal($('#nav-more').getAttribute('aria-expanded'), 'true');
  click(dialog().querySelector('a[href="#/settings"]'));
  await waitFor(() => $('#nav a.active')?.dataset.id === 'settings', 'settings from More');
  assert.equal($('#page-title').textContent, '设置');
  assert.equal($('#nav-more').classList.contains('active'), true);
  await waitFor(() => $('#nav-more').getAttribute('aria-expanded') === 'false', 'More collapsed');
  assert.equal(dialog(), undefined);
  await go('overview');
});

await test('nodes: import links, edit, delete', async () => {
  await go('proxies');
  click(byText('button', '导入'));
  await waitFor(dialog, 'import dialog');
  setInput(inDialog('textarea')[0], 'trojan://pw@a.example.com:443#节点A\nvless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@b.example.com:443?security=tls#节点B\n');
  await dialogButton('导入');
  await waitFor(() => $$('.list .title').some((e) => e.textContent === '节点A'), 'imported node');
  const row = $$('.list li').find((li) => li.querySelector('.title') && li.querySelector('.title').textContent === '节点A');
  click([...row.querySelectorAll('button')].find((b) => b.textContent === '编辑'));
  await waitFor(dialog, 'edit dialog');
  const nameInput = inDialog('.field').find((f) => f.querySelector('.label').textContent === '名称').querySelector('input');
  setInput(nameInput, '节点A-改');
  await dialogButton('保存');
  await waitFor(() => $$('.list .title').some((e) => e.textContent === '节点A-改'), 'renamed node');
  const status = await api.get('/api/v1/nodes');
  assert.ok(status.nodes.find((n) => n.name === '节点A-改').secrets.password, 'secret kept after edit');
});

await test('nodes: add a node with the form', async () => {
  click(byText('button', '添加'));
  await waitFor(dialog, 'add dialog');
  const field = (label) => inDialog('.field').find((f) => f.querySelector('.label').textContent === label);
  setInput(field('名称').querySelector('input'), '手动 SS');
  setInput(field('服务器').querySelector('input'), '1.2.3.4');
  setInput(field('端口').querySelector('input'), '8388');
  setInput(field('密码').querySelector('input'), 'pw-ss');
  await dialogButton('保存');
  await waitFor(() => $$('.list .title').some((e) => e.textContent === '手动 SS'), 'added node');
});

await test('nodes: imported headers survive form rename and reload', async () => {
  const imported = await api.post('/api/v1/nodes/import', { text: JSON.stringify({
    outbounds: [{ type: 'vless', tag: 'Header round trip', server: 'example.com', server_port: 443,
      uuid: '0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f', tls: { enabled: true },
      transport: { type: 'ws', path: '/ws', headers: { Host: 'cdn.example.com', 'X-Test': 'required-value' } } }],
  }) });
  assert.equal(imported.added, 1);
  await go('overview');
  await go('proxies');
  const row = await waitFor(() => $$('.list li').find((li) => li.querySelector('.title')?.textContent === 'Header round trip'), 'header node');
  click([...row.querySelectorAll('button')].find((b) => b.textContent === '编辑'));
  await waitFor(dialog, 'header edit dialog');
  const name = inDialog('.field').find((f) => f.querySelector('.label').textContent === '名称').querySelector('input');
  setInput(name, 'Header renamed');
  await dialogButton('保存');
  await waitFor(() => $$('.list .title').some((e) => e.textContent === 'Header renamed'), 'saved header node');
  const saved = (await api.get('/api/v1/nodes')).nodes.find((n) => n.name === 'Header renamed');
  assert.equal(saved.transport.headers['X-Test'], 'required-value');
  assert.equal(saved.transport.host, 'cdn.example.com');
  assert.equal(saved.transport.path, '/ws');
  assert.equal(saved.secrets.uuid, true);
});

await test('subscriptions: add, preview and commit', async () => {
  await go('subscriptions');
  click(byText('button', '添加'));
  await waitFor(dialog, 'sub dialog');
  const field = (label) => inDialog('.field').find((f) => f.querySelector('.label').textContent === label);
  setInput(field('名称').querySelector('input'), '测试订阅');
  setInput(field('订阅地址').querySelector('input'), subURL);
  await dialogButton('保存');
  await waitFor(() => dialog() && dialog().querySelector('.dialog-title').textContent.startsWith('确认更新'), 'preview dialog', 20000);
  assert.match(dialog().textContent, /新增 2/);
  await dialogButton('应用');
  await waitFor(() => $$('.list .sub').some((e) => /2 个节点/.test(e.textContent)), 'committed subscription');
  assert.ok(!w.document.body.textContent.includes('secret-token'), 'subscription token shown in UI');
});

await test('routing: add a rule and save DNS', async () => {
  await go('routing');
  await waitFor(() => byText('button', '添加'), 'routing loaded');
  click(byText('button', '添加'));
  await waitFor(dialog, 'rule dialog');
  setInput(inDialog('textarea')[0], 'example.org\n.example.net');
  await dialogButton('确定');
  await waitFor(() => $$('.list .sub').some((e) => e.textContent.includes('example.org')), 'rule listed');
  const r = await api.get('/api/v1/routing');
  assert.equal(r.routing.rules.length, 1);
  assert.deepEqual(r.routing.rules[0].values, ['example.org', '.example.net']);
});

await test('routing and DNS use their own snapshot revisions', async () => {
  const { default: mountRouting } = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/pages/routing.js')).href + '?v=__V__');
  const routing = await api.get('/api/v1/routing');
  const dns = await api.get('/api/v1/dns');
  const groups = await api.get('/api/v1/groups');
  const writes = [];
  api.setTransport(async (method, requestPath, body) => {
    const pathname = requestPath.split('?')[0];
    if (method === 'GET' && pathname === '/api/v1/routing') return { status: 200, body: { ...routing, revision: 41 } };
    if (method === 'GET' && pathname === '/api/v1/dns') return { status: 200, body: { ...dns, revision: 42 } };
    if (method === 'GET' && pathname === '/api/v1/groups') return { status: 200, body: groups };
    if (method === 'PUT' && ['/api/v1/routing', '/api/v1/dns'].includes(pathname)) {
      writes.push(requestPath);
      return { status: 200, body: { revision: 43 } };
    }
    return api.bridgeRequest(method, requestPath, body);
  });
  const root = ui.h('div');
  document.body.append(root);
  const dispose = mountRouting(root);
  const section = (name) => [...root.querySelectorAll('.section')].find((el) => el.querySelector('h2')?.textContent === name);
  const save = (name) => [...section(name).querySelectorAll('button')].find((el) => el.textContent === '保存');
  try {
    await waitFor(() => section('DNS')?.querySelector('textarea'), 'independent snapshot forms');
    save('分流设置').click();
    await waitFor(() => writes.length === 1, 'routing revision write');
    assert.equal(writes[0], '/api/v1/routing?rev=41');
    await sleep(20);
    save('DNS').click();
    await waitFor(() => writes.length === 2, 'DNS revision write');
    assert.equal(writes[1], '/api/v1/dns?rev=42');
  } finally {
    dispose();
    root.remove();
    api.setTransport(null);
  }
});

await test('apps: include mode with a selected app', async () => {
  await go('apps');
  await waitFor(() => $$('input[name="app-mode"]').length === 3, 'modes');
  const include = $$('input[name="app-mode"]')[1];
  include.checked = true;
  include.dispatchEvent(new w.Event('change', { bubbles: true }));
  await waitFor(() => $$('.list .title').some((e) => e.textContent === 'App browser'), 'labelled app');
  const li = $$('.list li').find((x) => x.textContent.includes('com.example.browser'));
  const cb = li.querySelector('input[type=checkbox]');
  cb.checked = true;
  cb.dispatchEvent(new w.Event('change', { bubbles: true }));
  click(byText('button', '保存'));
  await waitFor(async () => (await api.get('/api/v1/apps')).policy.mode === 'include', 'policy saved');
  const p = (await api.get('/api/v1/apps')).policy;
  assert.deepEqual(p.packages, ['com.example.browser']);
});

await test('settings: save, export backup, web key', async () => {
  await go('settings');
  await waitFor(() => $$('.field .label').some((e) => e.textContent === '代理 IPv6'), 'settings form');
  const ipv6 = $$('.field').find((f) => f.querySelector('.label').textContent === '代理 IPv6').querySelector('input');
  ipv6.checked = !ipv6.checked;
  ipv6.dispatchEvent(new w.Event('change', { bubbles: true }));
  const want = ipv6.checked;
  click(byText('button', '保存'));
  await waitFor(async () => (await api.get('/api/v1/settings')).settings.ipv6 === want, 'settings saved');
  click(byText('button', '导出（不含凭据）'));
  await waitFor(() => dialog() && dialog().querySelector('.dialog-title').textContent === '已导出', 'export done');
  await dialogButton('关闭');
  const exported = fs.readdirSync(dataDir).filter((f) => f.startsWith('ksu_proxy_manager-'));
  assert.equal(exported.length, 1);
  const doc = JSON.parse(fs.readFileSync(path.join(dataDir, exported[0]), 'utf8'));
  assert.equal(Object.keys(doc.secrets.nodes || {}).length, 0, 'export without secrets contains secrets');
});

await test('browser settings hide credential export', async () => {
  const { default: mountSettings } = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/pages/settings.js')).href + '?v=__V__');
  const bridge = globalThis.ksu;
  const root = ui.h('div');
  w.document.body.append(root);
  api.setTransport((method, path, body) => {
    globalThis.ksu = bridge;
    const response = api.bridgeRequest(method, path, body);
    globalThis.ksu = undefined;
    return response;
  });
  globalThis.ksu = undefined;
  let dispose;
  try {
    dispose = mountSettings(root, { status: null, refreshStatus: async () => {} });
    await waitFor(() => root.textContent.includes('导出（不含凭据）'), 'browser backup controls');
    assert.ok(!root.textContent.includes('导出（含凭据）'));
    assert.ok(!root.textContent.includes('下载目录中的备份文件'));
  } finally {
    if (dispose) dispose();
    api.setTransport(null);
    globalThis.ksu = bridge;
    root.remove();
  }
});

await test('cores, connections and logs pages render', async () => {
  await go('cores');
  await waitFor(() => $$('.section h2').some((e) => e.textContent === '已安装'), 'cores page');
  await waitFor(() => $$('.banner.warn').some((e) => /尚未安装/.test(e.textContent)), 'missing core hint');
  await go('connections');
  await waitFor(() => /核心未运行/.test($('#view').textContent), 'connections page');
  await go('logs');
  await waitFor(() => $('.logbox') && $('.logbox').childElementCount > 0, 'log lines');
  await go('overview');
  await waitFor(() => byText('button', '启动核心'), 'start button');
  click(byText('button', '启动核心'));
  await waitFor(() => toastsErr.some((t) => /尚未安装/.test(t)), 'start failure surfaced');
  toastsErr.length = 0;
});

await test('log source changes discard late responses from the old source', async () => {
  const { default: mountLogs } = await import(pathToFileURL(path.join(moduleDir, 'webroot/assets/pages/logs.js')).href + '?v=__V__');
  let releaseDaemon;
  api.setTransport((method, path, body) => {
    if (!path.startsWith('/api/v1/logs')) return api.bridgeRequest(method, path, body);
    const response = (text) => ({ status: 200, body: { last: 1, lines: [{ level: 'info', time: new Date().toISOString(), text }] } });
    if (path.includes('source=daemon')) return new Promise((resolve) => { releaseDaemon = () => resolve(response('STALE_DAEMON_LINE')); });
    return Promise.resolve(response('CURRENT_CORE_LINE'));
  });
  const root = ui.h('div');
  document.body.append(root);
  const dispose = mountLogs(root);
  try {
    await waitFor(() => releaseDaemon, 'pending daemon logs');
    root.querySelector('input[value="core"]').click();
    await waitFor(() => root.textContent.includes('CURRENT_CORE_LINE'), 'core log response');
    releaseDaemon();
    await sleep(100);
    assert.ok(!root.textContent.includes('STALE_DAEMON_LINE'));
  } finally {
    dispose();
    root.remove();
    api.setTransport(null);
  }
});

await test('large request bodies use chunked uploads', async () => {
  const many = Array.from({ length: 1500 }, (_, i) => `trojan://pw${i}@n${i}.example.com:443#批量${i}`).join('\n');
  const before = commands.length;
  const r = await api.post('/api/v1/nodes/import', { text: many });
  assert.equal(r.added, 1500);
  const used = commands.slice(before);
  assert.ok(used.some((c) => / chunk [a-f0-9]{16} 0 /.test(c)), 'chunk command used');
  assert.ok(used.some((c) => / --chunks [a-f0-9]{16} \d+$/.test(c)));
  assert.deepEqual(fs.readdirSync(path.join(dataDir, 'run/bridge')), [], 'bridge chunks cleaned up');
});

await test('no unexpected errors', () => {
  assert.deepEqual(toastsErr, []);
  assert.deepEqual(rejections, []);
  assert.deepEqual(domErrors, []);
});

try {
  execFileSync(realCtl, ['daemon', 'stop'], { env, stdio: 'pipe' });
} catch (e) {
  console.log('daemon stop failed: ' + e.message);
  failures++;
}
subServer.close();
fs.rmSync(dataDir, { recursive: true, force: true });
console.log(failures ? `${failures} FAILED` : 'ALL PASSED');
process.exit(failures ? 1 : 0);
