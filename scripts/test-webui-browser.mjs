// Real-browser regression checks against scripts/preview-webui.mjs only.
// NODE_PATH must contain playwright; KPM_WEBUI_TEST_KEY is the preview key.
// Usage: node scripts/test-webui-browser.mjs <preview-url> <screenshot-directory>
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const baseURL = process.argv[2];
const output = path.resolve(process.argv[3] || '');
const key = process.env.KPM_WEBUI_TEST_KEY;
assert.ok(baseURL && key && process.argv[3], 'preview URL, key and output directory required');
assert.equal(new URL(baseURL).hostname, '127.0.0.1', 'only a loopback preview is allowed');
fs.mkdirSync(output, { recursive: true });
const browser = await chromium.launch({ channel: process.env.KPM_BROWSER_CHANNEL || 'chrome', headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, colorScheme: 'light', locale: 'zh-CN' });
const page = await context.newPage();
const errors = [];
const results = [];
page.on('pageerror', (e) => errors.push(e.message));
const api = async (url, method = 'GET', data) => {
  const response = await context.request.fetch(new URL(url, baseURL).href, { method, data, headers: { Authorization: 'Bearer ' + key } });
  assert.ok(response.ok(), `${method} ${url}: ${response.status()}`);
  return response.json();
};
const pages = [
  ['overview', '概览'], ['proxies', '节点'], ['subscriptions', '订阅'], ['routing', '分流'],
  ['apps', '应用'], ['cores', '核心'], ['connections', '连接'], ['logs', '日志'], ['settings', '设置'],
];
const go = async (id) => {
  await page.evaluate((id) => { location.hash = '#/' + id; }, id);
  await page.waitForFunction((id) => document.querySelector('#nav a.active')?.dataset.id === id, id);
  await page.waitForFunction(() => !document.querySelector('#view .loading'));
  await page.waitForTimeout(120);
};
const checkLayout = async (label) => {
  const problems = await page.evaluate(() => {
    const problems = [];
    const width = document.documentElement.clientWidth;
    if (document.documentElement.scrollWidth > width + 1) problems.push(`document width ${document.documentElement.scrollWidth} > ${width}`);
    for (const el of document.querySelectorAll('#view .btn, #view .label, #view h2, #view .member, .dialog, .dialog footer')) {
      if (el.closest('[hidden]') || !el.getClientRects().length) continue;
      const rect = el.getBoundingClientRect();
      if (rect.left < -1 || rect.right > width + 1) problems.push(`${el.className || el.tagName} outside viewport: ${Math.round(rect.left)}..${Math.round(rect.right)}`);
      if (el.matches('.btn:not(.icon-only)') && el.scrollWidth > el.clientWidth + 2) problems.push(`button text overflow: ${el.textContent}`);
    }
    return problems;
  });
  assert.deepEqual(problems, [], label);
  results.push(label);
};
const capture = async (name) => {
  await page.mouse.move(0, 0);
  await page.screenshot({ path: path.join(output, name + '.png'), animations: 'disabled' });
};
const rowNamed = (name) => page.locator('.node-row').filter({ has: page.locator('.title', { hasText: name }) });

try {
  const system = await api('/api/v1/system');
  assert.ok(system.dataDir.startsWith('/tmp/kpm-ui-preview-'), 'refusing to change a non-preview data directory');
  await page.goto(baseURL);
  await page.getByRole('dialog').getByLabel('访问密钥', { exact: true }).fill(key);
  await page.getByRole('dialog').getByRole('button', { name: '确定', exact: true }).click();
  await go('overview');
  assert.equal(await page.locator('#nav a').count(), 9);
  results.push('browser authentication and initial render');

  await go('proxies');
  const original = (await api('/api/v1/nodes')).nodes.some((n) => n.name === 'US West 01') ? 'US West 01' : 'Browser roundtrip';
  await rowNamed(original).getByRole('button', { name: '编辑', exact: true }).click();
  await page.getByRole('dialog').getByLabel('名称', { exact: true }).fill('Browser roundtrip');
  await page.getByRole('dialog').getByRole('button', { name: '保存', exact: true }).click();
  await rowNamed('Browser roundtrip').waitFor();
  assert.ok((await api('/api/v1/nodes')).nodes.some((n) => n.name === 'Browser roundtrip' && n.secrets.password));
  await rowNamed('Browser roundtrip').getByRole('button', { name: '复制', exact: true }).click();
  await page.waitForFunction(() => [...document.querySelectorAll('.node-row .title')].filter((el) => el.textContent.includes('Browser roundtrip')).length === 2);
  const copy = (await api('/api/v1/nodes')).nodes.find((n) => n.name.startsWith('Browser roundtrip') && n.name !== 'Browser roundtrip');
  const copiedRow = page.locator('.node-row').filter({ has: page.locator('.title', { hasText: copy.name }) });
  await copiedRow.getByRole('button', { name: '删除', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: '删除', exact: true }).click();
  await copiedRow.waitFor({ state: 'detached' });
  await rowNamed('Browser roundtrip').getByRole('button', { name: '编辑', exact: true }).click();
  await page.getByRole('dialog').getByLabel('名称', { exact: true }).fill('US West 01');
  await page.getByRole('dialog').getByRole('button', { name: '保存', exact: true }).click();
  await rowNamed('US West 01').waitFor();
  results.push('node rename, credential preservation, copy and confirmed deletion');

  const firstGroup = page.locator('.runtime-group').first();
  const selected = firstGroup.locator('.member').filter({ hasText: 'Hong Kong 01' });
  await selected.click();
  await page.waitForFunction(() => [...document.querySelectorAll('.runtime-group .member')].some((el) => el.textContent.includes('Hong Kong 01') && el.getAttribute('aria-pressed') === 'true'));
  await firstGroup.locator('summary').click();
  await page.getByRole('button', { name: '刷新', exact: true }).click();
  await page.waitForTimeout(200);
  assert.equal(await firstGroup.getAttribute('open'), null);
  await firstGroup.locator('summary').click();
  await page.getByLabel('节点类型', { exact: true }).selectOption('trojan');
  assert.equal(await page.locator('.node-row').count(), 3);
  await page.getByRole('searchbox').fill('not-a-real-node');
  await page.getByText('没有匹配的节点', { exact: true }).waitFor();
  await page.getByRole('searchbox').fill('');
  await page.getByLabel('节点类型', { exact: true }).selectOption('');
  results.push('group selection, preserved collapse state, type filter and empty search');

  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('#nav-more').click();
  assert.equal(await page.getByRole('dialog').locator('.more-menu a').count(), 5);
  await page.getByRole('dialog').getByRole('link', { name: '设置', exact: true }).click();
  await page.getByLabel('代理 IPv6', { exact: true }).waitFor();
  const ipv6 = page.getByLabel('代理 IPv6', { exact: true });
  const previousIPv6 = await ipv6.isChecked();
  await ipv6.setChecked(!previousIPv6);
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await page.waitForTimeout(300);
  assert.equal((await api('/api/v1/settings')).settings.ipv6, !previousIPv6);
  assert.equal(await page.getByRole('button', { name: '导出（含凭据）', exact: true }).count(), 0);
  results.push('mobile More navigation, settings save and browser credential boundary');

  // Only visual-state fixtures are intercepted; mutations above used the real API.
  await page.route('**/api/v1/status', async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    data.core = { ...data.core, state: 'running', engine: 'mihomo', version: '1.19.33', pid: 18507,
      startedAt: new Date(Date.now() - 486000).toISOString(), captureActive: true, lastError: '', lastExit: '', pending: false };
    await route.fulfill({ response, json: data });
  });
  let tick = 0;
  await page.route('**/api/v1/traffic', async (route) => {
    const history = Array.from({ length: 120 }, (_, i) => ({
      t: new Date(Date.now() - (119 - i) * 1000).toISOString().slice(11, 19),
      down: Math.round((2.1 + Math.sin((i + tick) / 7) * .7 + (i % 11) * .1) * 1048576),
      up: Math.round((.12 + (i % 9) * .02) * 1048576),
    }));
    tick++;
    await route.fulfill({ json: { ...history[119], downTotal: 3284918272, upTotal: 185491827, connections: 18, history } });
  });
  await page.route('**/api/v1/proxies', async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    data.running = true;
    for (const group of data.groups) group.members.forEach((member, i) => { member.delay = 48 + i * 73; });
    await route.fulfill({ response, json: data });
  });
  await page.route('**/api/v1/connections', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    await route.fulfill({ json: {
      running: true, downloadTotal: 83418921, uploadTotal: 4818331,
      connections: ['api.example.org', 'cdn.example.net', 'a-very-long-service-hostname.example.com'].map((host, i) => ({
        id: 'visual-' + i, host, dest: `203.0.113.${i + 1}:443`, network: i === 1 ? 'udp' : 'tcp',
        chains: ['Hong Kong 01', '节点选择'], rule: 'DOMAIN-SUFFIX / example.org', download: 3821481 * (i + 1), upload: 49218 * (i + 1),
      })),
    } });
  });
  await page.waitForFunction(() => document.getElementById('hdr-state').textContent === '运行中');
  await page.waitForFunction(() => !document.querySelector('#toasts .toast'));

  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: 'reduce' });
    for (const [width, height] of [[1440, 1000], [390, 844], [320, 740], [768, 1024]]) {
      await page.setViewportSize({ width, height });
      for (const [id] of pages) {
        await go(id);
        await checkLayout(`${scheme} ${width}px ${id}`);
        if (id === 'overview') {
          const pixels = await page.locator('canvas').evaluate((canvas) => {
            const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
            let visible = 0;
            for (let i = 3; i < pixels.length; i += 4) if (pixels[i]) visible++;
            return visible;
          });
          assert.ok(pixels > 100, 'traffic canvas must be nonblank');
        }
        if ([1440, 390].includes(width)) await capture(`${scheme}-${width}-${id}`);
      }
    }
  }

  await page.setViewportSize({ width: 320, height: 740 });
  await go('proxies');
  await page.locator('#view > .section').nth(1).getByRole('button', { name: '添加', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('类型', { exact: true }).selectOption('vless');
  await dialog.getByLabel('启用 TLS', { exact: true }).check();
  await dialog.getByLabel('SNI', { exact: true }).fill('very-long-name-that-must-not-overflow.example.com');
  await dialog.locator('.body').evaluate((el) => { el.scrollTop = el.scrollHeight; });
  await checkLayout('320px long conditional node form');
  const footer = await dialog.locator('footer').boundingBox();
  const body = await dialog.locator('.body').boundingBox();
  assert.ok(footer.y + footer.height <= 741 && body.y + body.height <= footer.y + 1, 'fixed actions must stay visible without overlapping the form');
  await capture('dark-320-node-dialog');
  await dialog.getByRole('button', { name: '保存', exact: true }).focus();
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), '关闭');
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'detached' });
  await page.setViewportSize({ width: 844, height: 390 });
  await page.locator('#view > .section').nth(1).getByRole('button', { name: '添加', exact: true }).click();
  await checkLayout('landscape node dialog');
  await capture('dark-landscape-node-dialog');
  await page.keyboard.press('Escape');

  await page.setViewportSize({ width: 390, height: 844 });
  await go('overview');
  await page.getByRole('button', { name: '外观', exact: true }).click();
  await page.getByRole('dialog').getByLabel('浅色', { exact: true }).check();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
  await page.getByRole('dialog').getByRole('button', { name: '完成', exact: true }).click();
  await page.reload();
  await page.waitForSelector('#nav a.active', { state: 'attached' });
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
  results.push('long and landscape dialogs, keyboard focus, saved theme after reload');
  const offline = (route) => route.fulfill({ status: 503, json: { error: { code: 'DAEMON_DOWN', message: 'Test connection interruption' } } });
  await page.route('**/api/v1/status', offline);
  await page.getByRole('button', { name: '重新连接', exact: true }).waitFor();
  await page.unroute('**/api/v1/status', offline);
  await page.getByRole('button', { name: '重新连接', exact: true }).click();
  await page.getByRole('button', { name: '重新连接', exact: true }).waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#hdr-state').textContent(), '运行中');
  results.push('visible mobile connection failure and retry recovery');
  assert.deepEqual(errors, [], 'browser runtime errors');
  fs.writeFileSync(path.join(output, 'results.json'), JSON.stringify({ browser: browser.version(), results, errors }, null, 2) + '\n');
  console.log(`ALL PASSED: ${results.length} workflow/layout checks; screenshots in ${output}`);
} catch (error) {
  await page.screenshot({ path: path.join(output, 'failure.png'), animations: 'disabled' }).catch(() => {});
  throw error;
} finally {
  await browser.close();
}
