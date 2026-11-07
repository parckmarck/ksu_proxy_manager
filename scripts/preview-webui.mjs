// Isolated Linux/WSL preview backed by the real daemon. Never use device data.
// Usage: node scripts/preview-webui.mjs <module-dir-with-host-binaries> [port]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { execFileSync } from 'node:child_process';

if (process.platform !== 'linux' || fs.existsSync('/system/bin/app_process')) {
  throw new Error('Run this preview on a Linux/WSL development host, not Android.');
}
const moduleDir = path.resolve(process.argv[2] || '');
const ctl = path.join(moduleDir, 'bin/arm64-v8a/proxyctl');
if (!fs.existsSync(ctl) || !fs.existsSync(path.join(moduleDir, 'webroot/index.html'))) {
  throw new Error('A module directory with host binaries and webroot is required.');
}
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kpm-ui-preview-'));
const env = { ...process.env, KPM_MODULE_DIR: moduleDir, KPM_DATA_DIR: dataDir,
  KPM_ALLOW_CAPTURE: '0', KPM_IMPORT_ROOT: dataDir, KPM_PACKAGES_LIST: path.join(dataDir, 'packages.list') };
fs.writeFileSync(env.KPM_PACKAGES_LIST, 'com.example.browser 10123 0 /x\ncom.example.reader 10124 0 /x\ncom.android.settings 10050 0 /x\n');
const run = (...args) => execFileSync(ctl, args, { env, encoding: 'utf8', maxBuffer: 16 << 20 });
const api = (method, url, body) => {
  const args = ['api', method, url];
  if (body !== undefined) args.push('--body-b64', Buffer.from(JSON.stringify(body)).toString('base64'));
  const result = JSON.parse(run(...args).trim().split('\n').pop());
  if (result.status < 200 || result.status >= 300) throw new Error(JSON.stringify(result));
  return result.body;
};
const subServer = http.createServer((_req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Subscription-Userinfo', 'upload=268435456; download=3221225472; total=53687091200; expire=1900000000');
  res.end('trojan://demo-only@hk.example.com:443#Hong%20Kong%2001\ntrojan://demo-only@jp.example.com:443#Tokyo%2001\ntrojan://demo-only@sg.example.com:443#Singapore%2001\n');
});
let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  try { run('daemon', 'stop'); } catch { /* A failed startup may have no daemon. */ }
  subServer.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
};
process.on('SIGINT', () => { stop(); process.exit(0); });
process.on('SIGTERM', () => { stop(); process.exit(0); });
process.on('exit', stop);

try {
  await new Promise((resolve) => subServer.listen(0, '127.0.0.1', resolve));
  const probe = net.createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(Number(process.argv[3]) || 0, '127.0.0.1', resolve);
  });
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  run('daemon', 'start');
  const initial = api('GET', '/api/v1/settings');
  api('PUT', '/api/v1/settings', { ...initial.settings, autoStart: false, autoRestart: false, rulesetAutoUpdate: false, webAccess: { enabled: true, port } });
  const key = api('POST', '/api/v1/system/web-key').key;
  const subURL = `http://127.0.0.1:${subServer.address().port}/subscription`;
  const sub = api('POST', '/api/v1/subscriptions', {
    subscription: { name: 'Example subscription', userAgent: '', autoUpdateHours: 0, viaProxy: false, filter: '', excludeFilter: '' },
    url: subURL,
  });
  let task = api('POST', `/api/v1/subscriptions/${sub.id}/refresh`);
  while (task.state === 'running') {
    await new Promise((resolve) => setTimeout(resolve, 100));
    task = api('GET', '/api/v1/tasks/' + task.id);
  }
  if (task.state !== 'succeeded') throw new Error('Preview subscription failed: ' + task.error);
  api('POST', `/api/v1/subscriptions/${sub.id}/commit`, { previewId: task.result.previewId });
  api('POST', '/api/v1/nodes/import', { text: [
    'ss://YWVzLTEyOC1nY206ZGVtby1vbmx5@us.example.com:443#US%20West%2001',
    'vless://0f9e8d7c-6b5a-4c3d-9e8f-7a6b5c4d3e2f@de.example.com:443?security=tls&type=ws#Frankfurt%2001',
  ].join('\n') });
  const routing = api('GET', '/api/v1/routing').routing;
  api('PUT', '/api/v1/routing', { ...routing, preset: 'custom', rules: [
    { id: 'demo-direct', enabled: true, type: 'domain_suffix', values: ['example.cn'], target: 'DIRECT', note: 'Example direct rule' },
    { id: 'demo-proxy', enabled: true, type: 'domain_suffix', values: ['example.org'], target: 'group:proxy', note: 'Example proxy rule' },
  ] });
  api('PUT', '/api/v1/apps/policy', { mode: 'include', packages: ['com.example.browser'], users: [0] });
  api('POST', '/api/v1/core/stop');
  console.log(JSON.stringify({ url: `http://127.0.0.1:${port}/`, key, subURL, dataDir, moduleDir, pid: process.pid }));
} catch (error) {
  stop();
  throw error;
}
