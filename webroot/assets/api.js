// Transport to the management daemon. Inside the KernelSU WebUI requests go
// through `ksu.exec` and the proxyctl bridge; in a browser (optional local web
// access) they use HTTP with a bearer key.

export const MODULE_DIR = '/data/adb/modules/ksu_proxy_manager';
export const PROXYCTL = MODULE_DIR + '/proxyctl';
// A single shell argument must stay well below the kernel's 128 KiB limit.
export const INLINE_LIMIT = 60000;
export const CHUNK_SIZE = 90000;

export class ApiError extends Error {
  constructor(status, code, message, field) {
    super(message);
    this.status = status;
    this.code = code;
    this.field = field || '';
  }
}

export function hasBridge() {
  return typeof globalThis.ksu === 'object' && globalThis.ksu !== null && typeof globalThis.ksu.exec === 'function';
}

let seq = 0;

// exec runs a shell command through KernelSU and resolves {errno, stdout, stderr}.
export function exec(cmd, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const name = `__kpm_cb_${Date.now().toString(36)}_${seq++}`;
    const timer = setTimeout(() => {
      delete globalThis[name];
      reject(new ApiError(0, 'TIMEOUT', '命令执行超时'));
    }, timeoutMs);
    globalThis[name] = (errno, stdout, stderr) => {
      clearTimeout(timer);
      delete globalThis[name];
      resolve({ errno: Number(errno), stdout: String(stdout ?? ''), stderr: String(stderr ?? '') });
    };
    try {
      globalThis.ksu.exec(cmd, '{}', name);
    } catch (e) {
      clearTimeout(timer);
      delete globalThis[name];
      reject(new ApiError(0, 'BRIDGE', '无法调用 KernelSU 接口: ' + (e && e.message ? e.message : e)));
    }
  });
}

// shQuote quotes one argument for /system/bin/sh.
export function shQuote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

export function toBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function randomHex(n = 8) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

const PATH_RE = /^\/api\/v1\/[A-Za-z0-9._~/%?&=:,+-]*$/;

export function validPath(p) {
  if (typeof p !== 'string' || p.length > 4096 || !PATH_RE.test(p)) return false;
  try {
    const path = decodeURIComponent(p.split('?')[0]);
    return !path.includes('\\') && !path.split('/').some((part) => part === '.' || part === '..');
  } catch {
    return false;
  }
}

const METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);

// buildCommands returns the shell commands needed for one request: optional
// chunk uploads followed by the API call.
export function buildCommands(method, path, body, idFn = randomHex) {
  if (!METHODS.has(method)) throw new ApiError(0, 'BAD_METHOD', '请求方法无效');
  if (!validPath(path)) throw new ApiError(0, 'BAD_PATH', '请求路径无效');
  let call = `${PROXYCTL} api ${method} ${shQuote(path)}`;
  const uploads = [];
  if (body !== undefined) {
    const data = toBase64(JSON.stringify(body));
    if (data.length <= INLINE_LIMIT) {
      call += ` --body-b64 ${data}`;
    } else {
      const id = idFn(8);
      const n = Math.ceil(data.length / CHUNK_SIZE);
      for (let i = 0; i < n; i++) {
        uploads.push(`${PROXYCTL} chunk ${id} ${i} ${data.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)}`);
      }
      call += ` --chunks ${id} ${n}`;
    }
  }
  return { uploads, call };
}

export function parseBridgeOutput(r) {
  const text = (r.stdout || '').trim();
  const last = text.split('\n').pop();
  let out;
  try {
    out = JSON.parse(last);
  } catch {
    const detail = (r.stderr || text || '').trim().slice(0, 300);
    throw new ApiError(0, 'BRIDGE', detail ? '桥接调用失败: ' + detail : '桥接调用失败（无输出）');
  }
  if (!out || !out.status) {
    // proxyctl reports a stable code; only a connection failure may trigger
    // the automatic daemon start.
    const code = out?.code || 'DAEMON_DOWN';
    throw new ApiError(0, code, (out && out.error) || '管理服务未运行');
  }
  return { status: out.status, body: out.body };
}

export async function bridgeRequest(method, path, body, execFn = exec) {
  const { uploads, call } = buildCommands(method, path, body);
  for (const cmd of uploads) {
    const r = await execFn(cmd, 60000);
    if (r.errno !== 0) throw new ApiError(0, 'BRIDGE', '上传请求数据失败');
  }
  return parseBridgeOutput(await execFn(call));
}

const KEY_STORE = 'kpm-web-key';

export function getWebKey() {
  try { return sessionStorage.getItem(KEY_STORE) || ''; } catch { return ''; }
}

export function setWebKey(k) {
  try { sessionStorage.setItem(KEY_STORE, k); } catch { /* storage unavailable */ }
}

async function httpRequest(method, path, body) {
  if (!validPath(path)) throw new ApiError(0, 'BAD_PATH', '请求路径无效');
  const headers = { Authorization: 'Bearer ' + getWebKey() };
  const init = { method, headers, cache: 'no-store', credentials: 'omit' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, 'DAEMON_DOWN', '无法连接管理服务');
  }
  const text = await res.text();
  let parsed = text;
  try { parsed = JSON.parse(text); } catch { /* keep text */ }
  return { status: res.status, body: parsed };
}

let transport = null;

// setTransport replaces the request function (used by tests).
export function setTransport(fn) { transport = fn; }

export async function api(method, path, body) {
  const fn = transport || (hasBridge() ? bridgeRequest : httpRequest);
  const { status, body: data } = await fn(method, path, body);
  if (status >= 200 && status < 300) return data;
  const e = (data && typeof data === 'object' && data.error) || {};
  throw new ApiError(status, e.code || 'HTTP_' + status, e.message || `请求失败（HTTP ${status}）`, e.field);
}

export const get = (p) => api('GET', p);
export const post = (p, b) => api('POST', p, b);
export const put = (p, b) => api('PUT', p, b);
export const del = (p) => api('DELETE', p);

export function q(path, params) {
  const parts = [];
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === '') continue;
    parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(String(v)));
  }
  return parts.length ? path + '?' + parts.join('&') : path;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// waitTask polls a background task until it finishes and returns its result.
// opts.timeoutMs bounds the wait (default 30 minutes); opts.signal aborts it
// and asks the daemon to cancel the task.
export async function waitTask(task, onProgress, opts = {}) {
  const timeoutMs = opts.timeoutMs || 30 * 60 * 1000;
  const started = Date.now();
  let t = task;
  for (;;) {
    if (onProgress) onProgress(t);
    if (t.state !== 'running') break;
    if (opts.signal && opts.signal.aborted) {
      await post('/api/v1/tasks/' + encodeURIComponent(t.id) + '/cancel').catch(() => {});
      throw new ApiError(200, 'TASK_CANCELLED', '已取消');
    }
    if (Date.now() - started > timeoutMs) {
      await post('/api/v1/tasks/' + encodeURIComponent(t.id) + '/cancel').catch(() => {});
      throw new ApiError(200, 'TASK_TIMEOUT', '任务超时，已请求取消');
    }
    await sleep(700);
    t = await get('/api/v1/tasks/' + encodeURIComponent(t.id));
  }
  if (t.state !== 'succeeded') {
    throw new ApiError(200, 'TASK_' + String(t.state).toUpperCase(), t.error || '任务失败');
  }
  return t.result;
}

export async function startDaemon() {
  if (!hasBridge()) throw new ApiError(0, 'NO_BRIDGE', '浏览器模式下无法启动管理服务');
  const r = await exec(`${PROXYCTL} daemon start`, 60000);
  if (r.errno !== 0) {
    throw new ApiError(0, 'DAEMON_START', ((r.stderr || '') + '\n' + (r.stdout || '')).trim() || '管理服务启动失败');
  }
}

// packageInfo returns {pkg: {label, system}} using the root manager's API when available.
export function packageInfo(pkgs) {
  const out = {};
  const k = globalThis.ksu;
  if (!k || typeof k.getPackagesInfo !== 'function') return out;
  for (let i = 0; i < pkgs.length; i += 100) {
    try {
      const list = JSON.parse(k.getPackagesInfo(JSON.stringify(pkgs.slice(i, i + 100))));
      for (const p of list || []) {
        if (p && p.packageName) out[p.packageName] = { label: p.appLabel || '', system: !!p.isSystem };
      }
    } catch { /* older managers */ }
  }
  return out;
}

export function ksuToast(msg) {
  try { globalThis.ksu.toast(String(msg)); } catch { /* not available */ }
}
