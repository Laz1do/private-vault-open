const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024;
const ID_PATTERN = /^[A-Za-z0-9_-]{1,80}$/;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function exactKeys(value, keys, message) {
  if (!isObject(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)))
    throw new Error(message);
}
function validId(value) {
  return typeof value === 'string' && ID_PATTERN.test(value) && !['__proto__', 'prototype', 'constructor'].includes(value);
}
function canonicalBase64(value, minBytes, maxBytes, message) {
  if (typeof value !== 'string' || value.length % 4 !== 0 || value.length > Math.ceil(maxBytes / 3) * 4
    || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error(message);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < minBytes || bytes.length > maxBytes || bytes.toString('base64') !== value) throw new Error(message);
  return bytes;
}

function validateConfig(value) {
  const keys = Object.hasOwn(value || {}, 'mode') ? ['vaultId', 'keyB64', 'token', 'endpoint', 'mode'] : ['vaultId', 'keyB64', 'token', 'endpoint'];
  exactKeys(value, keys, '密码库配置无效');
  if (!validId(value.vaultId) || typeof value.token !== 'string' || !/^[A-Za-z0-9_-]{20,200}$/.test(value.token))
    throw new Error('专属配置无效');
  canonicalBase64(value.keyB64, 32, 32, '专属密钥格式无效');
  let endpoint = null;
  if (value.endpoint !== null) {
    if (typeof value.endpoint !== 'string' || !value.endpoint.length || value.endpoint.length > 2048)
      throw new Error('同步地址无效');
    let url;
    try { url = new URL(value.endpoint); } catch { throw new Error('同步地址无效'); }
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username || url.password
      || url.search || url.hash || url.pathname !== '/') throw new Error('同步地址必须是根地址并使用 HTTPS');
    endpoint = url.origin;
  }
  const mode = value.mode ?? 'server';
  if (!['file', 'server'].includes(mode)) throw new Error('同步模式无效');
  return Object.freeze({ vaultId: value.vaultId, keyB64: value.keyB64, token: value.token, endpoint, mode });
}

function validateEnvelope(value, expectedVaultId) {
  exactKeys(value, ['v', 'vaultId', 'alg', 'nonce', 'data'], '只允许持久化加密密码库');
  if (value.v !== 1 || value.alg !== 'A256GCM' || !validId(value.vaultId)
    || (expectedVaultId !== undefined && value.vaultId !== expectedVaultId)) throw new Error('加密密码库标识或格式无效');
  canonicalBase64(value.nonce, 12, 12, '加密随机数格式无效');
  canonicalBase64(value.data, 16, MAX_CIPHERTEXT_BYTES, '加密密码库格式或大小无效');
}

function validateLocal(value, expectedVaultId) {
  exactKeys(value, ['deviceId', 'envelope'], '本地库格式无效');
  if (!validId(value.deviceId)) throw new Error('本地设备标识无效');
  validateEnvelope(value.envelope, expectedVaultId);
  const text = JSON.stringify(value);
  if (Buffer.byteLength(text) > MAX_BYTES) throw new Error('密码库过大');
  return text;
}

async function readBounded(file) {
  const handle = await fs.open(file, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_BYTES) throw new Error('文件过大或格式无效');
    const chunks = []; let size = 0;
    while (true) {
      const buffer = Buffer.alloc(Math.min(65536, MAX_BYTES + 1 - size));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      size += bytesRead;
      if (size > MAX_BYTES) throw new Error('文件过大');
      chunks.push(buffer.subarray(0, bytesRead));
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } finally { await handle.close(); }
}

async function atomicWrite(file, text) {
  const temp = path.join(path.dirname(file), `.private-vault-${crypto.randomUUID()}.tmp`);
  let handle;
  try {
    handle = await fs.open(temp, 'wx', 0o600);
    await handle.writeFile(text, 'utf8'); await handle.sync(); await handle.close(); handle = null;
    await fs.rename(temp, file);
  } finally {
    if (handle) await handle.close();
    await fs.unlink(temp).catch(() => {});
  }
}

function decryptForMigration(envelope, profile) {
  try {
    const data = Buffer.from(envelope.data, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(profile.keyB64, 'base64'), Buffer.from(envelope.nonce, 'base64'));
    decipher.setAAD(Buffer.from('private-vault/v1/' + profile.vaultId));
    decipher.setAuthTag(data.subarray(-16));
    const text = Buffer.concat([decipher.update(data.subarray(0, -16)), decipher.final()]);
    const vault = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(text));
    if (vault.schema !== 1 || vault.vaultId !== profile.vaultId || !isObject(vault.records)) throw new Error();
    return vault;
  } catch { throw new Error('文件密钥无法验证现有密码库，已保留原数据'); }
}

function createHost({ config, dataDir, clipboard, shell, safeStorage, dialog, getWindow = () => undefined }) {
  const suppliedConfig = config === undefined ? null : validateConfig(config);
  const compatibilityStorage = suppliedConfig !== null && safeStorage === undefined;
  if (typeof dataDir !== 'string' || !dataDir.length) throw new Error('本地存储目录无效');
  const dataFile = path.join(dataDir, 'vault.json');
  const stateFile = path.join(dataDir, 'state.json');
  let writes = Promise.resolve(), loading = null, blockedWrites = false, profile = suppliedConfig, local = null;
  const clone = value => value === null ? null : structuredClone(value);
  function requireProtection() {
    if (!safeStorage?.isEncryptionAvailable?.() || safeStorage.getSelectedStorageBackend?.() === 'basic_text')
      throw new Error('系统密钥保护不可用，已停止保存；不会降级为明文配置');
  }
  async function load() {
    if (loading) return loading;
    loading = (async () => {
      try {
        if (!compatibilityStorage) {
          try {
            const state = JSON.parse(await readBounded(stateFile));
            exactKeys(state, ['v', 'protectedConfig', 'local'], '本地状态格式无效');
            if (state.v !== 1) throw new Error('本地状态版本无效');
            requireProtection();
            const encrypted = canonicalBase64(state.protectedConfig, 1, 32768, '本地配置保护格式无效');
            profile = validateConfig(JSON.parse(safeStorage.decryptString(encrypted)));
            validateLocal(state.local, profile.vaultId);
            local = clone(state.local);
            return;
          } catch (error) { if (error.code !== 'ENOENT') throw error; }
        }
        try {
          local = JSON.parse(await readBounded(dataFile));
          validateLocal(local, suppliedConfig?.vaultId);
          // An older installation has ciphertext, but no portable copy of its key.
          // Wait for an imported file instead of silently replacing that vault.
          profile = suppliedConfig;
          return;
        } catch (error) { if (error.code !== 'ENOENT') throw error; }
        local = null;
        if (!profile) {
          requireProtection();
          profile = validateConfig({ vaultId: crypto.randomUUID(), keyB64: crypto.randomBytes(32).toString('base64'),
            token: crypto.randomBytes(32).toString('base64url'), endpoint: null, mode: 'file' });
        }
      } catch (error) {
        blockedWrites = true;
        throw new Error('本地密码库无法读取，已停止以防覆盖数据');
      }
    })();
    return loading;
  }
  async function writeState(nextConfig, value) {
    if (blockedWrites) throw new Error('本地库已损坏，已停止写入以防覆盖数据');
    const nextProfile = validateConfig(nextConfig);
    const text = validateLocal(value, nextProfile.vaultId);
    await load();
    const nextLocal = JSON.parse(text);
    if (!compatibilityStorage) decryptForMigration(nextLocal.envelope, nextProfile);
    const job = writes.catch(() => {}).then(async () => {
      if (blockedWrites) throw new Error('本地库已损坏，已停止写入以防覆盖数据');
      if (local) {
        if (!profile) {
          if (nextProfile.vaultId !== local.envelope.vaultId) throw new Error('导入文件不属于现有密码库');
          decryptForMigration(local.envelope, nextProfile);
        } else if (profile.vaultId === nextProfile.vaultId) {
          if (profile.keyB64 !== nextProfile.keyB64) throw new Error('不能替换现有密码库的密钥');
        } else {
          const oldVault = decryptForMigration(local.envelope, profile);
          if (Object.keys(oldVault.records).length) throw new Error('已有记录，不能替换为另一个密码库');
        }
      }
      await fs.mkdir(dataDir, { recursive: true });
      if (compatibilityStorage) {
        if (JSON.stringify(nextProfile) !== JSON.stringify(profile)) throw new Error('系统密钥保护不可用，不能保存更改的配置');
        await atomicWrite(dataFile, text);
      } else {
        requireProtection();
        const protectedConfig = safeStorage.encryptString(JSON.stringify(nextProfile)).toString('base64');
        const stateText = JSON.stringify({ v: 1, protectedConfig, local: nextLocal });
        if (Buffer.byteLength(stateText) > MAX_BYTES) throw new Error('密码库过大');
        await atomicWrite(stateFile, stateText);
      }
      profile = nextProfile; local = clone(nextLocal);
    });
    writes = job;
    return job;
  }
  const host = {
    getConfig: async () => { await load(); return profile ? { ...profile, deviceLabel: 'Windows' } : null; },
    readLocal: async () => { await load(); return clone(local); },
    writeState,
    writeLocal: async value => {
      if (blockedWrites) throw new Error('本地库已损坏，已停止写入以防覆盖数据');
      await load();
      if (!profile) throw new Error('请先导入文件恢复现有密码库');
      return writeState(profile, value);
    },
    request: async (method, route, body) => {
      await load();
      if (!profile || profile.mode !== 'server') throw new Error('文件模式不进行云同步');
      if (!['GET', 'PUT'].includes(method) || route !== '/v1/vault') throw new Error('无效同步请求');
      if (method === 'GET' && body !== undefined) throw new Error('读取同步请求不能携带内容');
      if (method === 'PUT') {
        exactKeys(body, ['expectedRevision', 'envelope'], '同步写入格式无效');
        if (!Number.isSafeInteger(body.expectedRevision) || body.expectedRevision < 0) throw new Error('同步版本号无效');
        validateEnvelope(body.envelope, profile.vaultId);
      }
      if (!profile.endpoint) throw new Error('云同步未配置');
      const serialized = body === undefined ? undefined : JSON.stringify(body);
      if (serialized && Buffer.byteLength(serialized) > MAX_BYTES) throw new Error('同步请求过大');
      const response = await fetch(new URL(route, profile.endpoint), {
        method, headers: { Authorization: `Bearer ${profile.token}`, 'Content-Type': 'application/json' },
        body: serialized, redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      if (Number(response.headers.get('content-length')) > MAX_BYTES) {
        await response.body?.cancel().catch(() => {});
        throw new Error('同步响应过大');
      }
      const reader = response.body?.getReader();
      let size = 0;
      const chunks = [];
      if (reader) {
        while (true) {
          const next = await reader.read();
          if (next.done) break;
          size += next.value.length;
          if (size > MAX_BYTES) { await reader.cancel(); throw new Error('同步响应过大'); }
          chunks.push(Buffer.from(next.value));
        }
      }
      const text = Buffer.concat(chunks).toString('utf8');
      let parsed;
      try { parsed = text ? JSON.parse(text) : {}; } catch { throw new Error('同步服务器返回无效内容'); }
      return { status: response.status, body: parsed };
    },
    copyText: async text => {
      if (typeof text !== 'string' || text.length > 20000) throw new Error('复制内容无效');
      clipboard.writeText(text);
    },
    openExternal: async value => {
      if (typeof value !== 'string' || !value.length || value.length > 2048) throw new Error('链接无效');
      let url;
      try { url = new URL(value); } catch { throw new Error('链接无效'); }
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('链接无效');
      await shell.openExternal(url.href);
    },
    chooseImportFile: async () => {
      if (!dialog?.showOpenDialog) throw new Error('文件选择暂不可用');
      const options = { title: '导入密码库文件', properties: ['openFile'], filters: [
        { name: '密码库文件', extensions: ['pvault', 'json'] }, { name: '所有文件', extensions: ['*'] },
      ] };
      const parent = getWindow();
      const result = parent ? await dialog.showOpenDialog(parent, options) : await dialog.showOpenDialog(options);
      if (result.canceled || !result.filePaths?.length) return null;
      if (result.filePaths.length !== 1) throw new Error('请选择一个密码库文件');
      return readBounded(result.filePaths[0]);
    },
    saveExportFile: async text => {
      if (typeof text !== 'string' || !text.length || Buffer.byteLength(text, 'utf8') > MAX_BYTES) throw new Error('导出文件格式或大小无效');
      if (!dialog?.showSaveDialog) throw new Error('文件保存暂不可用');
      const options = { title: '导出密码库文件', defaultPath: 'PrivateVault.pvault', filters: [{ name: '密码库文件', extensions: ['pvault', 'json'] }] };
      const parent = getWindow();
      const result = parent ? await dialog.showSaveDialog(parent, options) : await dialog.showSaveDialog(options);
      if (result.canceled || !result.filePath) return false;
      const target = path.resolve(result.filePath);
      const canonicalDir = await fs.realpath(dataDir).catch(() => path.resolve(dataDir));
      const targetDir = await fs.realpath(path.dirname(target));
      const canonicalTarget = path.join(targetDir, path.basename(target));
      const storagePrefix = canonicalDir.toLowerCase() + path.sep;
      if (canonicalTarget.toLowerCase() === canonicalDir.toLowerCase() || canonicalTarget.toLowerCase().startsWith(storagePrefix))
        throw new Error('不能将导出文件保存到应用内部数据目录');
      await atomicWrite(target, text);
      return true;
    },
  };
  return host;
}

module.exports = { createHost, validateLocal, validateConfig };
