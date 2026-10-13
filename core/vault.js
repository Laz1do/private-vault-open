/** Shared client core. Password contents never cross the Host network boundary. */
const MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES = MAX_CIPHERTEXT_BYTES - 16;
const MAX_RECORDS = 5000;
const MAX_HEADS = 32;
const MAX_ANCESTORS = 20000;
const FIELD_LIMITS = Object.freeze({ title: 200, username: 1000, password: 4096, url: 2048, notes: 16384 });
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const ID_PATTERN = /^[A-Za-z0-9_-]{1,80}$/;

export class VaultError extends Error {
  constructor(code, message) { super(message); this.name = 'VaultError'; this.code = code; }
}

function fail(code, message) { throw new VaultError(code, message); }
function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function exactKeys(value, keys, code) {
  if (!isObject(value) || Object.keys(value).length !== keys.length || keys.some(k => !Object.hasOwn(value, k)))
    fail(code, '数据格式无效。');
}
function validId(value, code = 'invalid_vault') {
  if (typeof value !== 'string' || !ID_PATTERN.test(value) || ['__proto__', 'prototype', 'constructor'].includes(value))
    fail(code, '数据标识无效。');
  return value;
}
function randomId() { return globalThis.crypto.randomUUID(); }
function checkedEntry(value) {
  exactKeys(value, Object.keys(FIELD_LIMITS), 'invalid_entry');
  const result = {};
  for (const [name, limit] of Object.entries(FIELD_LIMITS)) {
    if (typeof value[name] !== 'string' || value[name].length > limit) fail('invalid_entry', '记录字段为空或超出长度限制。');
    result[name] = value[name];
  }
  if (!result.title.trim()) fail('invalid_entry', '请填写记录名称。');
  return result;
}

/** Strict validation also returns a detached, canonical representation. */
function checkedVault(value) {
  exactKeys(value, ['schema', 'vaultId', 'records'], 'invalid_vault');
  if (value.schema !== 1 || !isObject(value.records)) fail('invalid_vault', '密码库格式无效。');
  validId(value.vaultId);
  const recordIds = Object.keys(value.records).sort();
  if (recordIds.length > MAX_RECORDS) fail('vault_too_large', '密码库记录数量超出限制。');
  const records = {};
  const allIds = new Map();
  for (const recordId of recordIds) {
    validId(recordId);
    const heads = value.records[recordId];
    if (!Array.isArray(heads) || heads.length < 1 || heads.length > MAX_HEADS) fail('invalid_vault', '记录版本数量无效。');
    const versions = heads.map(v => {
      exactKeys(v, ['id', 'ancestors', 'kind', 'entry', 'deviceId', 'updatedAt'], 'invalid_vault');
      validId(v.id); validId(v.deviceId);
      if (allIds.has(v.id)) fail('invalid_vault', '密码库包含重复版本标识。');
      allIds.set(v.id, recordId);
      if (!Array.isArray(v.ancestors) || v.ancestors.length > MAX_ANCESTORS) fail('invalid_vault', '因果版本标识无效。');
      const ancestors = v.ancestors.map(id => validId(id));
      if (new Set(ancestors).size !== ancestors.length || ancestors.includes(v.id)) fail('invalid_vault', '因果版本标识无效。');
      if (!['put', 'delete'].includes(v.kind) || (v.kind === 'delete' && v.entry !== null)) fail('invalid_vault', '记录版本类型无效。');
      if (typeof v.updatedAt !== 'string' || v.updatedAt.length !== 24 || !Number.isFinite(Date.parse(v.updatedAt))
        || new Date(v.updatedAt).toISOString() !== v.updatedAt) fail('invalid_vault', '记录时间格式无效。');
      let entry = null;
      if (v.kind === 'put') {
        try { entry = checkedEntry(v.entry); } catch { fail('invalid_vault', '密码库记录字段无效。'); }
      }
      return { id: v.id, ancestors: ancestors.sort(), kind: v.kind, entry,
        deviceId: v.deviceId, updatedAt: v.updatedAt };
    }).sort((a, b) => a.id.localeCompare(b.id));
    for (let i = 0; i < versions.length; i++) for (let j = i + 1; j < versions.length; j++) {
      const a = versions[i], b = versions[j];
      const aAncestors = new Set(a.ancestors), bAncestors = new Set(b.ancestors);
      if ((aAncestors.has(b.id) && (bAncestors.has(a.id) || b.ancestors.some(id => !aAncestors.has(id))))
        || (bAncestors.has(a.id) && a.ancestors.some(id => !bAncestors.has(id))))
        fail('invalid_vault', '因果版本关系存在循环或缺少前驱。');
    }
    records[recordId] = versions;
  }
  for (const [recordId, heads] of Object.entries(records)) for (const head of heads) {
    if (head.ancestors.some(id => allIds.has(id) && allIds.get(id) !== recordId))
      fail('invalid_vault', '因果版本标识属于其他记录。');
  }
  return { schema: 1, vaultId: value.vaultId, records };
}

function canonical(vault) { return JSON.stringify(checkedVault(vault)); }
function ancestorsOf(heads) {
  const result = new Set();
  for (const head of heads) { result.add(head.id); for (const ancestor of head.ancestors) result.add(ancestor); }
  if (result.size > MAX_ANCESTORS) fail('vault_too_large', '记录的修改次数已达到限制。');
  return [...result].sort();
}
function newVersion(heads, entry, deviceId) {
  validId(deviceId);
  return { id: randomId(), ancestors: ancestorsOf(heads), kind: entry === null ? 'delete' : 'put',
    entry, deviceId, updatedAt: new Date().toISOString() };
}

export function createVault(vaultId) { return { schema: 1, vaultId: validId(vaultId), records: {} }; }

export function mergeVaults(a, b) {
  const left = checkedVault(a), right = checkedVault(b);
  if (left.vaultId !== right.vaultId) fail('invalid_vault', '不能合并不同密码库。');
  const merged = createVault(left.vaultId);
  for (const recordId of new Set([...Object.keys(left.records), ...Object.keys(right.records)])) {
    const versions = new Map();
    for (const version of [...(left.records[recordId] || []), ...(right.records[recordId] || [])]) {
      if (versions.has(version.id) && JSON.stringify(versions.get(version.id)) !== JSON.stringify(version))
        fail('invalid_vault', '同一版本标识对应不同内容。');
      versions.set(version.id, version);
    }
    const heads = [...versions.values()];
    for (const head of heads) for (const other of heads) {
      if (head.id !== other.id && head.ancestors.includes(other.id)) {
        if (other.ancestors.includes(head.id) || other.ancestors.some(id => !head.ancestors.includes(id)))
          fail('invalid_vault', '因果版本关系无效。');
      }
    }
    const superseded = new Set(heads.flatMap(h => h.ancestors));
    merged.records[recordId] = heads.filter(h => !superseded.has(h.id));
  }
  return checkedVault(merged);
}

export function listRecords(vault) {
  const normalized = checkedVault(vault);
  return Object.entries(normalized.records)
    .filter(([, versions]) => !(versions.length === 1 && versions[0].kind === 'delete'))
    .map(([id, versions]) => ({ id, versions, conflict: versions.length > 1,
      entry: versions.find(v => v.kind === 'put')?.entry ?? null, deleted: versions.every(v => v.kind === 'delete') }))
    .sort((a, b) => (a.entry?.title ?? '').localeCompare(b.entry?.title ?? '') || a.id.localeCompare(b.id));
}

export function writeRecord(vault, recordId, entry, deviceId) {
  const result = checkedVault(vault), normalizedEntry = checkedEntry(entry);
  const id = recordId == null ? randomId() : validId(recordId);
  const heads = result.records[id] || [];
  if (recordId != null && (!heads.length || (heads.length === 1 && heads[0].kind === 'delete')))
    fail('record_not_found', '记录不存在。');
  if (heads.length > 1) fail('conflict_requires_resolution', '请先选择要保留的冲突版本。');
  result.records[id] = [newVersion(heads, normalizedEntry, deviceId)];
  return checkedVault(result);
}

export function deleteRecord(vault, recordId, deviceId) {
  const result = checkedVault(vault), heads = result.records[validId(recordId)];
  if (!heads) fail('record_not_found', '记录不存在。');
  if (heads.length > 1) fail('conflict_requires_resolution', '请先处理冲突。');
  if (heads[0].kind === 'delete') return result;
  result.records[recordId] = [newVersion(heads, null, deviceId)];
  return checkedVault(result);
}

export function resolveRecord(vault, recordId, versionId, deviceId) {
  const result = checkedVault(vault), heads = result.records[validId(recordId)];
  validId(versionId);
  if (!heads) fail('record_not_found', '记录不存在。');
  const chosen = heads.find(v => v.id === versionId);
  if (!chosen) fail('record_not_found', '所选版本已不存在，请重新查看。');
  if (heads.length < 2) fail('conflict_requires_resolution', '记录没有需要处理的冲突。');
  result.records[recordId] = [newVersion(heads, chosen.entry, deviceId)];
  return checkedVault(result);
}

function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}
function fromBase64(value, maxBytes, code) {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes / 3) * 4 || value.length % 4 !== 0
    || !/^[A-Za-z0-9+/]*={0,2}$/.test(value))
    fail(code, '加密数据格式无效。');
  let bytes;
  try { bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0)); } catch { fail(code, '加密数据格式无效。'); }
  if (bytes.length > maxBytes || toBase64(bytes) !== value) fail(code, '加密数据格式无效。');
  return bytes;
}
async function importKey(keyB64) {
  const bytes = fromBase64(keyB64, 32, 'invalid_config');
  if (bytes.length !== 32) fail('invalid_config', '安装包的密钥配置无效。');
  return globalThis.crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
function checkedEnvelope(value, expectedVaultId) {
  exactKeys(value, ['v', 'vaultId', 'alg', 'nonce', 'data'], 'invalid_envelope');
  validId(value.vaultId, 'invalid_envelope');
  if (value.v !== 1 || value.alg !== 'A256GCM' || value.vaultId !== expectedVaultId) fail('invalid_envelope', '加密密码库标识或格式不匹配。');
  const nonce = fromBase64(value.nonce, 12, 'invalid_envelope');
  const data = fromBase64(value.data, MAX_CIPHERTEXT_BYTES, 'invalid_envelope');
  if (nonce.length !== 12 || data.length < 16) fail('invalid_envelope', '加密数据长度无效。');
  return { nonce, data };
}

export async function encryptVault(vault, keyB64) {
  const normalized = checkedVault(vault), plaintext = encoder.encode(JSON.stringify(normalized));
  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) fail('vault_too_large', '密码库超过 4 MiB 同步限制，请缩短备注或减少记录。');
  const key = await importKey(keyB64), nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
    additionalData: encoder.encode(`private-vault/v1/${normalized.vaultId}`), tagLength: 128 }, key, plaintext);
  return { v: 1, vaultId: normalized.vaultId, alg: 'A256GCM', nonce: toBase64(nonce), data: toBase64(new Uint8Array(encrypted)) };
}

export async function decryptVault(envelope, keyB64, expectedVaultId) {
  validId(expectedVaultId, 'invalid_config');
  const { nonce, data } = checkedEnvelope(envelope, expectedVaultId), key = await importKey(keyB64);
  let plaintext;
  try { plaintext = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce,
    additionalData: encoder.encode(`private-vault/v1/${expectedVaultId}`), tagLength: 128 }, key, data); }
  catch { fail('decrypt_failed', '密码库验证失败，密钥不匹配或文件已损坏。'); }
  let parsed;
  try { parsed = JSON.parse(decoder.decode(plaintext)); } catch { fail('invalid_vault', '解密后的密码库格式无效。'); }
  const result = checkedVault(parsed);
  if (result.vaultId !== expectedVaultId) fail('invalid_vault', '解密后的密码库标识不匹配。');
  return result;
}

function checkedConfig(config, strict = false) {
  if (!isObject(config)) fail('invalid_config', '密码库配置无效。');
  validId(config.vaultId, 'invalid_config');
  const key = fromBase64(config.keyB64, 32, 'invalid_config');
  if (key.length !== 32) fail('invalid_config', '密码库密钥配置无效。');
  const legacy = !Object.hasOwn(config, 'mode');
  const mode = legacy ? 'server' : config.mode;
  if (!['file', 'server'].includes(mode) || typeof config.token !== 'string'
    || ((strict || !legacy) ? !/^[A-Za-z0-9_-]{20,200}$/.test(config.token) : config.token.length > 4096))
    fail('invalid_config', '密码库或服务器配置无效。');
  let endpoint = null;
  if (config.endpoint !== null && config.endpoint !== undefined && config.endpoint !== '') {
    if (typeof config.endpoint !== 'string' || config.endpoint.length > 2048 || !config.token.length) fail('invalid_config', '同步配置无效。');
    let url;
    try { url = new URL(config.endpoint); } catch { fail('invalid_config', '同步地址无效。'); }
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || (url.protocol !== 'https:'
      && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))))
      fail('invalid_config', '公网同步地址必须是 HTTPS 根地址。');
    endpoint = url.origin;
  } else if (strict && config.endpoint !== null) fail('invalid_config', '同步地址格式无效。');
  return { vaultId: config.vaultId, keyB64: config.keyB64, token: config.token, endpoint, mode };
}

function newProfile() {
  return { vaultId: randomId(), keyB64: toBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))),
    token: toBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    endpoint: null, mode: 'file' };
}

/** Portable files deliberately contain plaintext passwords AND connection credentials. */
export function parsePortableFile(text) {
  try {
    if (typeof text !== 'string' || !text.length || encoder.encode(text).byteLength > 8 * 1024 * 1024)
      fail('invalid_file', '密码库文件为空或超过 8 MiB。');
    const file = JSON.parse(text);
    exactKeys(file, ['format', 'version', 'profile', 'vault'], 'invalid_file');
    if (file.format !== 'private-vault-file' || file.version !== 1) fail('invalid_file', '密码库文件版本无效。');
    exactKeys(file.profile, ['vaultId', 'keyB64', 'token', 'endpoint'], 'invalid_file');
    const { mode: _, ...profile } = checkedConfig({ ...file.profile, mode: 'file' }, true);
    const vault = checkedVault(file.vault);
    if (vault.vaultId !== profile.vaultId || encoder.encode(JSON.stringify(vault)).byteLength > MAX_PLAINTEXT_BYTES)
      fail('invalid_file', '密码库标识或大小无效。');
    return { format: 'private-vault-file', version: 1, profile, vault };
  } catch {
    fail('invalid_file', '无法读取无密码密码库文件，请选择本软件导出的完整 JSON 文件。');
  }
}

/** Edits and remote merges share one disk queue; network waits never lock editing. */
export async function createVaultClient(host) {
  if (!host || ['getConfig', 'readLocal', 'writeLocal', 'request'].some(name => typeof host[name] !== 'function'))
    fail('invalid_config', '本地存储桥接不可用。');
  const initialProfile = await host.getConfig();
  let config = initialProfile === null ? null : checkedConfig(initialProfile);
  const local = await host.readLocal();
  let deviceId, vault, storedEnvelope, needsImport = config === null && local !== null;
  const originalConfig = config ? JSON.stringify(config) : null;
  async function writeState(nextConfig, envelope) {
    const nextLocal = { deviceId, envelope };
    if (typeof host.writeState === 'function') await host.writeState({ ...nextConfig }, nextLocal);
    else if (originalConfig !== null && JSON.stringify(nextConfig) === originalConfig) await host.writeLocal(nextLocal);
    else fail('invalid_config', '此客户端无法原子保存密码库配置，请更新软件。');
  }
  if (local === null) {
    config ??= newProfile();
    await importKey(config.keyB64);
    deviceId = randomId(); vault = createVault(config.vaultId);
    storedEnvelope = await encryptVault(vault, config.keyB64);
    try { await writeState(config, storedEnvelope); } catch { fail('persistence_failed', '无法创建本地密码库，请检查存储权限。'); }
  } else {
    exactKeys(local, ['deviceId', 'envelope'], 'invalid_vault');
    deviceId = validId(local.deviceId);
    if (needsImport) {
      checkedEnvelope(local.envelope, local.envelope?.vaultId);
      vault = null;
    } else {
      await importKey(config.keyB64);
      vault = await decryptVault(local.envelope, config.keyB64, config.vaultId);
    }
    storedEnvelope = { ...local.envelope };
  }
  const configured = () => !needsImport && config.mode === 'server' && config.endpoint !== null;
  const localMessage = () => config?.mode === 'file' ? '文件模式：修改保存在本机，导出文件后由你手动传递。' : '云同步未配置。';
  let status = needsImport ? 'error' : 'local';
  let message = needsImport ? '发现旧密码库，请导入含原密钥的配套文件以恢复；原数据没有被覆盖。' : configured() ? '本地密码库已就绪。' : localMessage();
  let pending = !needsImport && local !== null, lastSync = null, generation = 0, needsPersist = false;
  let localQueue = Promise.resolve(), syncing = null, profileChanges = 0, changingVault = false;
  const pendingProfileChanges = new Set();
  const listeners = new Set();
  const snapshot = () => ({ records: vault ? listRecords(vault) : [], status, message, lastSync, configured: configured(), pending,
    mode: config?.mode ?? 'file', serverEndpoint: config?.endpoint ?? null,
    vaultId: config?.vaultId ?? storedEnvelope.vaultId, needsImport, changingVault,
    hasHistory: vault ? Object.keys(vault.records).length > 0 : needsImport });
  const emit = () => { for (const listener of listeners) { try { listener(snapshot()); } catch { /* A view cannot break persistence. */ } } };
  function serialized(fn) {
    const work = localQueue.then(fn);
    localQueue = work.catch(() => {});
    return work;
  }
  async function persist(envelope) {
    needsPersist = true;
    try { await writeState(config, envelope); storedEnvelope = envelope; needsPersist = false; }
    catch { fail('persistence_failed', '本地保存失败，修改仍保留在当前会话；请重试同步。'); }
  }
  function requireReady() { if (needsImport) fail('needs_import', '请先导入配套密码库文件恢复原数据。'); }
  function requireMutable() { if (changingVault) fail('vault_changing', '正在备份并新建密码库，请等待完成。'); }
  async function edit(operation) {
    requireMutable();
    let result;
    try {
      result = await serialized(async () => {
        requireReady();
        const { next, value } = operation(vault);
        // Validate and enforce the server size budget before adopting any new state.
        const envelope = await encryptVault(next, config.keyB64);
        vault = next; generation++; pending = true; status = syncing ? 'syncing' : 'local';
        message = configured() ? '修改已保留，正在保存。' : localMessage(); emit();
        await persist(envelope); emit();
        return value;
      });
    } catch (error) {
      if (error.code === 'persistence_failed') { status = 'error'; message = error.message; emit(); }
      throw error;
    }
    if (configured() && !profileChanges) void sync();
    return result;
  }
  function sync() {
    if (syncing) return syncing;
    if (needsImport || profileChanges || changingVault) return Promise.resolve(snapshot());
    // Install the in-flight promise before notifying listeners (which may call sync).
    syncing = Promise.resolve().then(runSync).finally(() => { syncing = null; });
    return syncing;
  }
  async function runSync() {
    if (!configured()) {
      try { await serialized(async () => { if (needsPersist) await persist(await encryptVault(vault, config.keyB64)); });
        status = 'local'; message = localMessage(); }
      catch { status = 'error'; message = '本地保存失败，修改仍保留在当前会话；请重试同步。'; }
      emit(); return snapshot();
    }
    status = 'syncing'; message = '正在同步…'; emit();
    try {
      for (let attempt = 0; attempt < 8; attempt++) {
        await serialized(async () => { if (needsPersist) await persist(await encryptVault(vault, config.keyB64)); });
        const response = await host.request('GET', '/v1/vault');
        if (response?.status !== 200) throw httpError(response?.status);
        const body = response.body;
        exactKeys(body, ['revision', 'envelope'], 'invalid_envelope');
        if (!Number.isSafeInteger(body.revision) || body.revision < 0) fail('invalid_envelope', '云端版本号无效。');
        const remote = body.envelope === null ? createVault(config.vaultId) : await decryptVault(body.envelope, config.keyB64, config.vaultId);
        const remoteFingerprint = canonical(remote);
        const outgoing = await serialized(async () => {
          const merged = mergeVaults(vault, remote), fingerprint = canonical(merged);
          if (fingerprint !== canonical(vault)) {
            const envelope = await encryptVault(merged, config.keyB64);
            vault = merged; generation++; pending = true; emit(); await persist(envelope);
          } else if (needsPersist) await persist(await encryptVault(vault, config.keyB64));
          return { generation, fingerprint, envelope: { ...storedEnvelope } };
        });
        if (outgoing.fingerprint !== remoteFingerprint) {
          const uploaded = await host.request('PUT', '/v1/vault', { expectedRevision: body.revision, envelope: outgoing.envelope });
          if (uploaded?.status === 409) continue;
          if (uploaded?.status !== 200) throw httpError(uploaded?.status);
          if (!isObject(uploaded.body) || !Number.isSafeInteger(uploaded.body.revision) || uploaded.body.revision !== body.revision + 1)
            fail('invalid_envelope', '云端同步响应无效。');
        }
        const finished = await serialized(async () => {
          if (generation !== outgoing.generation || needsPersist) return false;
          pending = false; status = 'synced'; lastSync = new Date().toISOString();
          message = listRecords(vault).some(record => record.conflict) ? '同步完成，有冲突需要选择。' : '所有修改已同步。';
          emit(); return true;
        });
        if (finished) return snapshot();
      }
      status = 'offline'; message = '同步期间出现多次并发修改，修改已保留，请稍后重试。'; emit();
    } catch (error) {
      if (['invalid_envelope', 'invalid_vault', 'decrypt_failed', 'vault_too_large'].includes(error.code)) {
        status = 'error'; message = '云端密码库无法验证或合并，已保留本地记录。';
      } else if (error.code === 'persistence_failed') { status = 'error'; message = error.message; }
      else if (error.code === 'unauthorized') { status = 'error'; message = '同步凭据无效，请检查服务器连接设置。'; }
      else { status = 'offline'; message = '暂时无法连接同步服务器，修改已保留在本地。'; }
      emit();
    }
    return snapshot();
  }
  async function changeProfile(operation) {
    requireMutable();
    profileChanges++;
    const work = (async () => {
      let completed = false;
      try {
        if (syncing) await syncing;
        const result = await serialized(operation);
        completed = true;
        return result;
      } catch (error) {
        if (error.code === 'persistence_failed') { status = 'error'; message = error.message; emit(); }
        throw error;
      } finally {
        profileChanges--;
        if (completed && !profileChanges && !changingVault && configured()) void sync();
      }
    })();
    pendingProfileChanges.add(work);
    // Attach cleanup without an unobserved rejected promise.
    work.then(() => pendingProfileChanges.delete(work), () => pendingProfileChanges.delete(work));
    return work;
  }
  function portableText() {
    const { mode: _, ...profile } = config;
    const text = JSON.stringify({ format: 'private-vault-file', version: 1, profile, vault: checkedVault(vault) });
    parsePortableFile(text);
    return text;
  }
  async function exportAndCreateNew() {
    requireMutable(); requireReady();
    if (typeof host.backupAndReplace !== 'function') fail('invalid_config', '此客户端暂不支持备份后新建密码库，请更新软件。');
    // Reserve the whole transaction immediately, before waiting on prior work.
    // Already accepted edits/profile changes finish into the old-vault backup.
    changingVault = true; profileChanges++; emit();
    try {
      await Promise.allSettled([...(syncing ? [syncing] : []), ...pendingProfileChanges]);
      const created = await serialized(async () => {
        requireReady();
        const text = portableText(), nextConfig = newProfile(), nextVault = createVault(nextConfig.vaultId);
        const envelope = await encryptVault(nextVault, nextConfig.keyB64);
        const replaced = await host.backupAndReplace(text, { ...nextConfig }, { deviceId, envelope });
        if (replaced === false) return false;
        if (replaced !== true) fail('persistence_failed', '新建结果无法确认，原密码库仍保留在当前会话。');
        config = nextConfig; vault = nextVault; storedEnvelope = envelope;
        needsImport = false; needsPersist = false; generation++; pending = false; status = 'local'; lastSync = null;
        message = '已备份原密码库并创建新的独立密码库。';
        return true;
      });
      return { ...snapshot(), changingVault: false, created };
    } finally {
      changingVault = false; profileChanges--; emit();
    }
  }
  async function adopt(nextConfig, nextVault) {
    const envelope = await encryptVault(nextVault, nextConfig.keyB64);
    try { await writeState(nextConfig, envelope); }
    catch { fail('persistence_failed', '配置或导入保存失败，原密码库和设置没有被替换，请重试。'); }
    config = nextConfig; vault = nextVault; storedEnvelope = envelope;
    needsImport = false; needsPersist = false; generation++; pending = true; status = 'local'; lastSync = null;
    message = configured() ? '已保存到本机，正在准备同步。' : localMessage(); emit();
    return snapshot();
  }
  return Object.freeze({ snapshot,
    subscribe(fn) { if (typeof fn !== 'function') fail('invalid_config', '订阅函数无效。'); listeners.add(fn); try { fn(snapshot()); } catch {} return () => listeners.delete(fn); },
    save(entry, recordId = null, expectedStamp = undefined, expectedVaultId = undefined) { return edit(current => {
      // A browser's new-record draft has no record ID to detect a queued
      // library switch. Validate its originating library inside the disk queue.
      if (expectedVaultId !== undefined) {
        validId(expectedVaultId, 'invalid_config');
        if (current.vaultId !== expectedVaultId) fail('stale_vault', '密码库已切换，请重新检查内容后保存。');
      }
      // Check inside the disk queue: a remote/file merge may already be queued
      // when the view submits a draft of the version it originally displayed.
      if (expectedStamp !== undefined) {
        if (recordId === null || typeof expectedStamp !== 'string' || expectedStamp.length > MAX_HEADS * 81)
          fail('invalid_config', '编辑版本标识无效。');
        const currentStamp = current.records[validId(recordId)]?.map(version => version.id).sort().join('|') ?? '';
        if (currentStamp !== expectedStamp) fail('stale_record', '这条记录已更新，请重新查看最新版本后编辑。');
      }
      const next = writeRecord(current, recordId, entry, deviceId);
      const id = recordId ?? Object.keys(next.records).find(id => !Object.hasOwn(current.records, id));
      return { next, value: id };
    }); },
    async remove(recordId) { await edit(current => ({ next: deleteRecord(current, recordId, deviceId) })); return snapshot(); },
    async resolve(recordId, versionId) { await edit(current => ({ next: resolveRecord(current, recordId, versionId, deviceId) })); return snapshot(); },
    sync,
    exportAndCreateNew,
    async exportFile() { requireMutable(); return serialized(async () => {
      requireReady();
      return portableText();
    }); },
    async importFile(text) {
      requireMutable();
      const file = parsePortableFile(text);
      return changeProfile(async () => {
        let nextVault;
        if (needsImport) {
          if (file.profile.vaultId !== storedEnvelope.vaultId) fail('different_vault', '此文件属于另一个密码库，原数据没有被替换。');
          let oldVault;
          try { oldVault = await decryptVault(storedEnvelope, file.profile.keyB64, file.profile.vaultId); }
          catch { fail('different_key', '此文件不能解密旧密码库，可能密钥不匹配或旧库已损坏；原数据没有被替换。'); }
          nextVault = mergeVaults(oldVault, file.vault);
        } else if (file.profile.vaultId !== config.vaultId) {
          if (Object.keys(vault.records).length) fail('different_vault', '此设备已有密码记录或删除标记，不能导入另一个密码库。');
          nextVault = file.vault;
        } else {
          if (file.profile.keyB64 !== config.keyB64) fail('different_key', '库标识相同但密钥不同，原数据没有被替换。');
          nextVault = mergeVaults(vault, file.vault);
        }
        return adopt({ ...file.profile, mode: config?.mode ?? 'file' }, nextVault);
      });
    },
    setMode(mode) { return changeProfile(async () => {
      requireReady();
      if (!['file', 'server'].includes(mode)) fail('invalid_config', '请选择文件模式或服务器模式。');
      if (mode === 'server' && config.endpoint === null) fail('server_not_configured', '请先配置服务器地址和连接凭据。');
      if (mode === config.mode && !needsPersist) return snapshot();
      return adopt({ ...config, mode }, vault);
    }); },
    configureServer(value) { return changeProfile(async () => {
      requireReady();
      exactKeys(value, ['endpoint', 'token'], 'invalid_config');
      if (value.endpoint === null) fail('invalid_config', '请填写 HTTPS 服务器根地址。');
      const nextConfig = checkedConfig({ ...config, endpoint: value.endpoint, token: value.token }, true);
      return adopt(nextConfig, vault);
    }); } });
}

function httpError(status) {
  return new VaultError(status === 401 || status === 403 ? 'unauthorized' : 'network_failed', '同步请求失败。');
}
