const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { createHost } = require('../host.cjs');
const core = import('../../core/vault.js');

// Mock only the OS crypto boundary; fixtures never use the user's DPAPI/profile.
function protectedStorage() {
  const key = crypto.randomBytes(32);
  return {
    isEncryptionAvailable: () => true,
    encryptString(value) { const nonce = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce); return Buffer.concat([nonce, cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]); },
    decryptString(value) { const decipher = crypto.createDecipheriv('aes-256-gcm', key, value.subarray(0, 12)); decipher.setAuthTag(value.subarray(-16)); return Buffer.concat([decipher.update(value.subarray(12, -16)), decipher.final()]).toString('utf8'); },
  };
}
async function fixture(t, extra = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'private-vault-generic-test-'));
  const dataDir = path.join(root, 'app'); await fs.mkdir(dataDir);
  const safeStorage = protectedStorage();
  const options = { dataDir, safeStorage, clipboard: {}, shell: {}, ...extra };
  t.after(async () => {
    if (!path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep + 'private-vault-generic-test-')) throw new Error('Unsafe test cleanup');
    await fs.rm(root, { recursive: true, force: true });
  });
  return { root, dataDir, options, host: createHost(options) };
}
async function localFor(profile, password = '') {
  const { createVault, writeRecord, encryptVault } = await core;
  let vault = createVault(profile.vaultId);
  if (password) vault = writeRecord(vault, null, { title: 'Test', username: '', password, url: '', notes: '' }, 'test-device');
  return { deviceId: 'test-device', envelope: await encryptVault(vault, profile.keyB64) };
}

test('fresh generic installs generate file profiles and persist key/profile+envelope atomically under OS protection', async t => {
  const { host, dataDir, options } = await fixture(t);
  const exposed = await host.getConfig();
  assert.equal(exposed.mode, 'file'); assert.equal(exposed.endpoint, null);
  assert.equal(Buffer.from(exposed.keyB64, 'base64').length, 32);
  assert.match(exposed.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(await host.readLocal(), null);
  assert.deepEqual(await fs.readdir(dataDir), [], 'getConfig alone must not write/create a vault');
  const { deviceLabel, ...profile } = exposed;
  const local = await localFor(profile, 'profile-test-secret');
  await host.writeState(profile, local);
  const raw = await fs.readFile(path.join(dataDir, 'state.json'), 'utf8');
  for (const secret of [profile.keyB64, profile.token, 'profile-test-secret']) assert.ok(!raw.includes(secret));
  assert.deepEqual(await fs.readdir(dataDir), ['state.json']);
  const reopened = createHost(options);
  assert.deepEqual(await reopened.getConfig(), exposed); assert.deepEqual(await reopened.readLocal(), local);
});

test('generic installs refuse unavailable or plaintext OS protection without writing a fallback key', async t => {
  for (const safeStorage of [undefined, { isEncryptionAvailable: () => false }, { isEncryptionAvailable: () => true, getSelectedStorageBackend: () => 'basic_text' }]) {
    const { host, dataDir } = await fixture(t, { safeStorage });
    await assert.rejects(host.getConfig()); assert.deepEqual(await fs.readdir(dataDir), []);
  }
});

test('failed atomic state replacement keeps the former profile and former vault together', async t => {
  const { host, dataDir } = await fixture(t);
  const { deviceLabel, ...profile } = await host.getConfig();
  const before = await localFor(profile, 'before'); await host.writeState(profile, before);
  const original = await fs.readFile(path.join(dataDir, 'state.json'), 'utf8');
  const rename = fs.rename;
  fs.rename = async (from, to) => { if (to === path.join(dataDir, 'state.json')) throw Object.assign(new Error('fixture failure'), { code: 'EIO' }); return rename(from, to); };
  try { await assert.rejects(host.writeState({ ...profile, mode: 'server', endpoint: 'https://example.com' }, await localFor(profile, 'after'))); }
  finally { fs.rename = rename; }
  assert.equal((await host.getConfig()).mode, 'file'); assert.deepEqual(await host.readLocal(), before);
  assert.equal(await fs.readFile(path.join(dataDir, 'state.json'), 'utf8'), original);
  assert.deepEqual(await fs.readdir(dataDir), ['state.json']);
});

test('legacy ciphertext waits for an import and is only migrated after its old key verifies it', async t => {
  const { dataDir, options } = await fixture(t);
  const profile = { vaultId: 'legacy-test-vault', keyB64: crypto.randomBytes(32).toString('base64'), token: crypto.randomBytes(32).toString('base64url'), endpoint: null, mode: 'file' };
  const local = await localFor(profile, 'legacy-password'); const legacyText = JSON.stringify(local);
  await fs.writeFile(path.join(dataDir, 'vault.json'), legacyText);
  const host = createHost(options);
  assert.equal(await host.getConfig(), null); assert.deepEqual(await host.readLocal(), local);
  await assert.rejects(host.writeLocal(local));
  const wrongKey = { ...profile, keyB64: crypto.randomBytes(32).toString('base64') };
  await assert.rejects(host.writeState(wrongKey, await localFor(wrongKey)));
  assert.equal(await fs.readFile(path.join(dataDir, 'vault.json'), 'utf8'), legacyText);
  assert.deepEqual(await fs.readdir(dataDir), ['vault.json']);
  await host.writeState(profile, local);
  assert.equal((await host.getConfig()).vaultId, profile.vaultId);
  assert.equal(await fs.readFile(path.join(dataDir, 'vault.json'), 'utf8'), legacyText, 'migration never deletes or rewrites legacy ciphertext');
  assert.deepEqual((await fs.readdir(dataDir)).sort(), ['state.json', 'vault.json']);
});

test('corrupt protected state and mismatched envelope prevent writes and preserve original bytes', async t => {
  const { host, dataDir, options } = await fixture(t);
  const { deviceLabel, ...profile } = await host.getConfig();
  await host.writeState(profile, await localFor(profile));
  const malformed = '{"v":1,"protectedConfig":"AAAA","local":null}';
  await fs.writeFile(path.join(dataDir, 'state.json'), malformed);
  const reopened = createHost(options);
  await assert.rejects(reopened.getConfig()); await assert.rejects(reopened.writeState(profile, await localFor(profile)));
  assert.equal(await fs.readFile(path.join(dataDir, 'state.json'), 'utf8'), malformed);
});

test('file mode blocks host network requests even with a remembered server endpoint', async t => {
  const { host } = await fixture(t);
  const { deviceLabel, ...profile } = await host.getConfig();
  await host.writeState({ ...profile, endpoint: 'https://example.com' }, await localFor(profile));
  const originalFetch = global.fetch; let calls = 0;
  global.fetch = async () => { calls++; throw new Error('must not fetch'); };
  try { await assert.rejects(host.request('GET', '/v1/vault'), /文件模式/); await assert.rejects(host.request('PUT', '/v1/vault', {}), /文件模式/); }
  finally { global.fetch = originalFetch; }
  assert.equal(calls, 0);
});

test('import picker handles cancellation, rejects invalid UTF8 and enforces an 8 MiB byte limit', async t => {
  let selected;
  const dialog = { showOpenDialog: async () => selected };
  const { root, host } = await fixture(t, { dialog });
  selected = { canceled: true, filePaths: [] }; assert.equal(await host.chooseImportFile(), null);
  const file = path.join(root, 'import.json');
  await fs.writeFile(file, '{"format":"test"}'); selected = { canceled: false, filePaths: [file] };
  assert.equal(await host.chooseImportFile(), '{"format":"test"}');
  await fs.writeFile(file, Buffer.from([0xc3, 0x28])); await assert.rejects(host.chooseImportFile());
  await fs.writeFile(file, Buffer.alloc(8 * 1024 * 1024 + 1)); await assert.rejects(host.chooseImportFile());
});

test('export picker handles cancellation, refuses internal data paths and atomically replaces only the explicitly chosen file', async t => {
  let selected;
  const dialog = { showSaveDialog: async () => selected };
  const { root, dataDir, host } = await fixture(t, { dialog });
  selected = { canceled: true }; assert.equal(await host.saveExportFile('{}'), false);
  selected = { canceled: false, filePath: path.join(dataDir, 'state.json') };
  await assert.rejects(host.saveExportFile('{"secret":"fixture"}'), /内部数据/);
  assert.deepEqual(await fs.readdir(dataDir), []);
  const file = path.join(root, 'transfer.json'); await fs.writeFile(file, 'old');
  selected = { canceled: false, filePath: file }; assert.equal(await host.saveExportFile('{"secret":"fixture"}'), true);
  assert.equal(await fs.readFile(file, 'utf8'), '{"secret":"fixture"}');
  assert.deepEqual((await fs.readdir(root)).sort(), ['app', 'transfer.json']);
  await assert.rejects(host.saveExportFile('x'.repeat(8 * 1024 * 1024 + 1)));
});
