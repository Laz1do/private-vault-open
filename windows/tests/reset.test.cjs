const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { createHost } = require('../host.cjs');
const core = import('../../core/vault.js');
const entry = password => ({ title: 'Native reset fixture', username: 'alice', password, url: 'https://example.com', notes: '' });
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function protectedStorage() {
  const key = crypto.randomBytes(32);
  return {
    isEncryptionAvailable: () => true,
    encryptString(value) { const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', key, nonce); return Buffer.concat([nonce, cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]); },
    decryptString(value) { const decipher = crypto.createDecipheriv('aes-256-gcm', key, value.subarray(0, 12)); decipher.setAuthTag(value.subarray(-16)); return Buffer.concat([decipher.update(value.subarray(12, -16)), decipher.final()]).toString('utf8'); },
  };
}
async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'private-vault-reset-test-'));
  const dataDir = path.join(root, 'app'); await fs.mkdir(dataDir);
  let selection = { canceled: false, filePath: path.join(root, 'old.pvault') }, dialogs = 0;
  const options = { dataDir, safeStorage: protectedStorage(), clipboard: {}, shell: {}, dialog: {
    showSaveDialog: async () => { dialogs++; return typeof selection === 'function' ? selection() : selection; },
  } };
  const host = createHost(options), { deviceLabel, ...profile } = await host.getConfig();
  const { createVault, writeRecord, encryptVault } = await core;
  const vault = writeRecord(createVault(profile.vaultId), null, entry('native-old-secret'), 'fixture-device');
  const local = { deviceId: 'fixture-device', envelope: await encryptVault(vault, profile.keyB64) };
  await host.writeState(profile, local);
  t.after(async () => {
    if (!path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep + 'private-vault-reset-test-')) throw new Error('Unsafe fixture cleanup');
    await fs.rm(root, { recursive: true, force: true });
  });
  return { root, dataDir, options, host, profile, local, vault, setSelection: value => { selection = value; }, dialogs: () => dialogs };
}
function portable(vault, profile) {
  const { mode, deviceLabel, ...portableProfile } = profile;
  return JSON.stringify({ format: 'private-vault-file', version: 1, profile: portableProfile, vault });
}
async function fresh(local, extra = {}) {
  const { createVault, encryptVault } = await core;
  const profile = { vaultId: crypto.randomUUID(), keyB64: crypto.randomBytes(32).toString('base64'), token: crypto.randomBytes(32).toString('base64url'), mode: 'file', endpoint: null, ...extra };
  return { profile, local: { deviceId: local.deviceId, envelope: await encryptVault(createVault(profile.vaultId), profile.keyB64) } };
}

test('native backup-and-replace verifies and saves the complete old library before committing one protected fresh state', async t => {
  const f = await fixture(t), next = await fresh(f.local), text = portable(f.vault, f.profile);
  assert.equal(await f.host.backupAndReplace(text, next.profile, next.local), true);
  assert.equal(await fs.readFile(path.join(f.root, 'old.pvault'), 'utf8'), text);
  assert.deepEqual(await f.host.readLocal(), next.local);
  const actual = await f.host.getConfig(); assert.equal(actual.vaultId, next.profile.vaultId); assert.equal(actual.mode, 'file'); assert.equal(actual.endpoint, null);
  const raw = await fs.readFile(path.join(f.dataDir, 'state.json'), 'utf8');
  for (const secret of [f.profile.keyB64, f.profile.token, next.profile.keyB64, next.profile.token, 'native-old-secret']) assert.ok(!raw.includes(secret));
  assert.deepEqual(await createHost(f.options).readLocal(), next.local);
  // Ordinary writeState still cannot bypass protection of a nonempty library.
  const { writeRecord, createVault, encryptVault } = await core;
  const nonempty = { deviceId: next.local.deviceId, envelope: await encryptVault(writeRecord(createVault(next.profile.vaultId), null, entry('new secret'), next.local.deviceId), next.profile.keyB64) };
  await f.host.writeState(next.profile, nonempty);
  await assert.rejects(f.host.writeState(f.profile, f.local), /已有记录/);
  assert.deepEqual(await f.host.readLocal(), nonempty);
});

test('canceled native backup never touches the chosen existing file or the former protected state', async t => {
  const f = await fixture(t), next = await fresh(f.local), before = await fs.readFile(path.join(f.dataDir, 'state.json'), 'utf8');
  const target = path.join(f.root, 'old.pvault'); await fs.writeFile(target, 'older-backup');
  f.setSelection({ canceled: true, filePath: target });
  assert.equal(await f.host.backupAndReplace(portable(f.vault, f.profile), next.profile, next.local), false);
  assert.equal(await fs.readFile(target, 'utf8'), 'older-backup');
  assert.equal(await fs.readFile(path.join(f.dataDir, 'state.json'), 'utf8'), before); assert.deepEqual(await f.host.readLocal(), f.local);
});

test('native boundary refuses omitted record versions, tombstones and conflicting heads before showing a save dialog', async t => {
  const f = await fixture(t), next = await fresh(f.local);
  const { createVault, writeRecord, deleteRecord, mergeVaults, encryptVault } = await core;
  const id = Object.keys(f.vault.records)[0];
  const deleted = deleteRecord(f.vault, id, 'fixture-device');
  const conflict = mergeVaults(deleted, writeRecord(f.vault, id, entry('concurrent edit'), 'other-device'));
  const withOther = writeRecord(conflict, null, entry('another record'), 'fixture-device');
  const persisted = { deviceId: f.local.deviceId, envelope: await encryptVault(withOther, f.profile.keyB64) };
  await f.host.writeState(f.profile, persisted);
  const incompleteFiles = [createVault(f.profile.vaultId), f.vault, conflict, deleted];
  for (const incomplete of incompleteFiles) await assert.rejects(f.host.backupAndReplace(portable(incomplete, f.profile), next.profile, next.local), /遗漏/);
  assert.equal(f.dialogs(), 0); assert.deepEqual(await f.host.readLocal(), persisted);
  assert.equal(await f.host.backupAndReplace(portable(withOther, f.profile), next.profile, next.local), true);
});

test('native boundary independently requires the actual old profile and a genuinely independent empty new profile', async t => {
  const f = await fixture(t), next = await fresh(f.local), { createVault, writeRecord, encryptVault } = await core;
  const oldText = portable(f.vault, f.profile);
  for (const mutation of [
    value => { value.keyB64 = crypto.randomBytes(32).toString('base64'); },
    value => { value.token = crypto.randomBytes(32).toString('base64url'); },
    value => { value.endpoint = 'https://different.example.com'; },
  ]) {
    const wrong = { ...f.profile }; mutation(wrong);
    await assert.rejects(f.host.backupAndReplace(portable(f.vault, wrong), next.profile, next.local), /完整配置/);
  }
  for (const altered of [
    { ...next.profile, vaultId: f.profile.vaultId }, { ...next.profile, keyB64: f.profile.keyB64 },
    { ...next.profile, token: f.profile.token }, { ...next.profile, endpoint: 'https://old.example.com' }, { ...next.profile, mode: 'server' },
  ]) {
    const local = { deviceId: f.local.deviceId, envelope: await encryptVault(createVault(altered.vaultId), altered.keyB64) };
    await assert.rejects(f.host.backupAndReplace(oldText, altered, local), /独立/);
  }
  await assert.rejects(f.host.backupAndReplace(oldText, next.profile, { ...next.local, deviceId: 'different-device' }), /独立/);
  const nonempty = { deviceId: f.local.deviceId, envelope: await encryptVault(writeRecord(createVault(next.profile.vaultId), null, entry('forbidden'), f.local.deviceId), next.profile.keyB64) };
  await assert.rejects(f.host.backupAndReplace(oldText, next.profile, nonempty), /必须为空/);
  const corrupted = structuredClone(next.local); corrupted.envelope.data = crypto.randomBytes(32).toString('base64');
  await assert.rejects(f.host.backupAndReplace(oldText, next.profile, corrupted));
  assert.equal(f.dialogs(), 0); assert.deepEqual(await f.host.readLocal(), f.local);
});

test('native backup refuses internal data targets and never commits fresh state after a backup or state rename failure', async t => {
  const f = await fixture(t), next = await fresh(f.local), before = await fs.readFile(path.join(f.dataDir, 'state.json'), 'utf8'), text = portable(f.vault, f.profile);
  f.setSelection({ canceled: false, filePath: path.join(f.dataDir, 'state.json') });
  await assert.rejects(f.host.backupAndReplace(text, next.profile, next.local), /内部数据/);
  const target = path.join(f.root, 'old.pvault'); f.setSelection({ canceled: false, filePath: target });
  const rename = fs.rename;
  for (const failureTarget of [target, path.join(f.dataDir, 'state.json')]) {
    fs.rename = async (from, to) => { if (to === failureTarget) throw new Error('fixture rename failure'); return rename(from, to); };
    try { await assert.rejects(f.host.backupAndReplace(text, next.profile, next.local), /rename failure/); }
    finally { fs.rename = rename; }
    assert.equal(await fs.readFile(path.join(f.dataDir, 'state.json'), 'utf8'), before); assert.deepEqual(await f.host.readLocal(), f.local);
  }
  assert.equal(await fs.readFile(target, 'utf8'), text, 'state failure leaves a valid recovery file');
  assert.deepEqual(await fs.readdir(f.dataDir), ['state.json']);
});

test('backup queue drains earlier accepted native writes and blocks every new write or request until the save dialog settles', async t => {
  const f = await fixture(t), next = await fresh(f.local), { writeRecord, encryptVault } = await core;
  const latest = writeRecord(f.vault, Object.keys(f.vault.records)[0], entry('earlier queued edit'), f.local.deviceId);
  const latestLocal = { deviceId: f.local.deviceId, envelope: await encryptVault(latest, f.profile.keyB64) };
  const entered = deferred(), release = deferred(); f.setSelection(() => { entered.resolve(); return release.promise; });
  const oldWrite = f.host.writeLocal(latestLocal);
  const resetting = f.host.backupAndReplace(portable(latest, f.profile), next.profile, next.local);
  await entered.promise; await oldWrite;
  assert.deepEqual(await f.host.readLocal(), latestLocal);
  await assert.rejects(f.host.writeState(f.profile, f.local), /正在备份/);
  await assert.rejects(f.host.writeLocal(f.local), /正在备份/);
  await assert.rejects(f.host.backupAndReplace(portable(latest, f.profile), next.profile, next.local), /正在备份/);
  await assert.rejects(f.host.request('GET', '/v1/vault'), /正在备份/);
  release.resolve({ canceled: true }); assert.equal(await resetting, false);
  assert.deepEqual(await f.host.readLocal(), latestLocal);
  await f.host.writeState(f.profile, f.local); assert.deepEqual(await f.host.readLocal(), f.local);
});

test('a backup altered during disk writing is detected before fresh state commit', async t => {
  const f = await fixture(t), next = await fresh(f.local), text = portable(f.vault, f.profile), target = path.join(f.root, 'old.pvault');
  const before = await fs.readFile(path.join(f.dataDir, 'state.json'), 'utf8'), rename = fs.rename;
  fs.rename = async (from, to) => { await rename(from, to); if (to === target) await fs.writeFile(target, '{}'); };
  try { await assert.rejects(f.host.backupAndReplace(text, next.profile, next.local), /验证失败/); }
  finally { fs.rename = rename; }
  assert.equal(await fs.readFile(path.join(f.dataDir, 'state.json'), 'utf8'), before); assert.deepEqual(await f.host.readLocal(), f.local);
});
