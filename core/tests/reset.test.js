import test from 'node:test';
import assert from 'node:assert/strict';
import { createVault, createVaultClient, writeRecord, deleteRecord, encryptVault, decryptVault, parsePortableFile, mergeVaults } from '../vault.js';

const KEY = Buffer.alloc(32, 73).toString('base64');
const TOKEN = 'public_reset_fixture_token_123456789';
const entry = password => ({ title: 'Reset fixture', username: 'alice', password, url: 'https://example.com', notes: '' });
const clone = value => structuredClone(value);
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function memoryHost() {
  return {
    config: { vaultId: 'reset-fixture-vault', keyB64: KEY, token: TOKEN, endpoint: null, mode: 'file' }, local: null,
    requests: [], backups: [], failWrites: false, replaceResult: true, replaceError: null,
    remote: { revision: 0, envelope: null },
    async getConfig() { return clone(this.config); }, async readLocal() { return clone(this.local); },
    async writeLocal(value) { this.local = clone(value); },
    async writeState(config, local) {
      if (this.failWrites) throw new Error('fixture disk failure');
      this.config = clone(config); this.local = clone(local);
    },
    async backupAndReplace(text, config, local) {
      this.backups.push(parsePortableFile(text));
      if (this.replaceError) throw this.replaceError;
      if (!this.replaceResult) return false;
      this.config = clone(config); this.local = clone(local); return true;
    },
    async request(method, route, body) {
      this.requests.push({ method, route, profile: clone(this.config) });
      assert.equal(this.config.mode, 'server');
      if (method === 'GET') return { status: 200, body: clone(this.remote) };
      if (body.expectedRevision !== this.remote.revision) return { status: 409, body: {} };
      this.remote = { revision: this.remote.revision + 1, envelope: clone(body.envelope) };
      return { status: 200, body: { revision: this.remote.revision } };
    },
  };
}

test('backup-and-create keeps the complete prior library recoverable and starts an independent empty file library', async () => {
  const host = memoryHost(), client = await createVaultClient(host);
  const id = await client.save(entry('old-secret')), oldProfile = clone(host.config), oldDevice = host.local.deviceId;
  const oldText = await client.exportFile();
  const states = []; client.subscribe(state => states.push(state));
  const result = await client.exportAndCreateNew();
  assert.equal(result.created, true); assert.equal(result.changingVault, false);
  assert.equal(client.snapshot().hasHistory, false); assert.equal(client.snapshot().records.length, 0);
  assert.equal(client.snapshot().pending, false); assert.equal(client.snapshot().lastSync, null);
  assert.equal(host.config.mode, 'file'); assert.equal(host.config.endpoint, null);
  for (const field of ['vaultId', 'keyB64', 'token']) assert.notEqual(host.config[field], oldProfile[field]);
  assert.equal(host.local.deviceId, oldDevice); assert.deepEqual(host.backups, [parsePortableFile(oldText)]);
  assert.ok(states.some(state => state.changingVault)); assert.equal(states.at(-1).changingVault, false);
  assert.deepEqual((await decryptVault(host.local.envelope, host.config.keyB64, host.config.vaultId)).records, {});
  await assert.rejects(client.save(entry('stale draft'), id), { code: 'record_not_found' });
  await assert.rejects(client.remove(id), { code: 'record_not_found' });
  const reopened = await createVaultClient(host); assert.equal(reopened.snapshot().vaultId, host.config.vaultId);
  await reopened.importFile(oldText); assert.equal(reopened.snapshot().records[0].entry.password, 'old-secret');
  assert.equal(host.requests.length, 0);
});

test('canceling backup-and-create preserves the previous identity, encrypted state and current view exactly', async () => {
  const host = memoryHost(), client = await createVaultClient(host);
  await client.save(entry('unchanged')); host.replaceResult = false;
  const before = client.snapshot(), local = clone(host.local), profile = clone(host.config), text = await client.exportFile();
  const result = await client.exportAndCreateNew();
  assert.equal(result.created, false); assert.deepEqual(client.snapshot(), before);
  assert.deepEqual(host.local, local); assert.deepEqual(host.config, profile); assert.equal(await client.exportFile(), text);
  await client.save(entry('after cancel')); assert.equal(client.snapshot().records.length, 2);
});

test('backup failure preserves in-memory edits after a disk failure, and a retry backs them up before replacing', async () => {
  const host = memoryHost(), client = await createVaultClient(host);
  await client.save(entry('persisted')); const persisted = clone(host.local), profile = clone(host.config);
  host.failWrites = true; await assert.rejects(client.save(entry('unpersisted')), { code: 'persistence_failed' });
  host.replaceError = new Error('fixture backup disk failure'); const before = await client.exportFile();
  await assert.rejects(client.exportAndCreateNew(), /backup disk failure/);
  assert.equal(client.snapshot().changingVault, false); assert.equal(await client.exportFile(), before);
  assert.deepEqual(host.local, persisted); assert.deepEqual(host.config, profile);
  assert.equal(Object.keys(host.backups[0].vault.records).length, 2);
  host.replaceError = null;
  assert.equal((await client.exportAndCreateNew()).created, true);
  assert.deepEqual(host.backups[1], parsePortableFile(before));
});

test('the whole transaction gates new mutations and drains already accepted edits and configuration into the backup', async () => {
  const host = memoryHost(), client = await createVaultClient(host);
  const oldId = await client.save(entry('initial')), incoming = parsePortableFile(await client.exportFile());
  incoming.vault = writeRecord(incoming.vault, null, entry('imported'), 'other-device');
  incoming.profile.endpoint = 'https://new.example.com';
  const started = deferred(), release = deferred(), normalWrite = host.writeState.bind(host); let hold = true;
  host.writeState = async (...args) => { if (hold) { hold = false; started.resolve(); await release.promise; } return normalWrite(...args); };
  const saving = client.save(entry('queued edit'), oldId); await started.promise;
  const importing = client.importFile(JSON.stringify(incoming));
  const resetting = client.exportAndCreateNew(); assert.equal(client.snapshot().changingVault, true);
  await assert.rejects(client.save(entry('too late')), { code: 'vault_changing' });
  await assert.rejects(client.remove(oldId), { code: 'vault_changing' });
  await assert.rejects(client.resolve(oldId, 'obsolete-version'), { code: 'vault_changing' });
  await assert.rejects(client.importFile(JSON.stringify(incoming)), { code: 'vault_changing' });
  await assert.rejects(client.configureServer({ endpoint: 'https://late.example.com', token: TOKEN }), { code: 'vault_changing' });
  await assert.rejects(client.setMode('server'), { code: 'vault_changing' });
  await assert.rejects(client.exportFile(), { code: 'vault_changing' });
  await assert.rejects(client.exportAndCreateNew(), { code: 'vault_changing' });
  await client.sync(); assert.equal(host.requests.length, 0); assert.equal(host.backups.length, 0);
  release.resolve(); await Promise.all([saving, importing, resetting]);
  const backup = host.backups[0]; assert.equal(backup.profile.endpoint, 'https://new.example.com');
  assert.equal(backup.vault.records[oldId][0].entry.password, 'queued edit');
  assert.equal(Object.keys(backup.vault.records).length, 2); assert.equal(client.snapshot().records.length, 0);
});

test('backup-and-create waits for the old sync and includes remote deletion history before any new identity is committed', async () => {
  const host = memoryHost(), client = await createVaultClient(host);
  const oldId = await client.save(entry('to delete'));
  const oldFile = parsePortableFile(await client.exportFile());
  const remote = deleteRecord(oldFile.vault, oldId, 'other-device');
  host.remote = { revision: 1, envelope: await encryptVault(remote, KEY) };
  await client.configureServer({ endpoint: 'https://old.example.com', token: TOKEN });
  const started = deferred(), release = deferred(), normalRequest = host.request.bind(host); let hold = true;
  host.request = async (...args) => { if (hold && args[0] === 'GET') { hold = false; started.resolve(); await release.promise; } return normalRequest(...args); };
  await client.setMode('server'); await started.promise;
  const resetting = client.exportAndCreateNew();
  const activeSync = client.sync();
  assert.equal(host.backups.length, 0); assert.equal(client.snapshot().changingVault, true);
  release.resolve(); await Promise.all([activeSync, resetting]);
  assert.equal(host.backups[0].vault.records[oldId][0].kind, 'delete');
  assert.equal(host.backups[0].profile.endpoint, 'https://old.example.com');
  const requests = host.requests.length; await client.sync(); await client.save(entry('new library')); await client.sync();
  assert.equal(host.requests.length, requests); assert.equal(host.config.mode, 'file'); assert.equal(host.config.endpoint, null);
});

test('a deleted-only library has history and reset backs up tombstones rather than treating it as a fresh install', async () => {
  const host = memoryHost(), client = await createVaultClient(host), id = await client.save(entry('removed'));
  await client.remove(id); assert.equal(client.snapshot().records.length, 0); assert.equal(client.snapshot().hasHistory, true);
  await client.exportAndCreateNew(); assert.equal(host.backups[0].vault.records[id][0].kind, 'delete');
  assert.equal(client.snapshot().hasHistory, false);
  assert.deepEqual(mergeVaults(host.backups[0].vault, host.backups[0].vault), host.backups[0].vault);
});

test('a profile change already waiting for an old sync finishes into the backup without starting another old-server sync', async () => {
  const host = memoryHost(), client = await createVaultClient(host);
  await client.save(entry('profile race'));
  await client.configureServer({ endpoint: 'https://first.example.com', token: TOKEN });
  const started = deferred(), release = deferred(), normalRequest = host.request.bind(host); let hold = true;
  host.request = async (...args) => { if (hold && args[0] === 'GET') { hold = false; started.resolve(); await release.promise; } return normalRequest(...args); };
  await client.setMode('server'); await started.promise;
  const nextToken = 'public_updated_fixture_token_1234567';
  const configuring = client.configureServer({ endpoint: 'https://second.example.com', token: nextToken });
  const resetting = client.exportAndCreateNew();
  release.resolve(); await Promise.all([configuring, resetting]);
  assert.equal(host.backups[0].profile.endpoint, 'https://second.example.com'); assert.equal(host.backups[0].profile.token, nextToken);
  assert.ok(host.requests.every(request => request.profile.endpoint === 'https://first.example.com'));
  assert.equal(host.config.endpoint, null); assert.equal(host.config.mode, 'file');
});

test('recovery without an old key cannot bypass the original encrypted library using backup-and-create', async () => {
  const host = memoryHost(); host.local = { deviceId: 'legacy-device', envelope: await encryptVault(createVault(host.config.vaultId), KEY) }; host.config = null;
  const client = await createVaultClient(host);
  await assert.rejects(client.exportAndCreateNew(), { code: 'needs_import' });
  assert.equal(host.backups.length, 0); assert.equal(client.snapshot().hasHistory, true); assert.equal(client.snapshot().needsImport, true);
});
