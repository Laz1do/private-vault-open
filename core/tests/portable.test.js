import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createVault, writeRecord, deleteRecord, encryptVault, decryptVault, listRecords,
  createVaultClient, parsePortableFile,
} from '../vault.js';

const KEY = Buffer.alloc(32, 51).toString('base64');
const OTHER_KEY = Buffer.alloc(32, 52).toString('base64');
const TOKEN = 'test_public_connection_token_123456789';
const clone = value => structuredClone(value);
const entry = (password = 'file-password', title = 'Example') => ({ title, username: 'alice', password, url: 'https://example.com', notes: '' });
const profile = (extra = {}) => ({ vaultId: 'portable-test-vault', keyB64: KEY, token: TOKEN, endpoint: null, mode: 'file', ...extra });
const fileText = (vault, config = profile()) => {
  const { mode: _, ...portableProfile } = config;
  return JSON.stringify({ format: 'private-vault-file', version: 1, profile: portableProfile, vault });
};
const firstId = vault => Object.keys(vault.records)[0];
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function memoryHost(config = null, local = null) {
  return {
    config: clone(config), local: clone(local), writes: 0, requests: [], failWrites: 0,
    remote: { revision: 0, envelope: null },
    async getConfig() { return clone(this.config); },
    async readLocal() { return clone(this.local); },
    async writeLocal(value) { if (this.failWrites > 0) { this.failWrites--; throw new Error('test disk failure'); } this.local = clone(value); this.writes++; },
    async writeState(nextConfig, nextLocal) {
      if (this.failWrites > 0) { this.failWrites--; throw new Error('test disk failure'); }
      this.config = clone(nextConfig); this.local = clone(nextLocal); this.writes++;
    },
    async request(method, path, body) {
      this.requests.push({ method, path, body: clone(body) });
      if (this.config?.mode === 'file') throw new Error('file mode must never reach a network host');
      assert.equal(path, '/v1/vault');
      if (method === 'GET') return { status: 200, body: clone(this.remote) };
      if (body.expectedRevision !== this.remote.revision) return { status: 409, body: {} };
      this.remote = { revision: this.remote.revision + 1, envelope: clone(body.envelope) };
      return { status: 200, body: { revision: this.remote.revision } };
    },
  };
}

test('fresh public installations create independent file-mode identities and never contact a server', async () => {
  const aHost = memoryHost(), bHost = memoryHost();
  const a = await createVaultClient(aHost), b = await createVaultClient(bHost);
  assert.equal(a.snapshot().mode, 'file'); assert.equal(a.snapshot().configured, false);
  assert.equal(aHost.config.token.length, 43);
  assert.equal(Buffer.from(aHost.config.keyB64, 'base64').length, 32);
  assert.notEqual(aHost.config.vaultId, bHost.config.vaultId);
  assert.notEqual(aHost.config.keyB64, bHost.config.keyB64);
  assert.notEqual(aHost.config.token, bHost.config.token);
  await a.save(entry()); await a.sync();
  assert.equal(aHost.requests.length, 0); assert.equal(bHost.requests.length, 0);
  const publicSnapshot = JSON.stringify(a.snapshot());
  assert.ok(!publicSnapshot.includes(aHost.config.keyB64)); assert.ok(!publicSnapshot.includes(aHost.config.token));
  assert.equal(b.snapshot().records.length, 0);
});

test('portable files carry unprotected records, causal state and connection profile, without device identity or mode', async () => {
  const host = memoryHost(profile({ endpoint: 'https://vault.example.com' })), client = await createVaultClient(host);
  await client.save(entry('portable-plaintext'));
  const text = await client.exportFile(), file = parsePortableFile(text);
  assert.equal(file.profile.keyB64, KEY); assert.equal(file.profile.token, TOKEN);
  assert.equal(file.profile.endpoint, 'https://vault.example.com');
  assert.equal(listRecords(file.vault)[0].entry.password, 'portable-plaintext');
  assert.ok(text.includes('portable-plaintext')); assert.ok(text.includes(KEY)); assert.ok(text.includes(TOKEN));
  assert.deepEqual(Object.keys(file.profile).sort(), ['endpoint', 'keyB64', 'token', 'vaultId']);
  assert.equal(Object.hasOwn(file, 'deviceId'), false);
  assert.equal(Object.hasOwn(file.profile, 'deviceId'), false);
  assert.ok(!JSON.stringify(host.local).includes('portable-plaintext'));
  assert.equal(host.requests.length, 0);
});

test('a fresh device adopts a portable library and connection settings while retaining its device identity', async () => {
  const originalHost = memoryHost(profile({ endpoint: 'https://vault.example.com' })), original = await createVaultClient(originalHost);
  await original.save(entry());
  const newHost = memoryHost(), fresh = await createVaultClient(newHost), deviceId = newHost.local.deviceId;
  await fresh.importFile(await original.exportFile());
  assert.equal(newHost.local.deviceId, deviceId); assert.notEqual(newHost.local.deviceId, originalHost.local.deviceId);
  assert.deepEqual(newHost.config, originalHost.config);
  assert.equal(fresh.snapshot().mode, 'file'); assert.equal(fresh.snapshot().serverEndpoint, 'https://vault.example.com');
  assert.equal(fresh.snapshot().records[0].entry.password, 'file-password');
  assert.equal(newHost.requests.length, 0);
  const reopened = await createVaultClient(newHost);
  assert.deepEqual(reopened.snapshot().records, fresh.snapshot().records);
});

test('offline file exchange merges different records and retains concurrent versions of the same record', async () => {
  const a = await createVaultClient(memoryHost(profile()));
  const id = await a.save(entry('initial'));
  const b = await createVaultClient(memoryHost()); await b.importFile(await a.exportFile());
  await a.save(entry('computer'), id); await b.save(entry('phone'), id);
  await a.save(entry('only-a', 'A')); await b.save(entry('only-b', 'B'));
  await a.importFile(await b.exportFile()); await b.importFile(await a.exportFile());
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  const conflict = a.snapshot().records.find(record => record.id === id);
  assert.equal(conflict.conflict, true);
  assert.deepEqual(conflict.versions.map(version => version.entry.password).sort(), ['computer', 'phone']);
  assert.equal(a.snapshot().records.length, 3);
  await a.resolve(id, conflict.versions.find(v => v.entry.password === 'phone').id);
  await b.importFile(await a.exportFile()); await a.importFile(await b.exportFile());
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  assert.equal(a.snapshot().records.find(record => record.id === id).conflict, false);
});

test('an editor draft queued behind a newer file merge is refused without superseding the incoming password', async () => {
  const client = await createVaultClient(memoryHost(profile()));
  const id = await client.save(entry('before-edit'));
  const baseline = client.snapshot().records.find(record => record.id === id).versions.map(version => version.id).sort().join('|');
  const incoming = parsePortableFile(await client.exportFile());
  incoming.vault = writeRecord(incoming.vault, id, entry('incoming-password'), 'other_device');
  const importing = client.importFile(JSON.stringify(incoming));
  const saving = client.save(entry('stale-draft'), id, baseline);
  await Promise.all([importing, assert.rejects(saving, { code: 'stale_record' })]);
  const current = client.snapshot().records.find(record => record.id === id);
  assert.equal(current.entry.password, 'incoming-password');
  assert.equal(current.conflict, false);
  assert.ok(!(await client.exportFile()).includes('stale-draft'));
  // A second click with the same obsolete baseline cannot silently overwrite it.
  await assert.rejects(client.save(entry('stale-draft'), id, baseline), { code: 'stale_record' });
  const latestStamp = current.versions.map(version => version.id).sort().join('|');
  await client.save(entry('reviewed-edit'), id, latestStamp);
  assert.equal(client.snapshot().records.find(record => record.id === id).entry.password, 'reviewed-edit');
});

test('old exported files cannot restore a deletion or superseded password', async () => {
  const client = await createVaultClient(memoryHost(profile()));
  const id = await client.save(entry('old-secret')), oldFile = await client.exportFile();
  await client.save(entry('new-secret'), id); await client.importFile(oldFile);
  assert.equal(client.snapshot().records[0].entry.password, 'new-secret');
  await client.remove(id); await client.importFile(oldFile);
  assert.equal(client.snapshot().records.length, 0);
  const exported = await client.exportFile();
  assert.ok(!exported.includes('old-secret')); assert.ok(!exported.includes('new-secret'));
  assert.equal(parsePortableFile(exported).vault.records[id][0].kind, 'delete');
});

test('delete-versus-edit file conflicts remain visible and resolve without later resurrection', async () => {
  const a = await createVaultClient(memoryHost(profile())), id = await a.save(entry());
  const b = await createVaultClient(memoryHost()); await b.importFile(await a.exportFile());
  await a.remove(id); await b.save(entry('edited'), id);
  const staleEdit = await b.exportFile();
  await b.importFile(await a.exportFile());
  const record = b.snapshot().records[0];
  assert.equal(record.conflict, true); assert.deepEqual(record.versions.map(v => v.kind).sort(), ['delete', 'put']);
  await b.resolve(id, record.versions.find(v => v.kind === 'delete').id);
  await b.importFile(staleEdit); assert.equal(b.snapshot().records.length, 0);
});

test('nonempty libraries, including tombstones-only libraries, reject a different vault identity', async () => {
  const client = await createVaultClient(memoryHost(profile())), id = await client.save(entry());
  const otherVault = createVault('different-vault'), different = fileText(otherVault, profile({ vaultId: 'different-vault' }));
  const before = await client.exportFile();
  await assert.rejects(client.importFile(different), { code: 'different_vault' });
  assert.equal(await client.exportFile(), before);
  await client.remove(id);
  await assert.rejects(client.importFile(different), { code: 'different_vault' });
  assert.equal(client.snapshot().vaultId, profile().vaultId); assert.equal(client.snapshot().records.length, 0);
});

test('the same library ID with a different key is refused, and malformed files change neither profile nor local data', async () => {
  const host = memoryHost(profile()), client = await createVaultClient(host);
  await client.save(entry()); const text = await client.exportFile(), beforeLocal = clone(host.local), beforeProfile = clone(host.config);
  const wrongKey = JSON.parse(text); wrongKey.profile.keyB64 = OTHER_KEY;
  await assert.rejects(client.importFile(JSON.stringify(wrongKey)), { code: 'different_key' });
  for (const mutation of [
    file => { file.version = 2; }, file => { file.profile.keyB64 += '\n'; },
    file => { file.profile.token = 'bad token'; }, file => { file.profile.endpoint = 'http://untrusted.example'; },
    file => { file.profile.endpoint = 'https://vault.example.com/subpath'; }, file => { file.deviceId = 'copy-this-device'; },
    file => { file.vault.vaultId = 'mismatch'; }, file => { file.vault.records[firstId(file.vault)][0].entry.password = 123; },
  ]) {
    const bad = JSON.parse(text); mutation(bad);
    await assert.rejects(client.importFile(JSON.stringify(bad)), { code: 'invalid_file' });
  }
  await assert.rejects(client.importFile('not-json'), { code: 'invalid_file' });
  await assert.rejects(client.importFile(' '.repeat(8 * 1024 * 1024 + 1)), { code: 'invalid_file' });
  assert.deepEqual(host.local, beforeLocal); assert.deepEqual(host.config, beforeProfile);
  assert.equal(await client.exportFile(), text); assert.equal(host.requests.length, 0);
});

test('same-library imports adopt exported connection settings but preserve the local mode', async () => {
  const host = memoryHost(profile({ endpoint: 'https://new.example.com' })), client = await createVaultClient(host);
  await client.save(entry());
  const incoming = JSON.parse(await client.exportFile()); incoming.profile.endpoint = 'https://old.example.com'; incoming.profile.token = 'old_public_test_connection_token_12345';
  await client.importFile(JSON.stringify(incoming));
  assert.equal(host.config.endpoint, incoming.profile.endpoint); assert.equal(host.config.token, incoming.profile.token);
  assert.equal(host.config.mode, 'file'); assert.equal(host.requests.length, 0);
});

test('import persistence failures leave the previous profile and password data unchanged', async () => {
  const host = memoryHost(profile()), client = await createVaultClient(host);
  await client.save(entry('unchanged'));
  const before = await client.exportFile(), beforeLocal = clone(host.local), beforeProfile = clone(host.config);
  const incoming = parsePortableFile(before);
  incoming.vault = writeRecord(incoming.vault, null, entry('incoming', 'Incoming'), 'other_device');
  incoming.profile.endpoint = 'https://new.example.com'; host.failWrites = 1;
  await assert.rejects(client.importFile(JSON.stringify(incoming)), { code: 'persistence_failed' });
  assert.equal(await client.exportFile(), before); assert.deepEqual(host.local, beforeLocal); assert.deepEqual(host.config, beforeProfile);
  await client.importFile(JSON.stringify(incoming));
  assert.equal(client.snapshot().records.length, 2); assert.equal(host.config.endpoint, 'https://new.example.com');
});

test('a legacy encrypted library without an embedded key enters recovery without writing, editing, exporting or networking', async () => {
  const oldVault = writeRecord(createVault(profile().vaultId), null, entry('legacy'), 'old_device');
  const local = { deviceId: 'old_device', envelope: await encryptVault(oldVault, KEY) };
  const host = memoryHost(null, local), client = await createVaultClient(host);
  assert.equal(client.snapshot().needsImport, true); assert.equal(client.snapshot().vaultId, profile().vaultId);
  await assert.rejects(client.save(entry()), { code: 'needs_import' });
  await assert.rejects(client.exportFile(), { code: 'needs_import' });
  await assert.rejects(client.setMode('server'), { code: 'needs_import' });
  await client.sync(); assert.equal(host.requests.length, 0); assert.equal(host.writes, 0); assert.deepEqual(host.local, local);
  await assert.rejects(client.importFile(fileText(oldVault, profile({ keyB64: OTHER_KEY }))), { code: 'different_key' });
  await assert.rejects(client.importFile(fileText(createVault('wrong-vault'), profile({ vaultId: 'wrong-vault' }))), { code: 'different_vault' });
  assert.equal(host.writes, 0); assert.deepEqual(host.local, local);
  const imported = writeRecord(oldVault, null, entry('from-file', 'Imported'), 'other_device');
  await client.importFile(fileText(imported));
  assert.equal(client.snapshot().needsImport, false); assert.equal(client.snapshot().records.length, 2);
  assert.equal(host.local.deviceId, 'old_device'); assert.equal(host.config.mode, 'file'); assert.equal(host.requests.length, 0);
  assert.equal(listRecords(await decryptVault(host.local.envelope, KEY, profile().vaultId)).length, 2);
});

test('recovery persistence failure preserves the old encrypted file and remains in recovery', async () => {
  const vault = writeRecord(createVault(profile().vaultId), null, entry(), 'old_device');
  const local = { deviceId: 'old_device', envelope: await encryptVault(vault, KEY) };
  const host = memoryHost(null, local), client = await createVaultClient(host); host.failWrites = 1;
  await assert.rejects(client.importFile(fileText(vault)), { code: 'persistence_failed' });
  assert.equal(client.snapshot().needsImport, true); assert.deepEqual(host.local, local); assert.equal(host.config, null);
  await client.importFile(fileText(vault)); assert.equal(client.snapshot().needsImport, false);
});

test('server configuration alone does not enable networking; server mode synchronizes ciphertext only', async () => {
  const host = memoryHost(), client = await createVaultClient(host);
  await client.save(entry('never-cloud-plaintext'));
  await assert.rejects(client.setMode('server'), { code: 'server_not_configured' });
  await client.configureServer({ endpoint: 'https://vault.example.com/', token: host.config.token });
  assert.equal(client.snapshot().mode, 'file'); await client.sync(); assert.equal(host.requests.length, 0);
  await client.setMode('server'); await client.sync();
  assert.equal(client.snapshot().mode, 'server'); assert.equal(client.snapshot().status, 'synced');
  assert.ok(!JSON.stringify(host.requests).includes('never-cloud-plaintext'));
  assert.ok(!JSON.stringify(host.requests).includes(host.config.keyB64));
  await client.setMode('file'); const requestCount = host.requests.length;
  await client.save(entry('file-only'), client.snapshot().records[0].id); await client.sync();
  assert.equal(host.requests.length, requestCount);
});

test('switching to file mode waits for an active sync, retains concurrent edits, and prevents later network activity', async () => {
  const host = memoryHost(profile({ mode: 'server', endpoint: 'https://vault.example.com' })), client = await createVaultClient(host);
  const started = deferred(), release = deferred(), normalRequest = host.request.bind(host);
  let hold = true;
  host.request = async (...args) => { if (args[0] === 'GET' && hold) { hold = false; started.resolve(); await release.promise; } return normalRequest(...args); };
  const id = await client.save(entry('before')); await started.promise;
  const switching = client.setMode('file');
  await client.save(entry('during'), id);
  assert.equal(client.snapshot().mode, 'server');
  release.resolve(); await switching;
  assert.equal(client.snapshot().mode, 'file'); assert.equal(client.snapshot().records[0].entry.password, 'during');
  const requestCount = host.requests.length; await client.sync(); await client.save(entry('after'), id); await client.sync();
  assert.equal(host.requests.length, requestCount);
  assert.equal(host.config.mode, 'file');
});

test('mode and connection persistence failures never change the effective networking profile', async () => {
  const host = memoryHost(profile({ endpoint: 'https://old.example.com' })), client = await createVaultClient(host);
  host.failWrites = 1;
  await assert.rejects(client.setMode('server'), { code: 'persistence_failed' });
  assert.equal(client.snapshot().mode, 'file'); assert.equal(host.config.mode, 'file'); assert.equal(host.requests.length, 0);
  host.failWrites = 1;
  await assert.rejects(client.configureServer({ endpoint: 'https://new.example.com', token: TOKEN }), { code: 'persistence_failed' });
  assert.equal(client.snapshot().serverEndpoint, 'https://old.example.com');
  assert.equal(host.config.endpoint, 'https://old.example.com'); assert.equal(host.requests.length, 0);
});

test('connection validation rejects plaintext transport, embedded credentials and subpaths before any write', async () => {
  const host = memoryHost(profile()), client = await createVaultClient(host), originalWrites = host.writes;
  for (const endpoint of [null, '', 'http://example.com', 'https://user:pass@example.com', 'https://example.com?x=1',
    'https://example.com#fragment', 'https://example.com/subpath', 'file:///tmp/file'])
    await assert.rejects(client.configureServer({ endpoint, token: TOKEN }), { code: 'invalid_config' });
  await assert.rejects(client.configureServer({ endpoint: 'https://example.com', token: 'invalid token' }), { code: 'invalid_config' });
  assert.equal(host.writes, originalWrites); assert.equal(host.requests.length, 0);
});

test('export includes edits from the serial queue even after a local disk failure', async () => {
  const host = memoryHost(profile()), client = await createVaultClient(host); host.failWrites = 1;
  const saving = client.save(entry('rescue-secret')); const exporting = client.exportFile();
  await assert.rejects(saving, { code: 'persistence_failed' });
  assert.equal(listRecords(parsePortableFile(await exporting).vault)[0].entry.password, 'rescue-secret');
  assert.equal(host.requests.length, 0);
  await client.sync();
  assert.equal(listRecords(await decryptVault(host.local.envelope, KEY, profile().vaultId))[0].entry.password, 'rescue-secret');
});
