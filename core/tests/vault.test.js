import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createVault, mergeVaults, listRecords, writeRecord, deleteRecord, resolveRecord,
  encryptVault, decryptVault, createVaultClient,
} from '../vault.js';

// These intentionally public test keys have no relationship to an installation.
const KEY = Buffer.alloc(32, 42).toString('base64');
const OTHER_KEY = Buffer.alloc(32, 43).toString('base64');
const VAULT_ID = 'test-vault';
const entry = (password = 'initial-secret', title = 'Example') => ({ title, username: 'alice', password, url: 'https://example.com', notes: '' });
const clone = value => structuredClone(value);
const firstId = vault => Object.keys(vault.records)[0];
function baseVault() { return writeRecord(createVault(VAULT_ID), null, entry(), 'device_a'); }
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }

function makeServer() {
  return {
    revision: 0, envelope: null, requests: [], collisions: 0,
    async request(method, path, body) {
      assert.equal(path, '/v1/vault');
      this.requests.push({ method, body: body && clone(body) });
      if (method === 'GET') return { status: 200, body: { revision: this.revision, envelope: clone(this.envelope) } };
      assert.equal(method, 'PUT');
      if (this.collisions > 0) { this.collisions--; this.revision++; return { status: 409, body: { error: 'revision_conflict' } }; }
      if (body.expectedRevision !== this.revision) return { status: 409, body: { error: 'revision_conflict' } };
      this.envelope = clone(body.envelope); this.revision++;
      return { status: 200, body: { revision: this.revision } };
    },
  };
}
function makeHost(server = makeServer(), options = {}) {
  const host = {
    server, storage: options.local ? clone(options.local) : null, writes: [], offline: false, failWrites: 0,
    async getConfig() { return { vaultId: VAULT_ID, keyB64: KEY, token: 'test-only-token', endpoint: options.unconfigured ? null : 'http://127.0.0.1:9876' }; },
    async readLocal() { return clone(this.storage); },
    async writeLocal(value) {
      if (this.failWrites > 0) { this.failWrites--; throw new Error('test disk failure'); }
      this.storage = clone(value); this.writes.push(clone(value));
    },
    async request(...args) { if (this.offline) throw new Error('test offline'); return this.server.request(...args); },
  };
  return host;
}

test('two offline edits of the same record remain conflicting, independent of timestamps', () => {
  const initial = baseVault(), id = firstId(initial);
  const a = writeRecord(initial, id, entry('computer-secret'), 'device_a');
  const b = writeRecord(initial, id, entry('phone-secret'), 'device_b');
  b.records[id][0].updatedAt = '2000-01-01T00:00:00.000Z';
  const merged = mergeVaults(a, b), record = listRecords(merged)[0];
  assert.equal(record.conflict, true);
  assert.deepEqual(record.versions.map(v => v.entry.password).sort(), ['computer-secret', 'phone-secret']);
  assert.deepEqual(mergeVaults(a, b), mergeVaults(b, a));
  assert.deepEqual(mergeVaults(merged, merged), merged);
  assert.throws(() => writeRecord(merged, id, entry('bad-overwrite'), 'device_a'), { code: 'conflict_requires_resolution' });
  assert.throws(() => deleteRecord(merged, id, 'device_a'), { code: 'conflict_requires_resolution' });
});

test('offline edits to different records merge without a conflict', () => {
  const a = writeRecord(createVault(VAULT_ID), null, entry('a', 'A'), 'device_a');
  const b = writeRecord(createVault(VAULT_ID), null, entry('b', 'B'), 'device_b');
  assert.deepEqual(listRecords(mergeVaults(a, b)).map(r => [r.entry.title, r.conflict]), [['A', false], ['B', false]]);
});

test('deletion retains a tombstone and an unchanged old device cannot revive it', () => {
  const initial = baseVault(), id = firstId(initial);
  const deleted = deleteRecord(initial, id, 'device_a');
  assert.equal(listRecords(mergeVaults(deleted, initial)).length, 0);
  assert.equal(deleted.records[id][0].kind, 'delete');
  assert.equal(deleted.records[id][0].entry, null);
  assert.ok(!JSON.stringify(deleted).includes('initial-secret'));
  assert.throws(() => writeRecord(deleted, id, entry('resurrect'), 'device_a'), { code: 'record_not_found' });
});

test('delete versus edit is visible, and resolving either choice converges with stale devices', () => {
  const initial = baseVault(), id = firstId(initial);
  const deleted = deleteRecord(initial, id, 'device_a');
  const edited = writeRecord(initial, id, entry('phone-secret'), 'device_b');
  const conflicting = mergeVaults(deleted, edited);
  const record = listRecords(conflicting)[0];
  assert.equal(record.conflict, true);
  assert.deepEqual(record.versions.map(v => v.kind).sort(), ['delete', 'put']);
  for (const choice of record.versions) {
    const resolved = resolveRecord(conflicting, id, choice.id, 'device_a');
    assert.equal(resolved.records[id].length, 1);
    assert.deepEqual(mergeVaults(resolved, deleted), resolved);
    assert.deepEqual(mergeVaults(resolved, edited), resolved);
    assert.deepEqual(mergeVaults(resolved, conflicting), resolved);
    assert.equal(listRecords(resolved).length, choice.kind === 'delete' ? 0 : 1);
  }
});

test('resolved edits keep causal IDs but discard losing and previous password contents', () => {
  const initial = baseVault(), id = firstId(initial);
  const a = writeRecord(initial, id, entry('chosen-secret'), 'device_a');
  const b = writeRecord(initial, id, entry('losing-secret'), 'device_b');
  const conflict = mergeVaults(a, b);
  const resolved = resolveRecord(conflict, id, a.records[id][0].id, 'device_a');
  const json = JSON.stringify(resolved);
  assert.ok(json.includes('chosen-secret'));
  assert.ok(!json.includes('initial-secret'));
  assert.ok(!json.includes('losing-secret'));
  assert.equal(resolved.records[id][0].ancestors.length, 3);
  const next = writeRecord(resolved, id, entry('latest-secret'), 'device_a');
  assert.ok(!JSON.stringify(next).includes('chosen-secret'));
});

test('AES-GCM authenticates ciphertext, key, nonce and vault identity', async () => {
  const vault = baseVault(), envelope = await encryptVault(vault, KEY);
  assert.deepEqual(await decryptVault(envelope, KEY, VAULT_ID), mergeVaults(vault, vault));
  assert.ok(!JSON.stringify(envelope).includes('initial-secret'));
  const another = await encryptVault(vault, KEY);
  assert.notEqual(envelope.nonce, another.nonce);
  await assert.rejects(decryptVault(envelope, OTHER_KEY, VAULT_ID), { code: 'decrypt_failed' });
  const tampered = clone(envelope), bytes = Buffer.from(tampered.data, 'base64');
  bytes[0] ^= 1; tampered.data = bytes.toString('base64');
  await assert.rejects(decryptVault(tampered, KEY, VAULT_ID), { code: 'decrypt_failed' });
  await assert.rejects(decryptVault(envelope, KEY, 'other-vault'), { code: 'invalid_envelope' });
  const wrongNonce = clone(envelope); wrongNonce.nonce = Buffer.alloc(12).toString('base64');
  await assert.rejects(decryptVault(wrongNonce, KEY, VAULT_ID), { code: 'decrypt_failed' });
});

test('malformed entries, states, IDs and encrypted envelopes are rejected', async () => {
  assert.throws(() => createVault('__proto__'), { code: 'invalid_vault' });
  assert.throws(() => writeRecord(createVault(VAULT_ID), null, { ...entry(), title: ' ' }, 'device_a'), { code: 'invalid_entry' });
  assert.throws(() => writeRecord(createVault(VAULT_ID), null, { ...entry(), password: 'x'.repeat(4097) }, 'device_a'), { code: 'invalid_entry' });
  assert.throws(() => writeRecord(createVault(VAULT_ID), null, { ...entry(), accidentalSecret: 'x' }, 'device_a'), { code: 'invalid_entry' });
  const v = baseVault(), id = firstId(v), invalid = clone(v);
  invalid.records[id][0].ancestors = [invalid.records[id][0].id];
  assert.throws(() => listRecords(invalid), { code: 'invalid_vault' });
  const collision = clone(v); collision.records[id][0].entry.password = 'different';
  assert.throws(() => mergeVaults(v, collision), { code: 'invalid_vault' });
  const envelope = await encryptVault(v, KEY);
  await assert.rejects(decryptVault({ ...envelope, data: 'not-base64' }, KEY, VAULT_ID), { code: 'invalid_envelope' });
  await assert.rejects(decryptVault({ ...envelope, nonce: 'AAAA' }, KEY, VAULT_ID), { code: 'invalid_envelope' });
  await assert.rejects(decryptVault(envelope, Buffer.alloc(16).toString('base64'), VAULT_ID), { code: 'invalid_config' });
});

test('client runs locally without cloud configuration and snapshots cannot mutate the vault', async () => {
  const host = makeHost(undefined, { unconfigured: true });
  const client = await createVaultClient(host);
  let calls = 0; const unsubscribe = client.subscribe(() => calls++);
  const id = await client.save(entry('local-secret'));
  const snapshot = client.snapshot();
  assert.equal(snapshot.configured, false); assert.equal(snapshot.pending, true); assert.equal(snapshot.status, 'local');
  assert.equal(snapshot.records[0].id, id);
  snapshot.records[0].entry.password = 'mutated';
  assert.equal(client.snapshot().records[0].entry.password, 'local-secret');
  assert.equal(host.server.requests.length, 0);
  assert.ok(!JSON.stringify(host.storage).includes('local-secret'));
  await client.sync(); unsubscribe(); assert.ok(calls >= 2);
  const reopened = await createVaultClient(host);
  assert.equal(reopened.snapshot().records[0].entry.password, 'local-secret');
});

test('corrupted local state rejects initialization without replacing the stored file', async () => {
  const host = makeHost();
  host.storage = { deviceId: 'device_a', envelope: { v: 1, vaultId: VAULT_ID, alg: 'A256GCM', nonce: 'broken', data: 'broken' } };
  const before = clone(host.storage);
  await assert.rejects(createVaultClient(host), { code: 'invalid_envelope' });
  assert.deepEqual(host.storage, before); assert.equal(host.writes.length, 0);
});

test('two actual clients converge after offline concurrent edits and a resolution', async () => {
  const server = makeServer(), hostA = makeHost(server), a = await createVaultClient(hostA);
  const id = await a.save(entry()); await a.sync();
  const hostB = makeHost(server, { local: { deviceId: 'device_b', envelope: hostA.storage.envelope } });
  const b = await createVaultClient(hostB);
  hostA.offline = true; hostB.offline = true;
  await a.save(entry('computer-secret'), id); await a.sync();
  await b.save(entry('phone-secret'), id); await b.sync();
  assert.equal(a.snapshot().status, 'offline'); assert.equal(a.snapshot().pending, true);
  hostA.offline = false; hostB.offline = false;
  await a.sync(); await b.sync(); await a.sync();
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  assert.equal(a.snapshot().records[0].conflict, true);
  const chosen = a.snapshot().records[0].versions.find(v => v.entry.password === 'phone-secret');
  await a.resolve(id, chosen.id); await a.sync(); await b.sync();
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  assert.equal(b.snapshot().records[0].entry.password, 'phone-secret');
  assert.equal(b.snapshot().records[0].conflict, false);
});

test('CAS retries reread and merge, while the network sees only ciphertext', async () => {
  const server = makeServer(); server.collisions = 2;
  const host = makeHost(server), client = await createVaultClient(host);
  await client.save(entry('network-secret')); await client.sync();
  assert.equal(client.snapshot().status, 'synced'); assert.equal(client.snapshot().pending, false);
  assert.ok(server.requests.filter(r => r.method === 'GET').length >= 3);
  assert.ok(!JSON.stringify(server.requests).includes('network-secret'));
  assert.equal(listRecords(await decryptVault(server.envelope, KEY, VAULT_ID))[0].entry.password, 'network-secret');
});

test('an edit during an in-flight upload persists immediately and is included before synced', async () => {
  const server = makeServer(), host = makeHost(server), client = await createVaultClient(host);
  const putStarted = deferred(), releasePut = deferred();
  const normalRequest = server.request.bind(server);
  let holdFirstPut = true;
  server.request = async (...args) => {
    if (args[0] === 'PUT' && holdFirstPut) { holdFirstPut = false; putStarted.resolve(); await releasePut.promise; }
    return normalRequest(...args);
  };
  const id = await client.save(entry('first-secret'));
  await putStarted.promise;
  await client.save(entry('second-secret'), id);
  const diskDuringUpload = await decryptVault(host.storage.envelope, KEY, VAULT_ID);
  assert.equal(listRecords(diskDuringUpload)[0].entry.password, 'second-secret');
  assert.equal(client.snapshot().pending, true);
  releasePut.resolve(); await client.sync();
  assert.equal(client.snapshot().status, 'synced'); assert.equal(client.snapshot().pending, false);
  assert.equal(listRecords(await decryptVault(server.envelope, KEY, VAULT_ID))[0].entry.password, 'second-secret');
});

test('an edit while downloading remote state is merged without being lost', async () => {
  const server = makeServer(), remote = writeRecord(createVault(VAULT_ID), null, entry('remote', 'Remote'), 'device_b');
  server.envelope = await encryptVault(remote, KEY); server.revision = 1;
  const host = makeHost(server), client = await createVaultClient(host);
  const getStarted = deferred(), releaseGet = deferred();
  const normalRequest = server.request.bind(server);
  let holdFirstGet = true;
  server.request = async (...args) => {
    if (args[0] === 'GET' && holdFirstGet) { holdFirstGet = false; getStarted.resolve(); await releaseGet.promise; }
    return normalRequest(...args);
  };
  const sync = client.sync(); await getStarted.promise;
  await client.save(entry('local', 'Local'));
  releaseGet.resolve(); await sync;
  assert.deepEqual(client.snapshot().records.map(r => r.entry.title), ['Local', 'Remote']);
  assert.deepEqual(listRecords(await decryptVault(server.envelope, KEY, VAULT_ID)).map(r => r.entry.title), ['Local', 'Remote']);
});

test('persistence failure retains the current edit, rejects save, and retries disk before uploading', async () => {
  const server = makeServer(), host = makeHost(server), client = await createVaultClient(host);
  host.failWrites = 1;
  await assert.rejects(client.save(entry('unsaved-secret')), { code: 'persistence_failed' });
  assert.equal(client.snapshot().records[0].entry.password, 'unsaved-secret');
  assert.equal(client.snapshot().status, 'error'); assert.equal(client.snapshot().pending, true);
  assert.equal(server.requests.length, 0);
  assert.equal(listRecords(await decryptVault(host.storage.envelope, KEY, VAULT_ID)).length, 0);
  await client.sync();
  assert.equal(client.snapshot().status, 'synced'); assert.equal(client.snapshot().pending, false);
  assert.equal(listRecords(await decryptVault(host.storage.envelope, KEY, VAULT_ID))[0].entry.password, 'unsaved-secret');
  assert.equal(listRecords(await decryptVault(server.envelope, KEY, VAULT_ID))[0].entry.password, 'unsaved-secret');
});

test('a failed disk merge never uploads or reports synced and leaves local edits available', async () => {
  const server = makeServer(), host = makeHost(server), client = await createVaultClient(host);
  host.offline = true; await client.save(entry('local', 'Local')); await client.sync(); host.offline = false;
  server.envelope = await encryptVault(writeRecord(createVault(VAULT_ID), null, entry('remote', 'Remote'), 'device_b'), KEY);
  server.revision = 1; host.failWrites = 1;
  await client.sync();
  assert.equal(client.snapshot().status, 'error'); assert.equal(client.snapshot().pending, true);
  assert.deepEqual(client.snapshot().records.map(r => r.entry.title), ['Local', 'Remote']);
  assert.equal(server.requests.filter(r => r.method === 'PUT').length, 0);
  await client.sync();
  assert.equal(client.snapshot().status, 'synced');
  assert.deepEqual(listRecords(await decryptVault(server.envelope, KEY, VAULT_ID)).map(r => r.entry.title), ['Local', 'Remote']);
});

test('bad remote ciphertext does not clear or overwrite a healthy local password library', async () => {
  const server = makeServer(), host = makeHost(server), client = await createVaultClient(host);
  await client.save(entry('healthy')); await client.sync();
  const diskBefore = clone(host.storage);
  server.envelope.data = Buffer.alloc(32, 7).toString('base64');
  await client.sync();
  assert.equal(client.snapshot().status, 'error');
  assert.equal(client.snapshot().records[0].entry.password, 'healthy');
  assert.deepEqual(host.storage, diskBefore);
});

test('authorization failure is distinguishable from an offline connection', async () => {
  const host = makeHost(); host.request = async () => ({ status: 401, body: { error: 'unauthorized' } });
  const client = await createVaultClient(host);
  await client.save(entry()); await client.sync();
  assert.equal(client.snapshot().status, 'error'); assert.equal(client.snapshot().pending, true);
  assert.match(client.snapshot().message, /凭据/);
});

test('sync subscriptions can reenter sync without starting parallel network requests', async () => {
  const host = makeHost(), client = await createVaultClient(host);
  let reentered = false;
  client.subscribe(snapshot => { if (snapshot.status === 'syncing' && !reentered) { reentered = true; void client.sync(); } });
  await client.sync();
  assert.equal(host.server.requests.length, 1); assert.equal(client.snapshot().status, 'synced');
});

test('a three-version causal cycle and cross-record ancestor claims are rejected', () => {
  const initial = baseVault(), id = firstId(initial), cycle = clone(initial);
  const template = cycle.records[id][0];
  cycle.records[id] = ['one', 'two', 'three'].map((name, i) => ({ ...clone(template), id: name,
    ancestors: [['two'], ['three'], ['one']][i] }));
  assert.throws(() => listRecords(cycle), { code: 'invalid_vault' });
  const other = writeRecord(initial, null, entry('other', 'Other'), 'device_a');
  const otherId = Object.keys(other.records).find(record => record !== id);
  other.records[id][0].ancestors = [other.records[otherId][0].id];
  assert.throws(() => listRecords(other), { code: 'invalid_vault' });
});

test('the ciphertext size budget is enforced before adopting or writing a new edit', async () => {
  const oversized = createVault(VAULT_ID);
  const largeEntry = { ...entry('size-test-secret'), notes: 'n'.repeat(16384) };
  let lastGood;
  for (let i = 0; i < 300; i++) {
    oversized.records[`record_${i}`] = [{ id: `version_${i}`, ancestors: [], kind: 'put', entry: largeEntry,
      deviceId: 'device_a', updatedAt: '2026-01-01T00:00:00.000Z' }];
    if (Buffer.byteLength(JSON.stringify(oversized)) > 4 * 1024 * 1024 - 16) break;
    lastGood = clone(oversized);
  }
  await assert.rejects(encryptVault(oversized, KEY), { code: 'vault_too_large' });
  const host = makeHost(undefined, { unconfigured: true, local: {
    deviceId: 'device_a', envelope: await encryptVault(lastGood, KEY),
  } });
  const client = await createVaultClient(host), originalCount = client.snapshot().records.length;
  await assert.rejects(client.save(largeEntry), { code: 'vault_too_large' });
  assert.equal(client.snapshot().records.length, originalCount);
  assert.equal(host.writes.length, 0);
  assert.equal(host.server.requests.length, 0);
});
