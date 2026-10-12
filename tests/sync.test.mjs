import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createVaultServer } from '../server/server.mjs';
import {
  createVaultClient, encryptVault, decryptVault, listRecords, createVault, writeRecord, deleteRecord, mergeVaults, parsePortableFile,
} from '../core/vault.js';

const TEMPORARY_ROOT = await realpath(os.tmpdir());
const entry = (password, title = 'Audit') => ({ title, username: 'dummy-user', password,
  url: 'https://example.invalid', notes: '' });
const deferred = () => {
  let resolve;
  const promise = new Promise((finish) => { resolve = finish; });
  return { promise, resolve };
};

async function setup(t) {
  const dataDir = await mkdtemp(path.join(TEMPORARY_ROOT, 'private-vault-sync-test-'));
  const vaultId = randomUUID();
  const keyB64 = randomBytes(32).toString('base64');
  const token = 'public-audit-dummy-token';
  const tokenHash = createHash('sha256').update(token).digest('hex');
  const server = createVaultServer({ dataDir, vaultId, tokenHash });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
    const absolute = await realpath(dataDir);
    assert.equal(path.dirname(absolute), TEMPORARY_ROOT);
    assert.ok(path.basename(absolute).startsWith('private-vault-sync-test-'));
    await rm(absolute, { recursive: true, force: true });
  });
  const hosts = [];
  function host(local = null) {
    const result = {
      storage: structuredClone(local), offline: false, requests: [], before: null, after: null,
      async getConfig() { return { vaultId, keyB64, token, endpoint }; },
      async readLocal() { return structuredClone(this.storage); },
      async writeLocal(value) { this.storage = structuredClone(value); },
      async request(method, route, body) {
        if (this.offline) throw new Error('dummy offline');
        if (this.before) await this.before(method);
        const response = await fetch(endpoint + route, {
          method,
          headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
          ...(body ? { body: JSON.stringify(body) } : {}),
        });
        const answer = { status: response.status, body: await response.json() };
        this.requests.push({ method, body: structuredClone(body), answer: structuredClone(answer) });
        if (this.after) await this.after(method, answer);
        return answer;
      },
    };
    hosts.push(result);
    return result;
  }
  async function remote() {
    const response = await fetch(endpoint + '/v1/vault', { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(response.status, 200);
    const body = await response.json();
    return { ...body, vault: await decryptVault(body.envelope, keyB64, vaultId) };
  }
  return { dataDir, vaultId, keyB64, token, hosts, host, remote };
}

test('public file-mode clients exchange a complete library and later synchronize only ciphertext with a real server', async t => {
  const fixture = await setup(t);
  function runtimeHost(initialProfile) {
    const host = fixture.host();
    host.profile = structuredClone(initialProfile);
    host.getConfig = async () => structuredClone(host.profile);
    host.writeState = async (profile, local) => { host.profile = structuredClone(profile); host.storage = structuredClone(local); };
    const realRequest = host.request.bind(host);
    host.request = async (...args) => {
      assert.equal(host.profile.mode, 'server', 'file mode must not issue a network request');
      return realRequest(...args);
    };
    return host;
  }
  const connection = await fixture.host().getConfig();
  const hostA = runtimeHost({ ...connection, mode: 'file' }), a = await createVaultClient(hostA);
  const id = await a.save(entry('portable-http-initial')); await a.sync();
  assert.equal(hostA.requests.length, 0);
  const portable = await a.exportFile();
  assert.equal(parsePortableFile(portable).profile.keyB64, fixture.keyB64);
  assert.ok(portable.includes('portable-http-initial'));
  const hostB = runtimeHost(null), b = await createVaultClient(hostB), deviceB = hostB.storage.deviceId;
  await b.importFile(portable);
  assert.equal(hostB.storage.deviceId, deviceB); assert.equal(b.snapshot().mode, 'file'); assert.equal(hostB.requests.length, 0);
  await b.setMode('server'); await b.sync();
  await a.setMode('server'); await a.sync();
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  await a.setMode('file'); await b.setMode('file');
  const requestsBefore = fixture.hosts.flatMap(host => host.requests).length;
  await a.save(entry('portable-http-a'), id); await b.save(entry('portable-http-b'), id);
  await a.importFile(await b.exportFile()); await b.importFile(await a.exportFile());
  assert.equal(fixture.hosts.flatMap(host => host.requests).length, requestsBefore);
  assert.equal(a.snapshot().records[0].conflict, true);
  await a.setMode('server'); await a.sync(); await b.setMode('server'); await b.sync();
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  const current = await fixture.remote();
  assert.deepEqual(listRecords(current.vault), a.snapshot().records);
  const disk = await readFile(path.join(fixture.dataDir, 'vault-state.json'), 'utf8');
  const requestBodies = JSON.stringify(fixture.hosts.flatMap(host => host.requests.map(request => request.body)));
  for (const secret of ['portable-http-initial', 'portable-http-a', 'portable-http-b', fixture.keyB64, fixture.token]) {
    assert.ok(!disk.includes(secret)); assert.ok(!requestBodies.includes(secret));
  }
});

test('real HTTP concurrent CAS preserves both offline password edits and a selected resolution', async (t) => {
  const fixture = await setup(t);
  const hostA = fixture.host();
  const a = await createVaultClient(hostA);
  const id = await a.save(entry('audit-initial-password')); await a.sync();
  const hostB = fixture.host(); const b = await createVaultClient(hostB); await b.sync();
  hostA.offline = true; hostB.offline = true;
  await a.save(entry('audit-computer-password'), id); await a.sync();
  await b.save(entry('audit-phone-password'), id); await b.sync();
  hostA.offline = false; hostB.offline = false;
  const release = deferred(), capturedA = deferred(), capturedB = deferred();
  for (const [host, captured] of [[hostA, capturedA], [hostB, capturedB]]) {
    let once = true;
    host.after = async (method) => {
      if (method === 'GET' && once) { once = false; captured.resolve(); await release.promise; }
    };
  }
  const syncA = a.sync(), syncB = b.sync();
  await Promise.all([capturedA.promise, capturedB.promise]); release.resolve();
  await Promise.all([syncA, syncB]);
  assert.ok(fixture.hosts.flatMap((host) => host.requests).some(({ answer }) => answer.status === 409));
  await a.sync(); await b.sync();
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  assert.deepEqual(a.snapshot().records[0].versions.map((v) => v.entry.password).sort(),
    ['audit-computer-password', 'audit-phone-password']);
  const chosen = a.snapshot().records[0].versions.find((v) => v.entry.password === 'audit-phone-password');
  await a.resolve(id, chosen.id); await a.sync(); await b.sync();
  assert.equal(b.snapshot().records[0].entry.password, 'audit-phone-password');
  assert.equal(b.snapshot().records[0].conflict, false);
  const current = await fixture.remote();
  assert.equal(listRecords(current.vault)[0].entry.password, 'audit-phone-password');
  const disk = await readFile(path.join(fixture.dataDir, 'vault-state.json'), 'utf8');
  const network = JSON.stringify(fixture.hosts.flatMap((host) => host.requests));
  for (const value of ['audit-initial-password', 'audit-computer-password', 'audit-phone-password', fixture.keyB64, fixture.token]) {
    assert.ok(!disk.includes(value)); assert.ok(!network.includes(value));
  }
});

test('real server preserves delete/edit conflicts and a stale offline device cannot revive a resolved deletion', async (t) => {
  const fixture = await setup(t), hostA = fixture.host(), a = await createVaultClient(hostA);
  const id = await a.save(entry('audit-delete-initial')); await a.sync();
  const staleLocal = structuredClone(hostA.storage);
  const hostB = fixture.host(), b = await createVaultClient(hostB); await b.sync();
  hostA.offline = true; hostB.offline = true;
  await a.remove(id); await a.sync();
  await b.save(entry('audit-offline-edit'), id); await b.sync();
  hostA.offline = false; hostB.offline = false;
  await a.sync(); await b.sync(); await a.sync();
  const conflict = a.snapshot().records[0];
  assert.equal(conflict.conflict, true);
  assert.deepEqual(conflict.versions.map((v) => v.kind).sort(), ['delete', 'put']);
  await a.resolve(id, conflict.versions.find((v) => v.kind === 'delete').id); await a.sync(); await b.sync();
  const hostC = fixture.host({ ...staleLocal, deviceId: 'audit_stale_device' });
  const c = await createVaultClient(hostC); await c.sync(); await a.sync();
  assert.equal(a.snapshot().records.length, 0);
  assert.equal(b.snapshot().records.length, 0);
  assert.equal(c.snapshot().records.length, 0);
  const current = await fixture.remote();
  assert.equal(current.vault.records[id][0].kind, 'delete');
  assert.equal(current.vault.records[id][0].entry, null);
});

test('edits during actual GET and PUT survive, including a server CAS collision caused by another device', async (t) => {
  const fixture = await setup(t), hostA = fixture.host(), a = await createVaultClient(hostA);
  const id = await a.save(entry('audit-old')); await a.sync();
  const hostB = fixture.host(), b = await createVaultClient(hostB); await b.sync();
  await b.save(entry('audit-remote', 'Remote')); await b.sync();
  const getCaptured = deferred(), releaseGet = deferred(); let firstGet = true;
  hostA.after = async (method) => {
    if (method === 'GET' && firstGet) { firstGet = false; getCaptured.resolve(); await releaseGet.promise; }
  };
  const syncGet = a.sync(); await getCaptured.promise;
  await a.save(entry('audit-local-during-get', 'Local during GET'));
  releaseGet.resolve(); await syncGet; hostA.after = null;
  assert.equal(a.snapshot().records.length, 3);
  assert.equal(listRecords((await fixture.remote()).vault).length, 3);

  const putStarted = deferred(), releasePut = deferred(); let firstPut = true;
  hostA.before = async (method) => {
    if (method === 'PUT' && firstPut) { firstPut = false; putStarted.resolve(); await releasePut.promise; }
  };
  await a.save(entry('audit-edit-one'), id); await putStarted.promise;
  await a.save(entry('audit-edit-two'), id);
  assert.equal(listRecords(await decryptVault(hostA.storage.envelope, fixture.keyB64, fixture.vaultId))
    .find((r) => r.id === id).entry.password, 'audit-edit-two');
  await b.save(entry('audit-other-during-put', 'Other during PUT')); await b.sync();
  releasePut.resolve(); await a.sync(); hostA.before = null; await b.sync();
  assert.equal(a.snapshot().status, 'synced'); assert.equal(a.snapshot().pending, false);
  assert.deepEqual(a.snapshot().records, b.snapshot().records);
  const cloudRecords = listRecords((await fixture.remote()).vault);
  assert.equal(cloudRecords.length, 4);
  assert.equal(cloudRecords.find((r) => r.id === id).entry.password, 'audit-edit-two');
  assert.ok(hostA.requests.some(({ answer }) => answer.status === 409));
});

test('valid causal branches merge associatively and keep delete/edit heads until resolved', () => {
  const initial = writeRecord(createVault('audit-vault'), null, entry('audit-base'), 'audit_device');
  const id = Object.keys(initial.records)[0];
  const branchA = writeRecord(writeRecord(initial, id, entry('audit-a1'), 'audit_a'), id, entry('audit-a2'), 'audit_a');
  const branchB = deleteRecord(initial, id, 'audit_b');
  const branchC = writeRecord(initial, id, entry('audit-c'), 'audit_c');
  const expected = mergeVaults(mergeVaults(branchA, branchB), branchC);
  assert.deepEqual(expected, mergeVaults(branchA, mergeVaults(branchB, branchC)));
  assert.deepEqual(expected, mergeVaults(branchC, mergeVaults(branchB, branchA)));
  assert.deepEqual(mergeVaults(expected, initial), expected);
  assert.deepEqual(expected.records[id].map((head) => head.kind).sort(), ['delete', 'put', 'put']);
});

test('a near-4-MiB encrypted core vault round-trips through the real server and oversized edits remain unadopted', async (t) => {
  const fixture = await setup(t);
  const vault = createVault(fixture.vaultId);
  const largeEntry = { ...entry('audit-size-password'), notes: 'n'.repeat(16384) };
  const plaintextLimit = 4 * 1024 * 1024 - 16;
  let index = 0;
  while (true) {
    const recordId = `size_record_${index}`;
    vault.records[recordId] = [{ id: `size_version_${index}`, ancestors: [], kind: 'put', entry: largeEntry,
      deviceId: 'audit_size_device', updatedAt: '2026-01-01T00:00:00.000Z' }];
    if (Buffer.byteLength(JSON.stringify(vault)) > plaintextLimit) { delete vault.records[recordId]; break; }
    index++;
  }
  assert.ok(Buffer.byteLength(JSON.stringify(vault)) > plaintextLimit - 20000);
  const host = fixture.host({ deviceId: 'audit_size_device', envelope: await encryptVault(vault, fixture.keyB64) });
  const client = await createVaultClient(host); await client.sync();
  assert.equal(client.snapshot().status, 'synced'); assert.equal(client.snapshot().pending, false);
  const cloud = await fixture.remote();
  assert.equal(cloud.revision, 1);
  assert.equal(listRecords(cloud.vault).length, index);
  const before = structuredClone(host.storage);
  await assert.rejects(client.save(largeEntry), { code: 'vault_too_large' });
  assert.deepEqual(host.storage, before);
  assert.equal(client.snapshot().records.length, index);
  assert.equal((await fixture.remote()).revision, 1);
});
