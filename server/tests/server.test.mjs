import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createCipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createVaultServer, MAX_CIPHERTEXT_BYTES, MAX_REQUEST_BYTES } from '../server.mjs';

const MOCK_PASSWORD = 'synthetic-test-password-not-a-real-secret';

function envelopeFor(vaultId, label = '') {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(`private-vault/v1/${vaultId}`));
  const plaintext = Buffer.from(JSON.stringify({ password: MOCK_PASSWORD, label }));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return {
    envelope: { v: 1, vaultId, alg: 'A256GCM', nonce: nonce.toString('base64'), data: ciphertext.toString('base64') },
    keyB64: key.toString('base64'),
  };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

async function fixture(t) {
  const temporaryRoot = await realpath(os.tmpdir());
  const dataDir = await mkdtemp(path.join(temporaryRoot, 'private-vault-server-test-'));
  const vaultId = randomUUID();
  const token = `mock-token-${randomUUID()}`;
  const tokenHash = createHash('sha256').update(token).digest('hex');
  let server = createVaultServer({ dataDir, vaultId, tokenHash });
  let endpoint = await listen(server);
  t.after(async () => {
    await close(server);
    const resolvedDirectory = await realpath(dataDir);
    // Verify the absolute deletion target is the test's immediate temp child.
    assert.equal(path.dirname(resolvedDirectory), temporaryRoot);
    assert.ok(path.basename(resolvedDirectory).startsWith('private-vault-server-test-'));
    await rm(resolvedDirectory, { recursive: true, force: true });
  });
  return {
    dataDir, vaultId, token, tokenHash,
    get server() { return server; },
    get endpoint() { return endpoint; },
    async restart() {
      await close(server);
      server = createVaultServer({ dataDir, vaultId, tokenHash });
      endpoint = await listen(server);
    },
    async request(method, route = '/v1/vault', body, options = {}) {
      const response = await fetch(endpoint + route, {
        method,
        headers: {
          ...(options.authorized === false ? {} : { Authorization: `Bearer ${options.token ?? token}` }),
          ...(body === undefined ? {} : { 'Content-Type': options.contentType ?? 'application/json' }),
        },
        ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
      });
      return { status: response.status, headers: response.headers, body: await response.json() };
    },
  };
}

async function rawRequest(endpoint, headers, bytes) {
  return new Promise((resolve, reject) => {
    let answered = false;
    const request = http.request(endpoint + '/v1/vault', { method: 'PUT', headers }, (response) => {
      const parts = [];
      response.on('data', (part) => parts.push(part));
      response.on('end', () => {
        answered = true;
        resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(parts).toString('utf8')) });
      });
    });
    request.on('error', (error) => { if (!answered) reject(error); });
    if (bytes) request.write(bytes);
    request.end();
  });
}

test('health is public, while encrypted state requires the correct bearer token', async (t) => {
  const vault = await fixture(t);
  const health = await vault.request('GET', '/health', undefined, { authorized: false });
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, { ok: true });
  for (const options of [{ authorized: false }, { token: 'wrong-token' }]) {
    const response = await vault.request('GET', '/v1/vault', undefined, options);
    assert.equal(response.status, 401);
    assert.deepEqual(response.body, { error: 'unauthorized' });
    assert.equal(response.headers.get('www-authenticate'), 'Bearer');
  }
  const unauthorizedPut = await vault.request('PUT', '/v1/vault', 'not json', { authorized: false });
  assert.equal(unauthorizedPut.status, 401);
  const initial = await vault.request('GET');
  assert.equal(initial.status, 200);
  assert.deepEqual(initial.body, { revision: 0, envelope: null });
  assert.equal(initial.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await readdir(vault.dataDir), []);
});

test('concurrent CAS permits exactly one writer and leaves a complete winning snapshot', async (t) => {
  const vault = await fixture(t);
  const candidates = Array.from({ length: 8 }, (_, i) => envelopeFor(vault.vaultId, String(i)).envelope);
  const responses = await Promise.all(candidates.map((envelope) =>
    vault.request('PUT', '/v1/vault', { expectedRevision: 0, envelope })));
  assert.equal(responses.filter((response) => response.status === 200).length, 1);
  assert.equal(responses.filter((response) => response.status === 409).length, 7);
  responses.filter((response) => response.status === 409).forEach((response) =>
    assert.deepEqual(response.body, { error: 'revision_conflict' }));
  const winnerIndex = responses.findIndex((response) => response.status === 200);
  assert.deepEqual(responses[winnerIndex].body, { revision: 1 });
  const state = await vault.request('GET');
  assert.deepEqual(state.body, { revision: 1, envelope: candidates[winnerIndex] });
  assert.deepEqual(await readdir(vault.dataDir), ['vault-state.json']);
  const diskState = JSON.parse(await readFile(path.join(vault.dataDir, 'vault-state.json'), 'utf8'));
  assert.deepEqual(diskState, state.body);
});

test('restart preserves revision and ciphertext, removes incomplete temps, and never stores test secrets', async (t) => {
  const vault = await fixture(t);
  const { envelope, keyB64 } = envelopeFor(vault.vaultId);
  assert.equal((await vault.request('PUT', '/v1/vault', { expectedRevision: 0, envelope })).status, 200);
  const second = envelopeFor(vault.vaultId, 'second').envelope;
  assert.deepEqual((await vault.request('PUT', '/v1/vault', { expectedRevision: 1, envelope: second })).body,
    { revision: 2 });
  await close(vault.server);
  await writeFile(path.join(vault.dataDir, `.vault-state-${randomUUID()}.tmp`), '{incomplete');
  await vault.restart();
  assert.deepEqual((await vault.request('GET')).body, { revision: 2, envelope: second });
  assert.deepEqual(await readdir(vault.dataDir), ['vault-state.json']);
  const disk = await readFile(path.join(vault.dataDir, 'vault-state.json'), 'utf8');
  for (const secret of [MOCK_PASSWORD, vault.token, vault.tokenHash, keyB64]) assert.ok(!disk.includes(secret));
  assert.ok(!disk.includes(envelope.data), 'replaced ciphertext is not retained as history');
});

test('invalid envelope shapes, nonce/base64, vault ID, and revision never mutate state', async (t) => {
  const vault = await fixture(t);
  const good = envelopeFor(vault.vaultId).envelope;
  const badEnvelopes = [
    null,
    [],
    { ...good, v: 2 },
    { ...good, alg: 'AES' },
    { ...good, vaultId: randomUUID() },
    { ...good, nonce: randomBytes(11).toString('base64') },
    { ...good, nonce: randomBytes(13).toString('base64') },
    { ...good, nonce: '________________' },
    { ...good, data: Buffer.alloc(15).toString('base64') },
    { ...good, data: 'AAAAAAAAAAAAAAAAAAAAAB==' }, // non-canonical unused padding bits
    { ...good, data: 'this is plaintext!' },
    { ...good, password: MOCK_PASSWORD },
    { ...good, nonce: 123 },
    { ...good, data: '' },
  ];
  for (const envelope of badEnvelopes) {
    const response = await vault.request('PUT', '/v1/vault', { expectedRevision: 0, envelope });
    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: 'invalid_envelope' });
  }
  for (const body of [null, [], {}, { expectedRevision: 0 },
    { expectedRevision: -1, envelope: good }, { expectedRevision: 0.5, envelope: good },
    { expectedRevision: Number.MAX_SAFE_INTEGER, envelope: good },
    { expectedRevision: '0', envelope: good }, { expectedRevision: 0, envelope: good, password: MOCK_PASSWORD }]) {
    assert.equal((await vault.request('PUT', '/v1/vault', body)).status, 400);
  }
  assert.equal((await vault.request('PUT', '/v1/vault', '{broken json')).status, 400);
  assert.equal((await vault.request('PUT', '/v1/vault', '{}', { contentType: 'text/plain' })).status, 415);
  assert.deepEqual((await vault.request('GET')).body, { revision: 0, envelope: null });
  assert.deepEqual(await readdir(vault.dataDir), []);
});

test('ciphertext and both declared and streamed request body limits are enforced', async (t) => {
  const vault = await fixture(t);
  const good = envelopeFor(vault.vaultId).envelope;
  const oversizedCiphertext = { ...good, data: Buffer.alloc(MAX_CIPHERTEXT_BYTES + 1).toString('base64') };
  const ciphertextResponse = await vault.request('PUT', '/v1/vault',
    { expectedRevision: 0, envelope: oversizedCiphertext });
  assert.equal(ciphertextResponse.status, 400);
  assert.deepEqual(ciphertextResponse.body, { error: 'invalid_envelope' });
  const headers = { Authorization: `Bearer ${vault.token}`, 'Content-Type': 'application/json' };
  const declared = await rawRequest(vault.endpoint,
    { ...headers, 'Content-Length': String(MAX_REQUEST_BYTES + 1) });
  assert.equal(declared.status, 413);
  const streamed = await rawRequest(vault.endpoint, { ...headers, 'Transfer-Encoding': 'chunked' },
    Buffer.alloc(MAX_REQUEST_BYTES + 1, 0x20));
  assert.equal(streamed.status, 413);
  assert.deepEqual((await vault.request('GET')).body, { revision: 0, envelope: null });
});

test('only the documented exact routes and methods are available', async (t) => {
  const vault = await fixture(t);
  for (const route of ['/v1/vault/', '/v1/vault?x=1', '/health?x=1', '/server.mjs', '/']) {
    assert.equal((await vault.request('GET', route)).status, 404);
  }
  const invalidMethod = await vault.request('POST', '/v1/vault');
  assert.equal(invalidMethod.status, 405);
  assert.equal(invalidMethod.headers.get('allow'), 'GET, PUT');
  const healthMethod = await vault.request('POST', '/health');
  assert.equal(healthMethod.status, 405);
  assert.equal(healthMethod.headers.get('allow'), 'GET');
});

test('corrupt or cross-vault persistent data fails startup without clearing it', async (t) => {
  const vault = await fixture(t);
  await close(vault.server);
  const statePath = path.join(vault.dataDir, 'vault-state.json');
  const malformed = '{interrupted-write';
  await writeFile(statePath, malformed);
  assert.throws(() => createVaultServer(vault), /Invalid persisted vault state/);
  assert.equal(await readFile(statePath, 'utf8'), malformed);
  const otherVault = JSON.stringify({ revision: 1, envelope: envelopeFor(randomUUID()).envelope });
  await writeFile(statePath, otherVault);
  assert.throws(() => createVaultServer(vault), /Invalid persisted vault state/);
  assert.equal(await readFile(statePath, 'utf8'), otherVault);
});

test('configuration never accepts an absent hash, raw token, or invalid vault ID', () => {
  const base = { dataDir: os.tmpdir(), vaultId: randomUUID(), tokenHash: 'a'.repeat(64) };
  for (const tokenHash of [undefined, '', 'mock-raw-token', 'g'.repeat(64)]) {
    assert.throws(() => createVaultServer({ ...base, tokenHash }), /VAULT_TOKEN_HASH/);
  }
  for (const vaultId of ['', '../vault', 'vault with spaces', 'a'.repeat(129)]) {
    assert.throws(() => createVaultServer({ ...base, vaultId }), /VAULT_ID/);
  }
});

test('a storage outage does not advance revision and a later retry can still commit', async (t) => {
  const vault = await fixture(t);
  const first = envelopeFor(vault.vaultId, 'first').envelope;
  const second = envelopeFor(vault.vaultId, 'second').envelope;
  assert.equal((await vault.request('PUT', '/v1/vault', { expectedRevision: 0, envelope: first })).status, 200);
  const directory = await realpath(vault.dataDir);
  const movedDirectory = `${directory}-temporarily-unavailable`;
  assert.equal(path.dirname(directory), path.dirname(movedDirectory));
  assert.ok(path.basename(movedDirectory).startsWith('private-vault-server-test-'));
  await rename(directory, movedDirectory);
  try {
    const failure = await vault.request('PUT', '/v1/vault', { expectedRevision: 1, envelope: second });
    assert.equal(failure.status, 500);
    assert.deepEqual(failure.body, { error: 'storage_error' });
    assert.deepEqual((await vault.request('GET')).body, { revision: 1, envelope: first });
    assert.deepEqual(JSON.parse(await readFile(path.join(movedDirectory, 'vault-state.json'), 'utf8')),
      { revision: 1, envelope: first });
  } finally {
    await rename(movedDirectory, directory);
  }
  assert.deepEqual((await vault.request('PUT', '/v1/vault', { expectedRevision: 1, envelope: second })).body,
    { revision: 2 });
});

test('duplicate Authorization headers are rejected even when one token is correct', async (t) => {
  const vault = await fixture(t);
  const result = await rawRequest(vault.endpoint, {
    Authorization: [`Bearer ${vault.token}`, 'Bearer wrong-token'],
    'Content-Type': 'application/json',
  }, Buffer.from('{}'));
  assert.equal(result.status, 401);
  assert.deepEqual(result.body, { error: 'unauthorized' });
});
