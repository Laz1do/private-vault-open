const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { once } = require('node:events');
const { createHost, validateLocal, validateConfig } = require('../host.cjs');

// Deliberately public fixtures; no real installation key or clipboard is used.
const KEY = Buffer.alloc(32).toString('base64');
const VAULT_ID = 'host-test-vault';
const TOKEN = 'public_test_only_token_123456789';
const core = import('../../core/vault.js');
const clone = value => structuredClone(value);
const config = (endpoint = null) => ({ vaultId: VAULT_ID, keyB64: KEY, token: TOKEN, endpoint });
const formatOnlyLocal = () => ({ deviceId: 'test_device', envelope: {
  v: 1, vaultId: VAULT_ID, alg: 'A256GCM', nonce: Buffer.alloc(12).toString('base64'), data: Buffer.alloc(16).toString('base64'),
} });
async function encryptedLocal(password = 'host-test-secret') {
  const { createVault, writeRecord, encryptVault } = await core;
  const vault = writeRecord(createVault(VAULT_ID), null, {
    title: 'Host test', username: 'test', password, url: 'https://example.com', notes: '',
  }, 'test_device');
  return { deviceId: 'test_device', envelope: await encryptVault(vault, KEY) };
}
async function fixture(t, endpoint = null) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'private-vault-host-test-'));
  const clipboardCalls = [], externalCalls = [];
  const host = createHost({ config: config(endpoint), dataDir,
    clipboard: { writeText: value => clipboardCalls.push(value) },
    shell: { openExternal: async value => externalCalls.push(value) },
  });
  t.after(async () => {
    const target = path.resolve(dataDir), prefix = path.resolve(os.tmpdir()) + path.sep + 'private-vault-host-test-';
    if (!target.startsWith(prefix)) throw new Error('Refusing to delete outside the test temporary directory');
    await fs.rm(target, { recursive: true, force: true });
  });
  return { host, dataDir, dataFile: path.join(dataDir, 'vault.json'), clipboardCalls, externalCalls };
}
async function localServer(t, handler) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}`;
}

test('configuration requires canonical 256-bit keys and a safe fixed endpoint', () => {
  assert.equal(validateConfig(config()).endpoint, null);
  assert.equal(validateConfig(config('https://vault.example.com/')).endpoint, 'https://vault.example.com');
  assert.equal(validateConfig(config('http://127.0.0.1:9876')).endpoint, 'http://127.0.0.1:9876');
  assert.equal(validateConfig(config('http://[::1]:9876')).endpoint, 'http://[::1]:9876');
  for (const invalid of [
    { ...config(), vaultId: 123 }, { ...config(), vaultId: '__proto__' },
    { ...config(), keyB64: KEY + '\n' }, { ...config(), keyB64: KEY.slice(0, -1) },
    { ...config(), keyB64: KEY.slice(0, -2) + 'B=' }, { ...config(), keyB64: Buffer.alloc(31).toString('base64') },
    { ...config(), token: 12345678901234567890n }, { ...config(), token: 'short' },
    { ...config(), endpoint: undefined }, { ...config(), endpoint: 123 }, { ...config(), extra: 'unexpected' },
  ]) assert.throws(() => validateConfig(invalid));
  for (const endpoint of ['http://vault.example.com', 'ftp://vault.example.com', 'https://user:pass@vault.example.com',
    'https://vault.example.com/path', 'https://vault.example.com?token=x', 'https://vault.example.com#fragment', 'not-a-url'])
    assert.throws(() => validateConfig(config(endpoint)));
});

test('local validation rejects loose IDs, extra fields and noncanonical encrypted formats', () => {
  assert.doesNotThrow(() => validateLocal(formatOnlyLocal(), VAULT_ID));
  const changes = [
    value => { value.deviceId = 123; }, value => { delete value.deviceId; },
    value => { value.deviceId = '__proto__'; }, value => { value.password = 'plaintext'; },
    value => { value.envelope.vaultId = 123; }, value => { delete value.envelope.vaultId; },
    value => { value.envelope.vaultId = 'other-vault'; }, value => { value.envelope.key = KEY; },
    value => { value.envelope.v = '1'; }, value => { value.envelope.alg = 'AES'; },
    value => { value.envelope.nonce += '\n'; }, value => { value.envelope.nonce = Buffer.alloc(11).toString('base64'); },
    value => { value.envelope.data = 'AAAAAAAAAAAAAAAAAAAAAB=='; },
    value => { value.envelope.data = Buffer.alloc(15).toString('base64'); },
    value => { value.envelope.data += ' '; }, value => { value.envelope.data = []; },
  ];
  for (const change of changes) { const value = formatOnlyLocal(); change(value); assert.throws(() => validateLocal(value, VAULT_ID)); }
  assert.throws(() => validateLocal([], VAULT_ID));
  assert.throws(() => validateLocal(null, VAULT_ID));
});

test('ciphertext length permits 4 MiB and rejects one byte beyond the synchronization budget', () => {
  const value = formatOnlyLocal();
  value.envelope.data = Buffer.alloc(4 * 1024 * 1024).toString('base64');
  assert.doesNotThrow(() => validateLocal(value, VAULT_ID));
  value.envelope.data = Buffer.alloc(4 * 1024 * 1024 + 1).toString('base64');
  assert.throws(() => validateLocal(value, VAULT_ID));
});

test('atomic storage persists ciphertext, survives reopen, and serializes competing writes', async t => {
  const { host, dataDir, dataFile } = await fixture(t), { decryptVault, listRecords } = await core;
  assert.equal(await host.readLocal(), null);
  const first = await encryptedLocal('first-host-secret'), second = await encryptedLocal('second-host-secret');
  await Promise.all([host.writeLocal(first), host.writeLocal(second)]);
  assert.deepEqual(await host.readLocal(), second);
  const raw = await fs.readFile(dataFile, 'utf8');
  assert.ok(!raw.includes('first-host-secret')); assert.ok(!raw.includes('second-host-secret'));
  assert.deepEqual(await fs.readdir(dataDir), ['vault.json']);
  const reopened = createHost({ config: config(), dataDir, clipboard: {}, shell: {} });
  const read = await reopened.readLocal();
  assert.equal(listRecords(await decryptVault(read.envelope, KEY, VAULT_ID))[0].entry.password, 'second-host-secret');
  await assert.rejects(host.writeLocal({ ...second, password: 'accidental plaintext' }));
  assert.equal(await fs.readFile(dataFile, 'utf8'), raw);
});

test('malformed or wrong-vault files are preserved and prevent subsequent overwrite', async t => {
  for (const contents of ['{malformed-json', JSON.stringify({ ...formatOnlyLocal(), envelope: {
    ...formatOnlyLocal().envelope, vaultId: 'other-vault',
  } })]) {
    const { host, dataFile } = await fixture(t);
    await fs.writeFile(dataFile, contents, 'utf8');
    await assert.rejects(host.readLocal(), /防覆盖/);
    await assert.rejects(host.writeLocal(await encryptedLocal()), /停止写入/);
    assert.equal(await fs.readFile(dataFile, 'utf8'), contents);
  }
});

test('a wrong-vault write is refused before replacing a healthy local file', async t => {
  const { host, dataFile } = await fixture(t), value = await encryptedLocal();
  await host.writeLocal(value); const original = await fs.readFile(dataFile, 'utf8');
  const wrong = clone(value); wrong.envelope.vaultId = 'other-vault';
  await assert.rejects(host.writeLocal(wrong));
  assert.equal(await fs.readFile(dataFile, 'utf8'), original);
});

test('the configured endpoint and key cannot be changed through a caller-owned object', async t => {
  const { dataDir } = await fixture(t), input = config('https://vault.example.com');
  const host = createHost({ config: input, dataDir, clipboard: {}, shell: {} });
  input.endpoint = 'http://attacker.example'; input.keyB64 = 'bad';
  const exposed = await host.getConfig();
  assert.equal(exposed.endpoint, 'https://vault.example.com'); assert.equal(exposed.keyB64, KEY);
  exposed.token = 'changed'; assert.equal((await host.getConfig()).token, TOKEN);
});

test('only the intended CAS route is allowed and Bearer credentials are supplied by Host', async t => {
  const requests = [];
  const endpoint = await localServer(t, async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    requests.push({ method: request.method, path: request.url, authorization: request.headers.authorization,
      body: Buffer.concat(chunks).toString('utf8') });
    response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify({ revision: 1, envelope: null }));
  });
  const { host } = await fixture(t, endpoint);
  assert.equal((await host.request('GET', '/v1/vault')).status, 200);
  const value = await encryptedLocal('never-network-plaintext');
  await host.request('PUT', '/v1/vault', { expectedRevision: 0, envelope: value.envelope });
  assert.deepEqual(requests.map(r => [r.method, r.path, r.authorization]), [
    ['GET', '/v1/vault', `Bearer ${TOKEN}`], ['PUT', '/v1/vault', `Bearer ${TOKEN}`],
  ]);
  assert.equal(requests[0].body, ''); assert.ok(!requests[1].body.includes('never-network-plaintext'));
  for (const [method, route, body] of [
    ['POST', '/v1/vault'], ['GET', '/health'], ['GET', 'https://attacker.example/v1/vault'],
    ['GET', '/v1/vault?leak=1'], ['GET', '/v1/vault', {}],
    ['PUT', '/v1/vault', { expectedRevision: -1, envelope: value.envelope }],
    ['PUT', '/v1/vault', { expectedRevision: 0, envelope: value.envelope, keyB64: KEY }],
    ['PUT', '/v1/vault', { expectedRevision: 0, envelope: { ...value.envelope, vaultId: 'other-vault' } }],
  ]) await assert.rejects(host.request(method, route, body));
  assert.equal(requests.length, 2);
});

test('redirects are refused and cannot send credentials to a second endpoint', async t => {
  let destinationRequests = 0;
  const destination = await localServer(t, (request, response) => { destinationRequests++; response.end('{}'); });
  const endpoint = await localServer(t, (request, response) => { response.writeHead(307, { Location: `${destination}/stolen` }); response.end(); });
  const { host } = await fixture(t, endpoint);
  await assert.rejects(host.request('GET', '/v1/vault'));
  assert.equal(destinationRequests, 0);
});

test('response limits are enforced for both declared and chunked sizes, and bad JSON is refused', async t => {
  for (const kind of ['declared', 'chunked', 'bad-json']) {
    const endpoint = await localServer(t, (request, response) => {
      if (kind === 'declared') { response.writeHead(200, { 'Content-Length': 8 * 1024 * 1024 + 1 }); response.write(' '); }
      else if (kind === 'chunked') { response.writeHead(200); response.end(Buffer.alloc(8 * 1024 * 1024 + 1, 32)); }
      else response.end('not-json');
    });
    const { host } = await fixture(t, endpoint);
    await assert.rejects(host.request('GET', '/v1/vault'), kind === 'bad-json' ? /无效内容/ : /响应过大/);
  }
});

test('clipboard and external links use safe limits without touching native system services', async t => {
  const { host, clipboardCalls, externalCalls } = await fixture(t);
  await host.copyText('mock-password'); await host.copyText('');
  for (const text of [null, 123, {}, 'x'.repeat(20001)]) await assert.rejects(host.copyText(text));
  assert.deepEqual(clipboardCalls, ['mock-password', '']);
  await host.openExternal('https://example.com/login'); await host.openExternal('http://example.com');
  for (const url of [null, 123, '', 'not-a-url', 'file:///C:/private.txt', 'javascript:alert(1)',
    'data:text/html,test', 'https://user:password@example.com', `https://example.com/${'x'.repeat(2048)}`])
    await assert.rejects(host.openExternal(url));
  assert.deepEqual(externalCalls, ['https://example.com/login', 'http://example.com/']);
});

test('a missing cloud endpoint fails sync requests while local storage remains available', async t => {
  const { host } = await fixture(t);
  await assert.rejects(host.request('GET', '/v1/vault'), /未配置/);
  const local = await encryptedLocal(); await host.writeLocal(local);
  assert.deepEqual(await host.readLocal(), local);
});
