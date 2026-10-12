import http from 'node:http';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, statSync, unlinkSync } from 'node:fs';
import { open, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024;
export const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const STATE_FILE = 'vault-state.json';
const TEMP_FILE_PATTERN = /^\.vault-state-[0-9a-f-]{36}\.tmp$/;
const MAX_BASE64_LENGTH = 4 * Math.ceil(MAX_CIPHERTEXT_BYTES / 3);

class RequestError extends Error {
  constructor(status, code, close = false) {
    super(code);
    this.status = status;
    this.code = code;
    this.close = close;
  }
}

function exactObject(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && fields.every((field) => Object.hasOwn(value, field));
}

function canonicalBase64(value, minBytes, maxBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0
      || value.length > 4 * Math.ceil(maxBytes / 3)
      || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length >= minBytes && bytes.length <= maxBytes
    && bytes.toString('base64') === value;
}

function validEnvelope(envelope, vaultId) {
  return exactObject(envelope, ['v', 'vaultId', 'alg', 'nonce', 'data'])
    && envelope.v === 1 && envelope.vaultId === vaultId && envelope.alg === 'A256GCM'
    && canonicalBase64(envelope.nonce, 12, 12)
    && typeof envelope.data === 'string' && envelope.data.length <= MAX_BASE64_LENGTH
    && canonicalBase64(envelope.data, 16, MAX_CIPHERTEXT_BYTES);
}

function validRevision(revision) {
  return Number.isSafeInteger(revision) && revision >= 0;
}

function readSnapshot(dataDir, vaultId) {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  // A crashed atomic replacement may leave an incomplete temporary file.
  // The committed file is the only source of truth; do not promote a temp file.
  for (const file of readdirSync(dataDir)) {
    if (TEMP_FILE_PATTERN.test(file)) unlinkSync(path.join(dataDir, file));
  }
  const statePath = path.join(dataDir, STATE_FILE);
  let raw;
  try {
    const info = statSync(statePath);
    if (!info.isFile() || info.size > MAX_REQUEST_BYTES) throw new Error('Invalid persisted vault state');
    raw = readFileSync(statePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return { revision: 0, envelope: null };
    throw error;
  }
  let state;
  try { state = JSON.parse(raw); } catch { throw new Error('Invalid persisted vault state'); }
  if (!exactObject(state, ['revision', 'envelope']) || !validRevision(state.revision)
      || (state.revision === 0 ? state.envelope !== null : !validEnvelope(state.envelope, vaultId))) {
    throw new Error('Invalid persisted vault state');
  }
  return state;
}

async function persistSnapshot(dataDir, nextState, committed) {
  const tempPath = path.join(dataDir, `.vault-state-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(tempPath, 'wx', 0o600);
    await handle.writeFile(JSON.stringify(nextState), 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(tempPath, path.join(dataDir, STATE_FILE));
    committed();
    // Unix needs a directory fsync to persist the rename across power loss.
    // Node cannot open a directory this way on Windows; rename is still atomic.
    if (process.platform !== 'win32') {
      const directory = await open(dataDir, 'r');
      try { await directory.sync(); } finally { await directory.close(); }
    }
  } finally {
    if (handle) await handle.close().catch(() => {});
    await unlink(tempPath).catch((error) => {
      if (error.code !== 'ENOENT') throw error;
    });
  }
}

function sendJson(response, status, body, close = false) {
  if (response.destroyed || response.writableEnded) return;
  const bytes = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': bytes.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...(status === 401 ? { 'WWW-Authenticate': 'Bearer' } : {}),
    ...(status === 405 && !response.hasHeader('Allow') ? { Allow: 'GET, PUT' } : {}),
    ...(close ? { Connection: 'close' } : {}),
  });
  response.end(bytes);
}

function authenticated(request, expectedHash) {
  const authorization = request.headers.authorization;
  if (request.headersDistinct.authorization?.length !== 1 || typeof authorization !== 'string') return false;
  const match = /^Bearer ([\x21-\x7e]{1,512})$/.exec(authorization);
  if (!match) return false;
  const actualHash = createHash('sha256').update(match[1], 'utf8').digest();
  return timingSafeEqual(actualHash, expectedHash);
}

function readJsonBody(request) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '')
      || (request.headers['content-encoding'] && request.headers['content-encoding'] !== 'identity')) {
    request.resume();
    throw new RequestError(415, 'unsupported_media_type', true);
  }
  if (Number(request.headers['content-length']) > MAX_REQUEST_BYTES) {
    request.resume();
    throw new RequestError(413, 'body_too_large', true);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const cleanup = () => {
      request.off('data', onData);
      request.off('end', onEnd);
      request.off('aborted', onAborted);
      request.off('error', onError);
    };
    const fail = (error) => {
      cleanup();
      request.once('error', () => {});
      request.resume();
      reject(error);
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) {
        fail(new RequestError(413, 'body_too_large', true));
      } else {
        chunks.push(chunk);
      }
    };
    const onEnd = () => {
      cleanup();
      try { resolve(JSON.parse(Buffer.concat(chunks, size).toString('utf8'))); }
      catch { reject(new RequestError(400, 'invalid_json')); }
    };
    const onAborted = () => fail(new RequestError(400, 'incomplete_body', true));
    const onError = () => fail(new RequestError(400, 'incomplete_body', true));
    request.on('data', onData);
    request.once('end', onEnd);
    request.once('aborted', onAborted);
    request.once('error', onError);
  });
}

/** Returns an unlistened http.Server. Only one process may use a dataDir. */
export function createVaultServer({ dataDir, tokenHash, vaultId, host = '127.0.0.1', port = 8787 }) {
  if (typeof dataDir !== 'string' || !dataDir.trim()) throw new Error('VAULT_DATA_DIR is required');
  if (typeof tokenHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(tokenHash)) {
    throw new Error('VAULT_TOKEN_HASH must be a SHA-256 hexadecimal digest');
  }
  if (typeof vaultId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(vaultId)) {
    throw new Error('VAULT_ID must be 1-128 letters, digits, dots, underscores, or hyphens');
  }
  if (typeof host !== 'string' || !host.trim() || !Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error('Invalid HOST or PORT');
  }
  const absoluteDataDir = path.resolve(dataDir);
  const expectedHash = Buffer.from(tokenHash, 'hex');
  let state = readSnapshot(absoluteDataDir, vaultId);
  let writes = Promise.resolve();

  const server = http.createServer({ maxHeaderSize: 8 * 1024 }, async (request, response) => {
    try {
      // Exact paths deliberately reject query strings, extra slashes, and other routes.
      if (request.url === '/health') {
        if (request.method !== 'GET') {
          response.setHeader('Allow', 'GET');
          sendJson(response, 405, { error: 'method_not_allowed' });
        } else {
          sendJson(response, 200, { ok: true });
        }
        request.resume();
        return;
      }
      if (request.url !== '/v1/vault') {
        sendJson(response, 404, { error: 'not_found' }, true);
        request.resume();
        return;
      }
      if (!authenticated(request, expectedHash)) {
        sendJson(response, 401, { error: 'unauthorized' }, true);
        request.resume();
        return;
      }
      if (!['GET', 'PUT'].includes(request.method)) {
        sendJson(response, 405, { error: 'method_not_allowed' }, true);
        request.resume();
        return;
      }
      if (request.method === 'GET') {
        if (request.headers['transfer-encoding'] || Number(request.headers['content-length'] ?? 0) !== 0) {
          throw new RequestError(400, 'unexpected_body', true);
        }
        sendJson(response, 200, state);
        return;
      }
      const body = await readJsonBody(request);
      if (!exactObject(body, ['expectedRevision', 'envelope'])
          || !validRevision(body.expectedRevision) || body.expectedRevision === Number.MAX_SAFE_INTEGER) {
        throw new RequestError(400, 'invalid_request');
      }
      if (!validEnvelope(body.envelope, vaultId)) throw new RequestError(400, 'invalid_envelope');

      // The comparison and durable replacement share one serialized critical section.
      // All concurrent callers using the same revision therefore cannot succeed.
      const write = writes.then(async () => {
        if (body.expectedRevision !== state.revision) throw new RequestError(409, 'revision_conflict');
        const nextState = { revision: state.revision + 1, envelope: body.envelope };
        await persistSnapshot(absoluteDataDir, nextState, () => { state = nextState; });
        return nextState.revision;
      });
      writes = write.catch(() => {});
      sendJson(response, 200, { revision: await write });
    } catch (error) {
      if (error instanceof RequestError) {
        sendJson(response, error.status, { error: error.code }, error.close);
      } else {
        // Filesystem failures never include request content, tokens, or paths in the response.
        sendJson(response, 500, { error: 'storage_error' });
      }
    }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.timeout = 20_000;
  server.maxRequestsPerSocket = 100;
  server.maxConnections = 32;
  return server;
}

function runCli() {
  const host = process.env.HOST ?? '127.0.0.1';
  const portValue = process.env.PORT ?? '8787';
  if (!/^\d{1,5}$/.test(portValue) || Number(portValue) < 1 || Number(portValue) > 65535) {
    throw new Error('PORT must be between 1 and 65535');
  }
  const port = Number(portValue);
  const server = createVaultServer({
    dataDir: process.env.VAULT_DATA_DIR,
    tokenHash: process.env.VAULT_TOKEN_HASH,
    vaultId: process.env.VAULT_ID,
    host,
    port,
  });
  server.on('error', () => {
    console.error('Vault server could not start or accept connections.');
    process.exitCode = 1;
  });
  server.listen(port, host, () => console.info(`Vault server listening on ${host}:${port}`));
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      server.close();
      const deadline = setTimeout(() => server.closeAllConnections(), 10_000);
      deadline.unref();
    });
  }
}

const mainPath = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href;
if (import.meta.url === mainPath) {
  try { runCli(); }
  catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
