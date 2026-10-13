import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import '../forms.js';
const code = readFileSync(new URL('../content.js', import.meta.url), 'utf8');
function input(attrs, value) {
  return { attrs, value, type: attrs.type || 'text', getAttribute(name) { return this.attrs[name] || null; }, getClientRects() { return [{}]; } };
}
function fixture(fields) {
  const sent = [], listeners = new Map();
  const scope = { querySelectorAll(selector) { return selector === 'input' ? fields : []; } };
  const document = { ...scope, addEventListener(name, listener) { listeners.set(name, listener); } };
  const self = {};
  const context = { document, location: new URL('https://login.example.com/'), window: { top: self, self },
    PrivateVaultForms: globalThis.PrivateVaultForms, crypto: globalThis.crypto, TextEncoder, Uint8Array, Date,
    setTimeout, clearTimeout, chrome: { runtime: { async sendMessage(message) { sent.push(message); return { ok: true }; } } } };
  vm.runInNewContext(code, context);
  const submit = trusted => listeners.get('submit')({ target: { form: scope }, isTrusted: trusted });
  return { submit, sent, scope, context, listeners };
}
async function completed() { await new Promise(resolve => setTimeout(resolve, 20)); }

test('content ignores synthetic page-created submits', async () => {
  const f = fixture([input({ autocomplete: 'username' }, 'me'), input({ type: 'password' }, 'secret')]);
  f.submit(false); await completed(); assert.equal(f.sent.length, 0);
});
test('trusted submission only stages a candidate and preserves value if SPA clears fields', async () => {
  const password = input({ type: 'password' }, 'secret');
  const f = fixture([input({ autocomplete: 'username' }, 'me'), password]);
  f.submit(true); password.value = ''; await completed();
  assert.ok(f.sent.some(message => message.type === 'remember-username'));
  const stage = f.sent.find(message => message.type === 'stage');
  assert.deepEqual(JSON.parse(JSON.stringify(stage.candidate)), { username: 'me', password: 'secret', kind: 'login' });
  assert.ok(f.sent.every(message => ['remember-username', 'stage'].includes(message.type)));
});
test('click and submit duplicates are coalesced without retaining plaintext fingerprints', async () => {
  const f = fixture([input({ autocomplete: 'username' }, 'me'), input({ type: 'password' }, 'secret')]);
  f.submit(true); f.submit(true); f.submit(true); await completed();
  assert.equal(f.sent.filter(message => message.type === 'stage').length, 1);
  assert.ok(code.includes("crypto.subtle.digest('SHA-256'"));
});
test('identifier-only step remembers username and never invents a password', async () => {
  const f = fixture([input({ type: 'email', name: 'identifierId' }, 'me@example.com')]);
  f.submit(true); await completed();
  assert.deepEqual(JSON.parse(JSON.stringify(f.sent)), [{ type: 'remember-username', username: 'me@example.com' }]);
});
test('content script is installed only once in each document', () => {
  const f = fixture([]); let additions = 0;
  f.context.document.addEventListener = () => additions++;
  vm.runInNewContext(code, f.context); assert.equal(additions, 0);
});
