import test from 'node:test';
import assert from 'node:assert/strict';

const id = 'dinagdpfpgbcfepiaabjccimnppakedl';
function event() { const listeners = []; return { addListener(fn) { listeners.push(fn); }, fire(...args) { for (const fn of listeners) fn(...args); }, listeners }; }
async function fixture() {
  const nativeCalls = [], scriptCalls = [], badgeCalls = [], popupCalls = [];
  let permitted = true, enabled = true, vaultId = 'vault-a', currentUrl = 'https://login.example.com/login', registration = [], needsImport = false, changingVault = false;
  const port = { onMessage: event(), onDisconnect: event(), postMessage(message) {
    nativeCalls.push(message);
    let result;
    switch (message.command) {
      case 'status': result = { enabled, browserEnabled: enabled, vaultId, needsImport, changingVault }; break;
      case 'matches': result = { enabled, vaultId, records: [{ id: 'record-a', title: 'Example', username: 'me', stamp: 'version-a' }] }; break;
      case 'fill': result = { username: 'me', password: 'native-password' }; break;
      case 'stage': result = enabled ? { draftId: 'draft-a', vaultId, kind: 'new' } : { disabled: true }; break;
      case 'draft': result = { draftId: 'draft-a', vaultId, password: 'draft-password', username: 'me', host: 'login.example.com', kind: 'new', records: [] }; break;
      case 'confirm': result = { saved: true, recordId: 'new-record' }; break;
      case 'dismiss': result = { dismissed: true }; break;
    }
    queueMicrotask(() => port.onMessage.fire({ requestId: message.requestId, ok: true, result }));
  } };
  const chrome = {
    runtime: { id, onMessage: event(), onInstalled: event(), onStartup: event(), connectNative(name) { assert.equal(name, 'com.local.privatevault'); return port; } },
    permissions: { async contains() { return permitted; }, onAdded: event(), onRemoved: event() },
    scripting: { async getRegisteredContentScripts() { return registration; }, async registerContentScripts(value) { registration = value; }, async unregisterContentScripts() { registration = []; },
      async executeScript(value) {
        scriptCalls.push(value);
        if (value.files) return [];
        if (!value.args) return [{ documentId: 'document-a', result: { url: currentUrl, top: true } }];
        return [{ documentId: 'document-a', result: { filled: true, fields: 2 } }];
      } },
    tabs: { async query() { return [{ id: 4, url: currentUrl }]; }, async get() { return { id: 4, url: currentUrl, active: true, windowId: 2 }; }, onRemoved: event(), onUpdated: event() },
    action: { async setBadgeText(value) { badgeCalls.push(value); }, async setBadgeBackgroundColor() {}, async openPopup(value) { popupCalls.push(value); } }
  };
  globalThis.chrome = chrome;
  await import(`../worker.js?fixture=${crypto.randomUUID()}`);
  const popup = { id, url: `chrome-extension://${id}/popup.html` };
  const content = { id, frameId: 0, documentId: 'document-a', url: currentUrl, tab: { id: 4, url: currentUrl } };
  const send = (message, sender = popup) => new Promise(resolve => {
    assert.equal(chrome.runtime.onMessage.listeners[0](message, sender, resolve), true);
  });
  return { send, popup, content, nativeCalls, scriptCalls, badgeCalls, popupCalls, chrome,
    setPermission(value) { permitted = value; }, setEnabled(value) { enabled = value; }, setVault(value) { vaultId = value; },
    setNeedsImport(value) { needsImport = value; }, setChangingVault(value) { changingVault = value; },
    setUrl(value) { currentUrl = value; } };
}

test('website scripts cannot query credentials or confirm a save', async () => {
  const f = await fixture();
  for (const type of ['state', 'fill', 'confirm', 'dismiss', 'refresh-detection']) {
    assert.equal((await f.send({ type, recordId: 'record-a' }, f.content)).ok, false);
  }
  assert.equal(f.nativeCalls.length, 0);
});
test('staging uses trusted top-tab URL and returns no credential metadata', async () => {
  const f = await fixture();
  const response = await f.send({ type: 'stage', url: 'https://attacker.example', candidate: { username: 'me', password: 'page-password', kind: 'login' } }, f.content);
  assert.deepEqual(response, { ok: true, result: { staged: true, unchanged: false, disabled: false } });
  const stage = f.nativeCalls.find(item => item.command === 'stage');
  assert.equal(stage.params.url, f.content.url); assert.equal(stage.params.password, 'page-password');
  assert.deepEqual(f.badgeCalls.at(-1), { tabId: 4, text: '1' });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.popupCalls, [{ windowId: 2 }]);
});
test('unsupported automatic popup keeps the visible badge and staged draft', async () => {
  const f = await fixture();
  f.chrome.action.openPopup = async () => { throw new Error('popup blocked'); };
  const response = await f.send({ type: 'stage', candidate: { username: 'me', password: 'page-password', kind: 'login' } }, f.content);
  assert.equal(response.result.staged, true);
  assert.deepEqual(f.badgeCalls.at(-1), { tabId: 4, text: '1' });
  await new Promise(resolve => setImmediate(resolve));
});
test('unsafe frames and revoked detection permission cannot stage', async () => {
  const f = await fixture(); const message = { type: 'stage', candidate: { username: 'me', password: 'page-password', kind: 'login' } };
  assert.equal((await f.send(message, { ...f.content, frameId: 2 })).ok, false);
  f.setPermission(false); assert.deepEqual((await f.send(message, f.content)).result, { disabled: true });
  assert.equal(f.nativeCalls.length, 0);
});
test('popup fill pins credentials to the checked document and authoritative stamp', async () => {
  const f = await fixture();
  const response = await f.send({ type: 'fill', tabId: 4, recordId: 'record-a', stamp: 'version-a', vaultId: 'vault-a' });
  assert.equal(response.ok, true);
  assert.deepEqual(f.nativeCalls.find(item => item.command === 'fill').params, { url: f.content.url, recordId: 'record-a', stamp: 'version-a', vaultId: 'vault-a' });
  const injection = f.scriptCalls.at(-1);
  assert.deepEqual(injection.target, { tabId: 4, documentIds: ['document-a'] });
  assert.deepEqual(injection.args, [{ username: 'me', password: 'native-password' }, 'https://login.example.com']);
});
test('popup cannot confirm arbitrary draft or an inactive tab', async () => {
  const f = await fixture();
  assert.equal((await f.send({ type: 'confirm', tabId: 4, draftId: 'unknown' })).ok, false);
  assert.equal((await f.send({ type: 'fill', tabId: 9, recordId: 'record-a' })).ok, false);
  assert.equal(f.nativeCalls.length, 0);
});
test('same-host username step is carried forward but invalidated by vault switch', async () => {
  const f = await fixture();
  await f.send({ type: 'remember-username', username: 'prior-user' }, f.content);
  await f.send({ type: 'stage', candidate: { username: '', password: 'first', kind: 'login' } }, f.content);
  assert.equal(f.nativeCalls.filter(item => item.command === 'stage').at(-1).params.username, 'prior-user');
  f.setVault('vault-b');
  await f.send({ type: 'stage', candidate: { username: '', password: 'second', kind: 'login' } }, f.content);
  assert.equal(f.nativeCalls.filter(item => item.command === 'stage').at(-1).params.username, '');
});
test('native assistant gate stops page staging and popup shows disabled status', async () => {
  const f = await fixture(); f.setEnabled(false);
  assert.deepEqual((await f.send({ type: 'stage', candidate: { username: '', password: 'first', kind: 'login' } }, f.content)).result, { disabled: true });
  assert.ok(!f.nativeCalls.some(item => item.command === 'stage'));
  const response = await f.send({ type: 'state' });
  assert.equal(response.result.status.enabled, false); assert.equal(response.result.draft, null);
});
test('recovery or changing-library popup state remains renderable without sensitive queries', async () => {
  for (const kind of ['import', 'change']) {
    const f = await fixture();
    if (kind === 'import') f.setNeedsImport(true); else f.setChangingVault(true);
    const response = await f.send({ type: 'state' });
    assert.equal(response.ok, true); assert.equal(response.result.connected, true);
    assert.equal(response.result.draft, null); assert.deepEqual(response.result.matches.records, []);
    assert.ok(!f.nativeCalls.some(item => item.command === 'matches' || item.command === 'draft'));
  }
});
test('detector registration uses HTTPS main frames and is removed when optional permission is revoked', async () => {
  const f = await fixture();
  await f.send({ type: 'state' });
  const [registered] = await f.chrome.scripting.getRegisteredContentScripts();
  assert.deepEqual(registered.matches, ['https://*/*']); assert.equal(registered.allFrames, false);
  f.setPermission(false); await f.send({ type: 'state' });
  assert.deepEqual(await f.chrome.scripting.getRegisteredContentScripts(), []);
});
test('confirm forwards edited draft only after explicit popup action then clears badge', async () => {
  const f = await fixture();
  await f.send({ type: 'stage', candidate: { username: 'me', password: 'first', kind: 'login' } }, f.content);
  assert.ok(!f.nativeCalls.some(item => item.command === 'confirm'));
  const response = await f.send({ type: 'confirm', tabId: 4, draftId: 'draft-a', vaultId: 'vault-a',
    title: 'My account', username: 'edited-me', password: 'edited-password', recordId: null });
  assert.equal(response.result.saved, true);
  assert.equal(f.nativeCalls.find(item => item.command === 'confirm').params.password, 'edited-password');
  assert.deepEqual(f.badgeCalls.at(-1), { tabId: 4, text: '' });
});
