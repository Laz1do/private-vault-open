import test from 'node:test';
import assert from 'node:assert/strict';
import { checkedHttpsUrl, isPopupSender, checkedContentSender, boundedCandidate } from '../policy.js';

const id = 'dinagdpfpgbcfepiaabjccimnppakedl';
test('Chrome URL policy accepts only credential-free HTTPS addresses', () => {
  assert.equal(checkedHttpsUrl('https://login.example.com/path#one'), 'https://login.example.com/path');
  assert.equal(checkedHttpsUrl('https://login.example.com:443/'), 'https://login.example.com/');
  for (const url of ['http://example.com', 'javascript:alert(1)', 'https://user:password@example.com', 'file:///foo', 'chrome://extensions', '', null])
    assert.throws(() => checkedHttpsUrl(url));
});
test('only the exact extension popup may issue credential and confirmation commands', () => {
  assert.equal(isPopupSender({ id, url: `chrome-extension://${id}/popup.html` }, id), true);
  for (const sender of [{ id: 'another', url: `chrome-extension://${id}/popup.html` },
    { id, url: `chrome-extension://${id}/popup.html?spoof` }, { id, url: `chrome-extension://${id}/popup.html`, tab: { id: 2 } },
    { id, url: 'https://example.com/popup.html' }, {}]) assert.equal(isPopupSender(sender, id), false);
});
test('website candidate provenance comes from Chrome top-document sender', () => {
  const sender = { id, frameId: 0, documentId: 'current-document', url: 'https://login.example.com/signin', tab: { id: 8, url: 'https://login.example.com/signin' } };
  assert.deepEqual(checkedContentSender(sender, id), { tabId: 8, documentId: 'current-document', url: sender.url, host: 'login.example.com' });
  for (const change of [{ frameId: 1 }, { id: 'other' }, { documentId: undefined },
    { url: 'https://other.example.com/' }, { tab: { id: 8, url: 'http://login.example.com' } }])
    assert.throws(() => checkedContentSender({ ...sender, ...change }, id));
  const portSender = { ...sender, url: 'https://login.example.com:8443/', tab: { id: 8, url: 'https://login.example.com:8443/' } };
  assert.equal(checkedContentSender(portSender, id).host, 'login.example.com:8443');
});
test('candidate input is bounded and excludes caller-supplied site or record metadata', () => {
  assert.deepEqual(boundedCandidate({ username: 'me', password: 'secret', kind: 'login', url: 'https://attacker.example', recordId: 'victim' }),
    { username: 'me', password: 'secret', kind: 'login' });
  for (const value of [{ username: 'me', password: '', kind: 'login' }, { username: 'x'.repeat(1001), password: 'x', kind: 'login' },
    { username: 'me', password: 'x'.repeat(4097), kind: 'login' }, { username: 'me', password: 'x', kind: 'auto-save' }, null])
    assert.throws(() => boundedCandidate(value));
});
