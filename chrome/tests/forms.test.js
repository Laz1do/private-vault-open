import test from 'node:test';
import assert from 'node:assert/strict';
import '../forms.js';
const forms = globalThis.PrivateVaultForms;

class Input {
  constructor(attrs = {}, value = '') { this.attrs = attrs; this.type = attrs.type || 'text'; this._value = value; this.events = []; this.disabled = false; this.readOnly = false; }
  get value() { return this._value; }
  set value(value) { this._value = value; }
  getAttribute(name) { return this.attrs[name] ?? null; }
  getClientRects() { return this.attrs.visible === false ? [] : [{}]; }
  dispatchEvent(event) { this.events.push(event.type); }
  focus() { this.focused = true; }
}
const input = (attrs, value) => new Input(attrs, value);
function scope(inputs) { return { querySelectorAll(selector) { return selector === 'input' ? inputs : []; } }; }
function doc(scopes, loose = []) { return { querySelectorAll(selector) { return selector === 'form' ? scopes : selector === 'input' ? loose : []; } }; }
function setLocation(url = 'https://github.com/login', top = true) {
  globalThis.location = new URL(url); const self = {}; globalThis.window = { self, top: top ? self : {} };
}

test('ordinary login extracts username and current password', () => {
  assert.deepEqual(forms.candidate(scope([input({ name: 'login', autocomplete: 'username' }, 'octocat'), input({ type: 'password', autocomplete: 'current-password' }, 'p@ss')])),
    { username: 'octocat', password: 'p@ss', kind: 'login' });
});
test('same-site split password step uses only supplied username fallback', () => {
  assert.deepEqual(forms.candidate(scope([input({ type: 'password', name: 'Passwd' }, 'secret')]), 'person@gmail.com'),
    { username: 'person@gmail.com', password: 'secret', kind: 'login' });
});
test('registration chooses matching new-password fields', () => {
  const fields = [input({ type: 'email' }, 'me@example.com'), input({ type: 'password', autocomplete: 'new-password' }, 'new'),
    input({ type: 'password', autocomplete: 'new-password' }, 'new')];
  assert.equal(forms.candidate(scope(fields)).kind, 'register');
  fields[2].value = 'different'; assert.equal(forms.candidate(scope(fields)), null);
});
test('password change stages new password instead of old password', () => {
  assert.deepEqual(forms.candidate(scope([input({ autocomplete: 'username' }, 'me'),
    input({ type: 'password', autocomplete: 'current-password' }, 'old'),
    input({ type: 'password', autocomplete: 'new-password' }, 'new'), input({ type: 'password', autocomplete: 'new-password' }, 'new')])),
    { username: 'me', password: 'new', kind: 'change' });
});
test('unlabelled change and registration require matching confirmation fields', () => {
  assert.equal(forms.candidate(scope([input({ type: 'password' }, 'old'), input({ type: 'password' }, 'new'), input({ type: 'password' }, 'new')])).password, 'new');
  assert.equal(forms.candidate(scope([input({ type: 'password' }, 'new'), input({ type: 'password' }, 'new')])).kind, 'register');
  assert.equal(forms.candidate(scope([input({ type: 'password' }, 'old'), input({ type: 'password' }, 'new')])), null);
});
test('OTP, hidden, readonly and disabled inputs never become password candidates', () => {
  const disabled = input({ type: 'password' }, 'disabled'); disabled.disabled = true;
  const readonly = input({ type: 'password' }, 'readonly'); readonly.readOnly = true;
  assert.equal(forms.candidate(scope([input({ type: 'password', autocomplete: 'one-time-code' }, '123456'),
    input({ type: 'password', visible: false }, 'hidden'), disabled, readonly])), null);
});
test('click fill uses native input setter and events but never submits', () => {
  setLocation();
  const username = input({ name: 'login' }, ''), password = input({ type: 'password' }, '');
  const result = forms.fill(doc([scope([username, password])]), { username: 'octocat', password: 'secret' }, 'https://github.com');
  assert.equal(result.filled, true); assert.equal(username.value, 'octocat'); assert.equal(password.value, 'secret');
  assert.deepEqual(username.events, ['input', 'change']); assert.deepEqual(password.events, ['input', 'change']);
});
test('Google and Microsoft identifier-only pages fill account without revealing password', () => {
  for (const attrs of [{ id: 'identifierId', type: 'email' }, { name: 'loginfmt', autocomplete: 'username' }]) {
    setLocation('https://accounts.google.com/'); const username = input(attrs, '');
    const result = forms.fill(doc([], [username]), { username: 'me@example.com', password: 'secret' }, 'https://accounts.google.com');
    assert.equal(result.filled, true); assert.equal(result.usernameOnly, true); assert.equal(username.value, 'me@example.com');
  }
});
test('fill refuses new-password and ambiguous multi-password forms', () => {
  setLocation();
  for (const passwords of [[input({ type: 'password', autocomplete: 'new-password' }, '')],
    [input({ type: 'password' }, ''), input({ type: 'password' }, '')]]) {
    const result = forms.fill(doc([scope([input({ autocomplete: 'username' }, ''), ...passwords])]), { username: 'me', password: 'secret' }, 'https://github.com');
    assert.equal(result.filled, false); assert.ok(passwords.every(field => field.value === ''));
  }
});
test('fill refuses host change, HTTP and iframes', () => {
  for (const [url, top] of [['https://attacker.example/', true], ['http://github.com/', true], ['https://github.com/', false]]) {
    setLocation(url, top); const password = input({ type: 'password' }, '');
    assert.equal(forms.fill(doc([scope([password])]), { username: 'me', password: 'secret' }, 'https://github.com').filled, false);
    assert.equal(password.value, '');
  }
});
test('fields are rediscovered for dynamically replaced login inputs', () => {
  setLocation(); let current = input({ type: 'password' }, '');
  const live = { querySelectorAll(selector) { return selector === 'form' ? [] : [current]; } };
  forms.fill(live, { username: '', password: 'first' }, 'https://github.com');
  const prior = current; current = input({ type: 'password' }, '');
  forms.fill(live, { username: '', password: 'second' }, 'https://github.com');
  assert.equal(prior.value, 'first'); assert.equal(current.value, 'second');
});
test('unrelated search input is not considered a username-only login form', () => {
  setLocation(); const search = input({ name: 'search-term' }, '');
  assert.equal(forms.fill(doc([], [search]), { username: 'me', password: 'secret' }, 'https://github.com').filled, false);
  assert.equal(search.value, '');
});
