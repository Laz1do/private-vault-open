/** Optional real-Chrome QA. Uses a disposable profile and synthetic credentials only. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
const extension = path.resolve(import.meta.dirname, '..');
const output = path.resolve(process.env.PRIVATE_VAULT_CHROME_QA_OUT || path.join(process.cwd(), 'work/chrome-v03-qa', crypto.randomUUID()));
mkdirSync(output, { recursive: true });
const chromePath = process.env.PRIVATE_VAULT_CHROME_EXE || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const browser = spawn(chromePath, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--disable-background-networking', `--user-data-dir=${path.join(output, 'profile')}`,
  '--remote-debugging-pipe', '--enable-unsafe-extension-debugging'], { windowsHide: true,
  stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
const pending = new Map(), listeners = new Map();
let nextId = 0, buffer = '';
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Chrome timed out: ${method}`)); }, 20000);
    pending.set(id, { resolve, reject, timer });
    browser.stdio[3].write(`${JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })}\0`);
  });
}
browser.on('error', error => { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(error); } pending.clear(); });
browser.stdio[4].on('data', data => {
  buffer += data.toString();
  let split;
  while ((split = buffer.indexOf('\0')) !== -1) {
    const text = buffer.slice(0, split); buffer = buffer.slice(split + 1);
    if (!text) continue;
    const message = JSON.parse(text), item = pending.get(message.id);
    if (item) { clearTimeout(item.timer); pending.delete(message.id);
      if (message.error) item.reject(new Error(`${message.error.message} (${message.error.code})`)); else item.resolve(message.result); }
    else if (message.method) for (const fn of listeners.get(message.method) || []) fn(message.params, message.sessionId);
  }
});
async function page() {
  const { targetId } = await command('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
  await command('Page.enable', {}, sessionId); await command('Runtime.enable', {}, sessionId);
  return sessionId;
}
async function evaluate(sessionId, expression) {
  const response = await command('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (response.exceptionDetails) throw new Error(response.exceptionDetails.text + ': ' + JSON.stringify(response.exceptionDetails.exception));
  return response.result.value;
}
async function ready(sessionId, predicate) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (await evaluate(sessionId, predicate)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Chrome page did not become ready');
}
const records = [{ id: 'first', title: '个人账号', username: 'me@example.com', stamp: 'a' },
  { id: 'second', title: '工作账号', username: 'work@example.com', stamp: 'b' }];
const base = { connected: true, permissionEnabled: true, status: { enabled: true, browserEnabled: true, vaultId: 'test-vault' },
  tab: { id: 7, url: 'https://login.example.com/', host: 'login.example.com' },
  matches: { vaultId: 'test-vault', records }, draft: null };
const checks = [];
try {
  const version = await command('Browser.getVersion');
  const loaded = await command('Extensions.loadUnpacked', { path: extension });
  assert.equal(loaded.id, 'dinagdpfpgbcfepiaabjccimnppakedl');
  checks.push('real Chrome loads MV3 manifest with stable ID');
  const popup = await page();
  await command('Emulation.setDeviceMetricsOverride', { width: 380, height: 600, deviceScaleFactor: 1, mobile: false }, popup);
  // This is visual QA only: no registered native host is contacted and no personal vault is opened.
  await command('Page.addScriptToEvaluateOnNewDocument', { source: `globalThis.__qaState=${JSON.stringify(base)};chrome.runtime.sendMessage=async(message)=>({ok:true,result:message.type==='state'?globalThis.__qaState:{filled:true}});` }, popup);
  await command('Page.navigate', { url: `chrome-extension://${loaded.id}/popup.html` }, popup);
  await ready(popup, `document.querySelectorAll('.account').length===2`);
  for (const theme of ['light', 'dark']) {
    await command('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] }, popup);
    await evaluate(popup, 'new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
    const screenshot = await command('Page.captureScreenshot', { format: 'png' }, popup);
    writeFileSync(path.join(output, `popup-accounts-${theme}.png`), Buffer.from(screenshot.data, 'base64'));
  }
  const draft = { draftId: 'draft-test', vaultId: 'test-vault', kind: 'update', host: 'login.example.com',
    title: 'Example', username: 'me@example.com', password: 'SYNTHETIC-QA-ONLY', records };
  await evaluate(popup, `globalThis.__qaState.draft=${JSON.stringify(draft)};document.getElementById('refresh').click()`);
  await ready(popup, `!document.getElementById('save-section').hidden`);
  assert.equal(await evaluate(popup, `document.getElementById('save-password').type`), 'password');
  assert.equal(await evaluate(popup, `document.getElementById('save-target').value`), 'first');
  assert.equal(await evaluate(popup, `document.documentElement.scrollWidth<=380`), true);
  for (const theme of ['light', 'dark']) {
    await command('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }, { name: 'prefers-reduced-motion', value: 'reduce' }] }, popup);
    await evaluate(popup, 'new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
    writeFileSync(path.join(output, `popup-save-${theme}.png`), Buffer.from((await command('Page.captureScreenshot', { format: 'png' }, popup)).data, 'base64'));
  }
  assert.equal(await evaluate(popup, `getComputedStyle(document.getElementById('save')).transitionDuration`), '0s');
  checks.push('light/dark popup, masked confirmation, exact account selection, 380px layout, reduced motion');
  const fixturePage = await page();
  const fixtureHTML = `<html><head><meta charset="utf-8"></head><body><form><input name="login" autocomplete="username"><input type="password" autocomplete="current-password"><button type="submit">登录</button></form><div id="dynamic"></div></body></html>`;
  listeners.set('Fetch.requestPaused', [async (params, sid) => {
    if (sid === fixturePage) await command('Fetch.fulfillRequest', { requestId: params.requestId, responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }], body: Buffer.from(fixtureHTML).toString('base64') }, sid);
  }]);
  await command('Fetch.enable', { patterns: [{ urlPattern: 'https://pvault.test/*', requestStage: 'Request' }] }, fixturePage);
  await command('Page.navigate', { url: 'https://pvault.test/login' }, fixturePage);
  await ready(fixturePage, `document.querySelectorAll('input').length===2`);
  await evaluate(fixturePage, readFileSync(path.join(extension, 'forms.js'), 'utf8'));
  const fill = await evaluate(fixturePage, `PrivateVaultForms.fill(document,{username:'synthetic-user',password:'SYNTHETIC-QA-ONLY'},'https://pvault.test')`);
  assert.equal(fill.filled, true);
  assert.deepEqual(await evaluate(fixturePage, `[...document.querySelectorAll('input')].map(input=>input.value)`), ['synthetic-user', 'SYNTHETIC-QA-ONLY']);
  assert.equal((await evaluate(fixturePage, `PrivateVaultForms.candidate(document)`)).kind, 'login');
  await evaluate(fixturePage, `document.body.innerHTML='<form><input autocomplete="username" value="synthetic-user"><input type="password" autocomplete="current-password" value="old"><input type="password" autocomplete="new-password" value="new"><input type="password" autocomplete="new-password" value="new"></form>'`);
  const changed = await evaluate(fixturePage, `PrivateVaultForms.candidate(document)`);
  assert.equal(changed.kind, 'change'); assert.equal(changed.password, 'new');
  checks.push('real HTTPS DOM fixture: native input setters, ordinary login, dynamic password-change fields');
  // Exercise real Chrome sender classification, action popup, activeTab and document-bound filling.
  // Only the native API is replaced; optional HTTPS detection permission remains ungranted.
  const { targetInfos } = await command('Target.getTargets');
  const workerTarget = targetInfos.find(target => target.type === 'service_worker' && target.url === `chrome-extension://${loaded.id}/worker.js`);
  assert.ok(workerTarget);
  const { sessionId: worker } = await command('Target.attachToTarget', { targetId: workerTarget.targetId, flatten: true });
  await command('Runtime.enable', {}, worker);
  await evaluate(worker, `globalThis.__qaNativeCalls=[];chrome.runtime.connectNative=()=>{const callbacks=[];return {onMessage:{addListener:fn=>callbacks.push(fn)},onDisconnect:{addListener:()=>{}},postMessage:message=>{__qaNativeCalls.push(message.command);let result=message.command==='status'?{enabled:true,browserEnabled:true,vaultId:'test-vault'}:message.command==='matches'?{enabled:true,vaultId:'test-vault',records:${JSON.stringify(records)}}:message.command==='fill'?{username:'synthetic-user',password:'SYNTHETIC-QA-ONLY'}:{};queueMicrotask(()=>callbacks.forEach(fn=>fn({requestId:message.requestId,ok:true,result})))}}};true`);
  assert.equal(await evaluate(worker, `chrome.permissions.contains({origins:['https://*/*']})`), false);
  assert.deepEqual(await evaluate(worker, `chrome.scripting.getRegisteredContentScripts()`), []);
  await evaluate(fixturePage, `document.body.innerHTML='<form><input name="login" autocomplete="username"><input type="password" autocomplete="current-password"><button type="submit">登录</button></form>'`);
  const fixtureTarget = (await command('Target.getTargets', { filter: [{ type: 'tab', exclude: false }, { exclude: true }] }))
    .targetInfos.find(target => target.url === 'https://pvault.test/login');
  assert.ok(fixtureTarget, 'outer tab target exists');
  await command('Target.activateTarget', { targetId: fixtureTarget.targetId });
  await command('Extensions.triggerAction', { id: loaded.id, targetId: fixtureTarget.targetId });
  let actionTarget;
  const existingPopupTargets = new Set(targetInfos.filter(target => target.url === `chrome-extension://${loaded.id}/popup.html`).map(target => target.targetId));
  for (let attempt = 0; attempt < 30; attempt++) {
    actionTarget = (await command('Target.getTargets')).targetInfos.find(target => target.url === `chrome-extension://${loaded.id}/popup.html` && !existingPopupTargets.has(target.targetId));
    if (actionTarget) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.ok(actionTarget, 'real extension action popup target exists');
  const { sessionId: actionPopup } = await command('Target.attachToTarget', { targetId: actionTarget.targetId, flatten: true });
  await command('Runtime.enable', {}, actionPopup);
  await ready(actionPopup, `document.querySelectorAll('.account').length===2`);
  assert.equal(await evaluate(actionPopup, `document.getElementById('host').textContent`), 'pvault.test');
  await evaluate(actionPopup, `document.querySelector('.account').click();true`);
  await ready(fixturePage, `document.querySelector('input[type=password]').value==='SYNTHETIC-QA-ONLY'`);
  assert.deepEqual(await evaluate(fixturePage, `[...document.querySelectorAll('input')].map(input=>input.value)`), ['synthetic-user', 'SYNTHETIC-QA-ONLY']);
  assert.ok((await evaluate(worker, `__qaNativeCalls`)).includes('fill'));
  checks.push('real action popup sender, optional detector off, activeTab manual fill, native-envelope mock, bound document injection');
  const result = { passed: true, chrome: version.product, extensionId: loaded.id, nativeConnectionMockedForVisuals: true,
    realWebAccountsUsed: false, checks, output };
  writeFileSync(path.join(output, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result, null, 2));
} finally {
  try { await command('Browser.close'); } catch { browser.kill(); }
  for (const request of pending.values()) { clearTimeout(request.timer); request.reject(new Error('QA browser closed')); }
  pending.clear();
}
