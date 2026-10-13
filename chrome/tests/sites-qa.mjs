/** Read-only public login-page compatibility check. No credentials are filled or submitted. */
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
const output = path.resolve(process.env.PRIVATE_VAULT_CHROME_QA_OUT || path.join(process.cwd(), 'work/chrome-v03-sites', crypto.randomUUID()));
mkdirSync(output, { recursive: true });
const browser = spawn(process.env.PRIVATE_VAULT_CHROME_EXE || 'C:/Program Files/Google/Chrome/Application/chrome.exe',
  ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    `--user-data-dir=${path.join(output, 'profile')}`, '--remote-debugging-pipe'],
  { windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
let nextId = 0, buffer = ''; const pending = new Map();
function command(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++nextId, timer = setTimeout(() => { pending.delete(id); reject(new Error(`${method} timeout`)); }, 20000);
    pending.set(id, { resolve, reject, timer });
    browser.stdio[3].write(`${JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })}\0`);
  });
}
browser.on('error', error => { for (const request of pending.values()) { clearTimeout(request.timer); request.reject(error); } pending.clear(); });
browser.stdio[4].on('data', data => {
  buffer += data.toString(); let split;
  while ((split = buffer.indexOf('\0')) >= 0) {
    const text = buffer.slice(0, split); buffer = buffer.slice(split + 1); if (!text) continue;
    const response = JSON.parse(text), request = pending.get(response.id); if (!request) continue;
    clearTimeout(request.timer); pending.delete(response.id);
    response.error ? request.reject(new Error(response.error.message)) : request.resolve(response.result);
  }
});
async function evaluate(sessionId, expression) {
  const response = await command('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
  return response.result.value;
}
const sites = [{ name: 'Google', url: 'https://accounts.google.com/ServiceLogin', expected: 'username-first' },
  { name: 'GitHub', url: 'https://github.com/login', expected: 'username-and-password' },
  { name: 'Microsoft', url: 'https://login.live.com/', expected: 'username-first' }];
const result = { checkedAt: new Date().toISOString(), profileIsolated: true, readOnly: true, credentialsUsed: false, sites: [] };
try {
  result.chrome = (await command('Browser.getVersion')).product;
  for (const site of sites) {
    const report = { ...site };
    try {
      const { targetId } = await command('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
      await command('Page.enable', {}, sessionId); await command('Runtime.enable', {}, sessionId);
      await command('Emulation.setDeviceMetricsOverride', { width: 1280, height: 850, deviceScaleFactor: 1, mobile: false }, sessionId);
      const navigation = await command('Page.navigate', { url: site.url }, sessionId);
      if (navigation.errorText) report.navigationError = navigation.errorText;
      for (let attempt = 0; attempt < 40; attempt++) {
        const ready = await evaluate(sessionId, `document.readyState==='complete' && (!!document.querySelector('input') || document.body?.innerText?.length>100)`);
        if (ready) break;
        await new Promise(resolve => setTimeout(resolve, 200));
      }
      await evaluate(sessionId, readFileSync(path.resolve(import.meta.dirname, '../forms.js'), 'utf8'));
      report.page = await evaluate(sessionId, `(()=>{const f=PrivateVaultForms.fields(document);return {url:location.href,title:document.title,username:f.username?{type:f.username.type,id:f.username.id,name:f.username.name,autocomplete:f.username.autocomplete}:null,passwordFields:f.passwords.map(i=>({type:i.type,id:i.id,name:i.name,autocomplete:i.autocomplete})),inputCount:document.querySelectorAll('input').length,bodyExcerpt:document.body.innerText.slice(0,600)}})()`);
      report.compatibleAtCurrentStep = site.expected === 'username-first' ? !!report.page.username : !!report.page.username && report.page.passwordFields.length === 1;
      if (!report.compatibleAtCurrentStep) report.limitation = report.navigationError || 'Public page did not expose the expected login fields; inspect page excerpt/screenshot for captcha, consent or network restriction.';
      writeFileSync(path.join(output, `${site.name.toLowerCase()}.png`), Buffer.from((await command('Page.captureScreenshot', { format: 'png' }, sessionId)).data, 'base64'));
      await command('Target.closeTarget', { targetId });
    } catch (error) { report.error = error.message; report.compatibleAtCurrentStep = false; }
    result.sites.push(report);
  }
  result.output = output;
  writeFileSync(path.join(output, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result, null, 2));
} finally { try { await command('Browser.close'); } catch { browser.kill(); } }
