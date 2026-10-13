import { HTTPS_PATTERN } from './policy.js';
const $ = id => document.getElementById(id);
let state = null, busy = false;
async function request(type, params = {}) {
  const response = await chrome.runtime.sendMessage({ type, ...params });
  if (!response?.ok) throw Object.assign(new Error(response?.error?.message || '操作未完成，请重试。'), { code: response?.error?.code });
  return response.result;
}
function message(text, error = false) {
  $('message').textContent = text;
  $('message').classList.toggle('error', error);
  $('message').hidden = !text;
}
function setBusy(value) {
  busy = value;
  for (const button of document.querySelectorAll('button')) button.disabled = value;
}
async function action(operation) {
  if (busy) return;
  setBusy(true); message('');
  try { await operation(); }
  catch (error) { message(error.message, true); }
  finally { setBusy(false); }
}
function renderDraft(draft) {
  $('save-section').hidden = !draft;
  if (!draft) { $('save-password').value = ''; return; }
  $('save-heading').textContent = draft.kind === 'update' ? '更新这个账号' : '保存这个账号';
  $('save-source').textContent = `来源：${draft.host} · 确认后写入本机密码库`;
  $('save-title').value = draft.title || draft.host;
  $('save-username').value = draft.username || '';
  $('save-password').value = draft.password || '';
  $('save-password').type = 'password'; $('reveal').textContent = '显示'; $('reveal').setAttribute('aria-label', '显示密码');
  const select = $('save-target');
  select.replaceChildren();
  const create = document.createElement('option'); create.value = ''; create.textContent = '新建记录'; select.append(create);
  for (const record of draft.records || []) {
    const option = document.createElement('option'); option.value = record.id;
    option.textContent = `更新：${record.title} · ${record.username || '未填写账号'}`;
    select.append(option);
  }
  const matching = (draft.records || []).filter(record => record.username === draft.username);
  select.value = draft.kind === 'update' && matching.length === 1 ? matching[0].id : '';
  updateTarget();
}
function updateTarget() {
  const updating = !!$('save-target').value;
  $('title-field').hidden = updating;
  $('save-title').required = !updating;
  $('update-note').hidden = !updating;
  $('save').textContent = updating ? '确认更新' : '确认保存';
}
function render(next) {
  state = next;
  $('host').textContent = next.tab?.host || '打开一个 HTTPS 网站';
  const available = next.connected && next.status?.enabled && !next.status?.needsImport && !next.status?.changingVault;
  $('connection').textContent = next.connected ? (available ? '已连接' : '已关闭') : '未连接';
  $('connection').classList.toggle('connected', available);
  let notice = '';
  if (!next.connected) notice = next.error?.message || '请打开 Windows 密码客户端，然后点击右上角重新连接。';
  else if (next.status?.needsImport) notice = '密码库需要恢复，请先在 Windows 客户端导入原库文件。';
  else if (next.status?.changingVault) notice = '密码库正在切换，请稍后重试。';
  else if (!next.status?.enabled) notice = '请在 Windows 客户端的“浏览器助手”里开启此功能。';
  else if (next.tabError) notice = next.tabError;
  $('disabled').textContent = notice; $('disabled').hidden = !notice;
  $('accounts-section').hidden = !available || !next.tab;
  const records = next.matches?.records || [];
  $('account-count').textContent = records.length ? `${records.length}${next.matches?.truncated ? '+' : ''} 个` : '';
  const accounts = $('accounts'); accounts.replaceChildren();
  for (const record of records) {
    const button = document.createElement('button'); button.className = 'account'; button.type = 'button';
    const initial = document.createElement('span'); initial.className = 'account-initial'; initial.setAttribute('aria-hidden', 'true');
    initial.textContent = (record.title || '?').slice(0, 1).toUpperCase();
    const copy = document.createElement('span'); copy.className = 'account-copy';
    const title = document.createElement('span'); title.className = 'account-title'; title.textContent = record.title;
    const username = document.createElement('span'); username.className = 'account-username'; username.textContent = record.username || '未填写账号';
    const fill = document.createElement('span'); fill.className = 'account-action'; fill.textContent = '填写';
    copy.append(title, username); button.append(initial, copy, fill);
    button.addEventListener('click', () => void action(async () => {
      const result = await request('fill', { tabId: next.tab.id, vaultId: next.matches.vaultId,
        recordId: record.id, stamp: record.stamp });
      message(result.usernameOnly ? '账号已填写。进入密码步骤后，再点一次此账号。' : '已填写，请自行点击网站登录。');
    }));
    accounts.append(button);
  }
  $('empty').hidden = records.length > 0;
  $('fill-note').hidden = !records.length;
  $('fill-note').textContent = next.matches?.truncated
    ? '当前显示前 50 个匹配账号。可在软件里整理记录，再选择填写。'
    : '选择账号即可填写，然后由你点击网站登录。';
  renderDraft(available ? next.draft : null);
  $('detection').textContent = next.permissionEnabled ? '关闭' : '开启';
  $('detection-note').textContent = next.permissionEnabled
    ? '已允许在所有 HTTPS 网站识别提交的密码。'
    : '开启后，在所有 HTTPS 网站识别提交的密码。';
}
async function refresh() { render(await request('state')); }
$('refresh').addEventListener('click', () => void action(refresh));
$('save-target').addEventListener('change', updateTarget);
$('reveal').addEventListener('click', () => {
  const showing = $('save-password').type === 'password';
  $('save-password').type = showing ? 'text' : 'password';
  $('reveal').textContent = showing ? '隐藏' : '显示';
  $('reveal').setAttribute('aria-label', showing ? '隐藏密码' : '显示密码');
});
$('save-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    const draft = state?.draft;
    if (!draft) throw new Error('候选已失效，请重新提交网站表单。');
    const recordId = $('save-target').value || null;
    const record = recordId ? draft.records.find(item => item.id === recordId) : null;
    await request('confirm', { tabId: state.tab.id, draftId: draft.draftId, vaultId: draft.vaultId,
      title: record ? undefined : $('save-title').value, username: $('save-username').value,
      password: $('save-password').value, recordId, stamp: record?.stamp });
    await refresh(); message(record ? '已更新到密码库。' : '已保存到密码库。');
  });
});
$('dismiss').addEventListener('click', () => void action(async () => {
  await request('dismiss', { tabId: state.tab.id, draftId: state.draft.draftId });
  await refresh(); message('已忽略这次候选。');
}));
$('detection').addEventListener('click', () => void action(async () => {
  // Permission request starts directly from the user gesture.
  const granted = state?.permissionEnabled
    ? !(await chrome.permissions.remove({ origins: [HTTPS_PATTERN] }))
    : await chrome.permissions.request({ origins: [HTTPS_PATTERN] });
  await request('refresh-detection'); await refresh();
  if (!granted && !state.permissionEnabled) message('网站检测已关闭。点击账号仍可手动填写。');
}));
void action(refresh);
