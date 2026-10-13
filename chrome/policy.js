export const NATIVE_HOST = 'com.local.privatevault';
export const SCRIPT_ID = 'private-vault-https-detection';
export const HTTPS_PATTERN = 'https://*/*';

export function checkedHttpsUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) throw new Error('请在 HTTPS 网站使用浏览器助手。');
  let url;
  try { url = new URL(value); } catch { throw new Error('当前网站地址无效。'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password)
    throw new Error('请在 HTTPS 网站使用浏览器助手。');
  url.hash = '';
  return url.href;
}

export function isPopupSender(sender, extensionId) {
  return sender?.id === extensionId && !sender.tab
    && sender.url === `chrome-extension://${extensionId}/popup.html`;
}

export function checkedContentSender(sender, extensionId) {
  if (sender?.id !== extensionId || !Number.isInteger(sender.tab?.id) || sender.frameId !== 0
    || typeof sender.documentId !== 'string') throw new Error('仅接受当前网站主页面的请求。');
  const url = checkedHttpsUrl(sender.url);
  if (new URL(url).origin !== new URL(checkedHttpsUrl(sender.tab.url)).origin)
    throw new Error('网站页面已经变化，请重新操作。');
  return { tabId: sender.tab.id, documentId: sender.documentId, url, host: new URL(url).host };
}

export function boundedCandidate(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('没有识别到可保存的密码。');
  const { username, password, kind } = value;
  if (typeof username !== 'string' || username.length > 1000 || typeof password !== 'string'
    || !password || password.length > 4096 || !['login', 'register', 'change'].includes(kind))
    throw new Error('识别的账号或密码超出限制。');
  return { username, password, kind };
}

export function publicError(error) {
  return { code: typeof error?.code === 'string' ? error.code : 'extension_error',
    message: typeof error?.message === 'string' ? error.message : '操作未完成，请重试。' };
}
