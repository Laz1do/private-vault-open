import { NATIVE_HOST, SCRIPT_ID, HTTPS_PATTERN, checkedHttpsUrl, isPopupSender,
  checkedContentSender, boundedCandidate, publicError } from './policy.js';

let nativePort = null;
const requests = new Map();
const drafts = new Map();
const usernames = new Map();
const REQUEST_TIMEOUT = 15000;
const DRAFT_TTL = 10 * 60 * 1000;

function nativeRequest(command, params = {}) {
  return new Promise((resolve, reject) => {
    let port;
    try {
      if (!nativePort) {
        nativePort = chrome.runtime.connectNative(NATIVE_HOST);
        const current = nativePort;
        current.onMessage.addListener(message => {
          const pending = requests.get(message?.requestId);
          if (!pending) return;
          clearTimeout(pending.timer); requests.delete(message.requestId);
          if (message.ok === true) pending.resolve(message.result);
          else pending.reject(Object.assign(new Error(message.error?.message || '密码软件未完成操作。'),
            { code: message.error?.code || 'native_error' }));
        });
        current.onDisconnect.addListener(() => {
          // Read lastError, but do not include platform diagnostics or credential fields in logs.
          const unavailable = chrome.runtime.lastError;
          void unavailable;
          if (nativePort === current) nativePort = null;
          for (const [id, pending] of requests) {
            clearTimeout(pending.timer); requests.delete(id);
            pending.reject(Object.assign(new Error('未连接到密码软件。请打开 Windows 客户端后重试。'), { code: 'app_offline' }));
          }
        });
      }
      port = nativePort;
      const requestId = crypto.randomUUID();
      const timer = setTimeout(() => {
        requests.delete(requestId);
        reject(Object.assign(new Error('密码软件响应超时，请重试。'), { code: 'native_timeout' }));
      }, REQUEST_TIMEOUT);
      requests.set(requestId, { resolve, reject, timer });
      try { port.postMessage({ requestId, command, params }); }
      catch (error) { clearTimeout(timer); requests.delete(requestId); reject(error); }
    } catch { reject(Object.assign(new Error('未连接到密码软件。请安装并打开 Windows 客户端。'), { code: 'app_offline' })); }
  });
}

async function updateDetection() {
  const permitted = await chrome.permissions.contains({ origins: [HTTPS_PATTERN] });
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID] });
  if (permitted && !existing.length) await chrome.scripting.registerContentScripts([{
    id: SCRIPT_ID, matches: [HTTPS_PATTERN], js: ['forms.js', 'content.js'],
    allFrames: false, runAt: 'document_idle', persistAcrossSessions: true
  }]);
  if (!permitted && existing.length) await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] });
  return permitted;
}

async function activeTab(requestedId) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !Number.isInteger(tab.id) || (requestedId !== undefined && requestedId !== tab.id))
    throw new Error('当前标签页已经变化，请重新打开助手。');
  return { id: tab.id, url: checkedHttpsUrl(tab.url), host: new URL(tab.url).host };
}

async function badge(tabId, present) {
  await Promise.allSettled([
    chrome.action.setBadgeText({ tabId, text: present ? '1' : '' }),
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#4B68E8' })
  ]);
}

async function promptDraft(tabId) {
  // Chrome 127+ can open action popups from a service worker. Older versions retain the badge.
  if (typeof chrome.action.openPopup !== 'function') return;
  const tab = await chrome.tabs.get(tabId);
  if (!tab.active) return;
  await chrome.action.openPopup({ windowId: tab.windowId });
}

async function currentDraft(tabId) {
  const held = drafts.get(tabId);
  if (!held) return null;
  if (Date.now() - held.createdAt > DRAFT_TTL) {
    drafts.delete(tabId); await badge(tabId, false); return null;
  }
  try { return await nativeRequest('draft', { draftId: held.draftId }); }
  catch (error) {
    if (['draft_expired', 'invalid_draft', 'stale_vault', 'browser_disabled'].includes(error.code)) {
      drafts.delete(tabId); await badge(tabId, false); return null;
    }
    throw error;
  }
}

async function popupState() {
  const permissionEnabled = await updateDetection();
  let tab = null, tabError = null;
  try { tab = await activeTab(); } catch (error) { tabError = error.message; }
  let status;
  try { status = await nativeRequest('status'); }
  catch (error) { return { connected: false, permissionEnabled, tab, tabError, error: publicError(error) }; }
  let matches = { records: [], vaultId: status.vaultId }, draft = null;
  if (status.enabled && !status.needsImport && !status.changingVault && tab) {
    matches = await nativeRequest('matches', { url: tab.url });
    draft = await currentDraft(tab.id);
  }
  return { connected: true, permissionEnabled, status, tab, tabError, matches, draft };
}

async function ensureScripts(tab) {
  const hasPermission = await chrome.permissions.contains({ origins: [HTTPS_PATTERN] });
  // activeTab also permits explicit, user-initiated filling when auto detection is off.
  await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, files: ['forms.js'] });
  if (hasPermission) await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, files: ['content.js'] });
}

async function fillSelected(message) {
  const tab = await activeTab(message.tabId);
  await ensureScripts(tab);
  const [snapshot] = await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: () => ({ url: location.href, top: window.top === window.self }) });
  if (!snapshot?.documentId || !snapshot.result?.top) throw new Error('当前页面无法填写。');
  const liveUrl = checkedHttpsUrl(snapshot.result.url);
  if (new URL(liveUrl).origin !== new URL(tab.url).origin) throw new Error('网站页面已经变化，请重试。');
  const credential = await nativeRequest('fill', { url: liveUrl, recordId: message.recordId,
    stamp: message.stamp, vaultId: message.vaultId });
  const [result] = await chrome.scripting.executeScript({
    target: { tabId: tab.id, documentIds: [snapshot.documentId] },
    func: (value, origin) => globalThis.PrivateVaultForms?.fill(document, value, origin)
      || { filled: false, reason: '网站页面已经变化，请重试。' },
    args: [credential, new URL(liveUrl).origin]
  });
  if (!result?.result?.filled) throw new Error(result?.result?.reason || '网站页面已经变化，请重试。');
  if (credential.username) usernames.set(tab.id, { host: tab.host, username: credential.username,
    vaultId: message.vaultId, at: Date.now() });
  return result.result;
}

async function fromPopup(message) {
  switch (message?.type) {
    case 'state': return popupState();
    case 'refresh-detection': {
      const enabled = await updateDetection();
      if (enabled) {
        try { await ensureScripts(await activeTab()); } catch { /* non-HTTPS page */ }
      }
      return { enabled };
    }
    case 'fill': return fillSelected(message);
    case 'confirm': {
      const tab = await activeTab(message.tabId);
      const held = drafts.get(tab.id);
      if (!held || held.draftId !== message.draftId) throw new Error('候选已失效，请重新提交网站表单。');
      const params = { draftId: message.draftId, vaultId: message.vaultId,
        username: message.username, password: message.password, recordId: message.recordId ?? null };
      if (message.title !== undefined) params.title = message.title;
      if (message.stamp !== undefined) params.stamp = message.stamp;
      const result = await nativeRequest('confirm', params);
      drafts.delete(tab.id); await badge(tab.id, false); return result;
    }
    case 'dismiss': {
      const tab = await activeTab(message.tabId);
      const held = drafts.get(tab.id);
      if (!held || held.draftId !== message.draftId) throw new Error('候选已失效。');
      const result = await nativeRequest('dismiss', { draftId: message.draftId });
      drafts.delete(tab.id); await badge(tab.id, false); return result;
    }
    default: throw new Error('不支持的助手操作。');
  }
}

async function fromContent(message, sender) {
  const source = checkedContentSender(sender, chrome.runtime.id);
  if (!(await chrome.permissions.contains({ origins: [HTTPS_PATTERN] }))) return { disabled: true };
  if (message?.type === 'remember-username') {
    if (typeof message.username !== 'string' || !message.username || message.username.length > 1000) return { ignored: true };
    const status = await nativeRequest('status');
    if (!status.enabled) return { disabled: true };
    usernames.set(source.tabId, { host: source.host, username: message.username, vaultId: status.vaultId, at: Date.now() });
    return { remembered: true };
  }
  if (message?.type !== 'stage') throw new Error('网站页面只能提交待确认候选。');
  const candidate = boundedCandidate(message.candidate);
  const status = await nativeRequest('status');
  if (!status.enabled) { usernames.delete(source.tabId); return { disabled: true }; }
  const remembered = usernames.get(source.tabId);
  if (!candidate.username && remembered?.host === source.host && remembered.vaultId === status.vaultId
    && Date.now() - remembered.at < 5 * 60 * 1000)
    candidate.username = remembered.username;
  const result = await nativeRequest('stage', { url: source.url, ...candidate });
  if (result?.draftId) {
    const old = drafts.get(source.tabId);
    if (old?.draftId && old.draftId !== result.draftId) void nativeRequest('dismiss', { draftId: old.draftId }).catch(() => {});
    drafts.set(source.tabId, { draftId: result.draftId, createdAt: Date.now() });
    await badge(source.tabId, true);
    void promptDraft(source.tabId).catch(() => {});
  }
  // Website scripts never receive native record metadata or plaintext from the vault.
  return { staged: !!result?.draftId, unchanged: !!result?.unchanged, disabled: !!result?.disabled };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const operation = isPopupSender(sender, chrome.runtime.id) ? fromPopup(message) : fromContent(message, sender);
  Promise.resolve(operation).then(result => sendResponse({ ok: true, result }),
    error => sendResponse({ ok: false, error: publicError(error) }));
  return true;
});
chrome.permissions.onAdded.addListener(() => void updateDetection().catch(() => {}));
chrome.permissions.onRemoved.addListener(() => void updateDetection().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => void updateDetection().catch(() => {}));
chrome.runtime.onStartup.addListener(() => void updateDetection().catch(() => {}));
chrome.tabs.onRemoved.addListener(tabId => {
  const held = drafts.get(tabId);
  drafts.delete(tabId); usernames.delete(tabId);
  if (held) void nativeRequest('dismiss', { draftId: held.draftId }).catch(() => {});
});
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (!change.url) return;
  const remembered = usernames.get(tabId);
  try { if (remembered?.host !== new URL(checkedHttpsUrl(change.url)).host) usernames.delete(tabId); }
  catch { usernames.delete(tabId); }
});
