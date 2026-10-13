(() => {
  if (globalThis.__privateVaultDetection || location.protocol !== 'https:' || window.top !== window.self) return;
  globalThis.__privateVaultDetection = true;
  const forms = globalThis.PrivateVaultForms;
  let previous = '', previousTime = 0;
  let debounce;
  async function submitted(target, trusted) {
    if (!trusted) return;
    const scope = forms.scopeFor(target, document);
    const found = forms.fields(scope);
    const username = String(found.username?.value || '');
    if (username && username.length <= 1000) {
      void chrome.runtime.sendMessage({ type: 'remember-username', username }).catch(() => {});
    }
    const candidate = forms.candidate(scope);
    if (!candidate) return;
    const bytes = new TextEncoder().encode(JSON.stringify(candidate));
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    bytes.fill(0);
    const fingerprint = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    if (previous === fingerprint && Date.now() - previousTime < 3000) return;
    previous = fingerprint; previousTime = Date.now();
    try { await chrome.runtime.sendMessage({ type: 'stage', candidate }); } catch { /* app may be closed */ }
  }
  document.addEventListener('submit', event => void submitted(event.target, event.isTrusted), true);
  document.addEventListener('click', event => {
    const button = event.target?.closest?.('button, input[type="submit"], [role="button"]');
    if (!button || !event.isTrusted) return;
    const inForm = !!button.form || !!button.closest?.('form');
    const defaultSubmit = button.tagName === 'BUTTON' && !button.getAttribute('type');
    const explicitSubmit = button.type === 'submit';
    const label = `${button.textContent || ''} ${button.getAttribute('aria-label') || ''} ${button.value || ''}`.trim();
    const loginAction = /sign.?in|log.?in|continue|next|register|create.?account|save|update|登录|登入|下一步|继续|註冊|注册|保存|更新/i.test(label);
    if ((inForm && (defaultSubmit || explicitSubmit)) || loginAction) void submitted(button, true);
  }, true);
  document.addEventListener('keydown', event => {
    if (event.key !== 'Enter' || !event.isTrusted || event.target?.tagName !== 'INPUT') return;
    clearTimeout(debounce);
    debounce = setTimeout(() => void submitted(event.target, true), 0);
  }, true);
})();
