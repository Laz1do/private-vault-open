/* Runs in Chrome's isolated world. No page-created script can call the native bridge. */
(() => {
  if (globalThis.PrivateVaultForms) return;
  const attr = (input, name) => String(input.getAttribute?.(name) || '');
  const autocomplete = input => attr(input, 'autocomplete').toLowerCase().split(/\s+/);
  const hint = input => `${attr(input, 'name')} ${attr(input, 'id')} ${attr(input, 'placeholder')} ${attr(input, 'aria-label')}`.toLowerCase();
  const type = input => String(input.type || 'text').toLowerCase();
  const otp = input => autocomplete(input).includes('one-time-code') || /\botp\b|one.?time|verification|验证码|驗證碼|auth.?code/.test(hint(input));
  function visible(input) {
    if (!input || input.disabled || input.readOnly || type(input) === 'hidden' || otp(input)) return false;
    if (input.getAttribute?.('aria-hidden') === 'true' || input.hidden) return false;
    if (typeof input.getClientRects === 'function' && !input.getClientRects().length) return false;
    const style = typeof getComputedStyle === 'function' ? getComputedStyle(input) : null;
    return !style || (style.visibility !== 'hidden' && style.display !== 'none');
  }
  function allInputs(scope) { return [...scope.querySelectorAll('input')].filter(visible); }
  const isPassword = input => type(input) === 'password'
    || autocomplete(input).some(word => ['current-password', 'new-password'].includes(word));
  function usernameInput(inputs, allowUnlabelled = false) {
    const candidates = inputs.filter(input => !isPassword(input) && ['text', 'email', 'tel'].includes(type(input)) && !otp(input));
    return candidates.find(input => autocomplete(input).includes('username'))
      || candidates.find(input => type(input) === 'email' || autocomplete(input).includes('email'))
      || candidates.find(input => /user|email|login|identifier|account|账号|帐号|郵箱|邮箱/.test(hint(input)))
      || (allowUnlabelled && candidates.length === 1 ? candidates[0] : null);
  }
  function fields(scope) {
    const inputs = allInputs(scope);
    const passwords = inputs.filter(isPassword);
    const nonNew = passwords.filter(input => !autocomplete(input).includes('new-password'));
    return { username: usernameInput(inputs, passwords.length > 0), passwords,
      current: passwords.find(input => autocomplete(input).includes('current-password')) || (nonNew.length === 1 ? nonNew[0] : null),
      newPasswords: passwords.filter(input => autocomplete(input).includes('new-password')) };
  }
  function candidate(scope, fallbackUsername = '') {
    const found = fields(scope);
    if (!found.passwords.length) return null;
    let chosen, kind;
    if (found.newPasswords.length) {
      chosen = found.newPasswords.find(input => String(input.value || ''));
      kind = found.current && !found.newPasswords.includes(found.current) ? 'change' : 'register';
      const values = found.newPasswords.map(input => String(input.value || '')).filter(Boolean);
      if (new Set(values).size > 1) return null;
    } else if (found.passwords.length >= 2) {
      // Unlabelled change forms often contain current / new / confirmation, in that order.
      const values = found.passwords.map(input => String(input.value || ''));
      if (values.length >= 3 && values.at(-1) === values.at(-2) && values.at(-1)) {
        chosen = found.passwords.at(-1); kind = 'change';
      } else if (values.length === 2 && values[0] && values[0] === values[1]) {
        chosen = found.passwords[0]; kind = 'register';
      } else return null;
    } else { chosen = found.passwords[0]; kind = 'login'; }
    const password = String(chosen?.value || '');
    const username = String(found.username?.value || fallbackUsername || '');
    if (!password || password.length > 4096 || username.length > 1000) return null;
    return { username, password, kind };
  }
  function scopeFor(target, document) {
    return target?.form || target?.closest?.('form') || document;
  }
  function setValue(input, value) {
    const prototype = Object.getPrototypeOf(input);
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set
      || Object.getOwnPropertyDescriptor(globalThis.HTMLInputElement?.prototype || {}, 'value')?.set;
    if (setter) setter.call(input, value); else input.value = value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }
  function fill(document, credential, expectedOrigin) {
    if (location.protocol !== 'https:' || location.origin !== expectedOrigin || window.top !== window.self)
      return { filled: false, reason: '网站页面已经变化。' };
    const scopes = [...document.querySelectorAll('form')];
    if (!scopes.length) scopes.push(document);
    const found = scopes.map(scope => ({ scope, ...fields(scope) }));
    // A login form takes precedence. Never fill a new-password field automatically.
    const chosen = found.find(group => group.current && !group.newPasswords.includes(group.current))
      || found.find(group => group.username && !group.passwords.length);
    if (!chosen) return { filled: false, reason: '没有找到可填写的登录字段。注册或改密页请自行输入。' };
    let count = 0;
    if (chosen.username && credential.username) { setValue(chosen.username, credential.username); count++; }
    if (chosen.current && credential.password) { setValue(chosen.current, credential.password); count++; }
    if (count) (chosen.current || chosen.username)?.focus?.();
    return { filled: count > 0, fields: count, usernameOnly: !chosen.current,
      reason: count ? '' : '当前页面没有可填写的账号或密码。' };
  }
  globalThis.PrivateVaultForms = Object.freeze({ candidate, fields, scopeFor, fill, visible, usernameInput });
})();
