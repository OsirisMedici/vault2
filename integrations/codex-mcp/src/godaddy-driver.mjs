// SPDX-License-Identifier: GPL-3.0-only
const ORIGIN = 'https://sso.godaddy.com';

// The caller supplies a fresh tab created by cua.createBrowserTab('iab', ...).
// Use supported, tab-scoped Browser APIs only. No clipboard, native app access,
// browser storage, cookies, protocol debugging or hidden transport is used.
export function bindGoDaddyDriver(tab, binding) {
  if (!tab || tab.id !== binding.tabId || binding.browser !== 'iab' || !binding.threadId) throw new Error('invalid_binding');
  let usernameAcknowledged = false, passwordAcknowledged = false;
  return {
    binding: { ...binding },
    async inspect() {
      const url = await tab.url();
      const state = await tab.playwright.evaluate(() => {
        const visible = e => !!e && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden';
        const text = document.body?.innerText ?? '';
        const challenges = [...document.querySelectorAll('iframe')].filter(visible).some(e => /challenge|captcha/i.test(e.title));
        const challenge = challenges || /verify (you are|you're) human|enter (the |your )?(verification|security) code|two.step verification|check your (email|phone)|account recovery/i.test(text);
        const rejected = /incorrect (username|password)|invalid (username|password|credentials)|couldn.t sign you in|password (is )?incorrect/i.test(text);
        const users = [...document.querySelectorAll('input#username')].filter(visible);
        const passwords = [...document.querySelectorAll('input#password')].filter(visible);
        const buttons = [...document.querySelectorAll('button#submitBtn')].filter(visible);
        const u = users[0], p = passwords[0], b = buttons[0];
        const form = users.length === 1 && passwords.length === 1 && buttons.length === 1 && u.type === 'text' && p.type === 'password' && !u.disabled && !p.disabled && !u.readOnly && !p.readOnly && u.form?.id === 'login-form' && p.form === u.form && b.form === u.form && b.type === 'button' && b.textContent.trim().toLowerCase() === 'sign in';
        const terms = /By clicking[\s\S]{0,180}agree to[\s\S]{0,100}Terms of Service/i.test(text);
        const termsLink = [...document.querySelectorAll('a')].find(e => e.textContent.trim() === 'Terms of Service')?.href ?? null;
        const providerBlocked = /your browser is a bit unusual/i.test(text);
        return { origin: location.origin, form, challenge, rejected, providerBlocked, termsRequired: terms, termsLink };
      });
      return { ...state, url, tabId: tab.id };
    },
    async fillUsername(value) { await tab.playwright.locator('input#username').fill(value, { timeoutMs: 4000 }); usernameAcknowledged = true; },
    async fillPassword(value) { await tab.playwright.locator('input#password').fill(value, { timeoutMs: 4000 }); passwordAcknowledged = true; },
    async probe() {
      await tab.playwright.locator('input#username').fill('vault2-bridge-check@example.invalid', { timeoutMs: 4000 });
      const ok = await tab.playwright.evaluate(() => {
        const input = document.querySelector('input#username');
        return location.origin === 'https://sso.godaddy.com' && input?.type === 'text' && !input.disabled && !input.readOnly && document.activeElement === input;
      });
      await tab.playwright.locator('input#username').fill('', { timeoutMs: 4000 });
      return ok;
    },
    async preparedFieldsReady() {
      // The browser deliberately redacts authentication field values. Respect
      // that protection: use acknowledged fill operations and current form
      // structure checks, never read back authentication field values.
      if (!usernameAcknowledged || !passwordAcknowledged) return false;
      return tab.playwright.evaluate(() => {
        const u = document.querySelector('input#username'), p = document.querySelector('input#password');
        return location.origin === 'https://sso.godaddy.com' && u?.type === 'text' && p?.type === 'password' && !u.disabled && !p.disabled && !u.readOnly && !p.readOnly && u.form?.id === 'login-form' && u.form === p.form;
      });
    },
    async submit() { await tab.playwright.locator('button#submitBtn').click({ timeoutMs: 4000 }); },
    async clear(expectedURL) {
      const currentURL = await tab.url();
      if (new URL(currentURL).origin === ORIGIN && (!expectedURL || currentURL === expectedURL)) {
        await tab.playwright.locator('input#password').fill('', { timeoutMs: 2000 });
        await tab.playwright.locator('input#username').fill('', { timeoutMs: 2000 });
        usernameAcknowledged = false; passwordAcknowledged = false;
        return true;
      }
      return false;
    },
  };
}
