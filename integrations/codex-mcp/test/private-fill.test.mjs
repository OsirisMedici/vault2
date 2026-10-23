// SPDX-License-Identifier: GPL-3.0-only
import { test, expect } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { createPrivateFillBridge } from '../src/private-fill.mjs';

const SECRET = 'SYNTHETIC_PRIVATE_VALUE_NEVER_IN_RESULTS';
function fixture({ origin = 'https://sso.godaddy.com', challenge = false, providerBlocked = false, throwFill = false, throwSubmit = false, ownerWrong = false, sourceWrong = false, cleanupFails = false, busy = false, navigateAfterUsername = false } = {}) {
  const events = [];
  let active = false, password = '', username = '', locked = false, currentOrigin = origin;
  const cfg = { apiBase: 'http://127.0.0.1:14521/', vault: 'bitwarden-import', ownerInput: 'owner', manifest: 'manifest', registeredGoDaddy: { alias: 'godaddy-test-account', sourceID: 'source-id', username: 'owner@example.invalid', origin: 'https://sso.godaddy.com' } };
  const driver = {
    binding: { tabId: 'owned-tab' },
    inspect: async () => ({ origin: currentOrigin, url: currentOrigin + '/', tabId: 'owned-tab', form: true, challenge, providerBlocked, rejected: false, termsRequired: true, termsLink: 'https://www.godaddy.com/legal/agreements/universal-terms-of-service-agreement' }),
    probe: async () => { events.push('probe'); return true; },
    fillUsername: async value => { events.push('fill_username'); username = value; if (navigateAfterUsername) currentOrigin = 'https://evil.invalid'; },
    fillPassword: async value => { events.push('fill_password'); if (throwFill) throw new Error('Browser echoed ' + value); password = value; },
    preparedFieldsReady: async () => username === 'owner@example.invalid' && password === SECRET,
    submit: async () => { events.push('submit'); if (throwSubmit) throw new Error(SECRET); },
    clear: async () => { events.push('clear'); password = ''; username = ''; return true; },
  };
  const readJSON = async path => path === 'owner' ? { email: 'owner@example.invalid', password: 'synthetic-owner-password' } : { records: [{ sourceID: sourceWrong ? 'other' : 'source-id', metadataKey: 'BW_GODADDY_RECORD', usernameKey: 'BW_GODADDY_USERNAME', passwordKey: 'BW_GODADDY_PASSWORD' }] };
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
  const fetchImpl = async (input) => {
    const url = new URL(input); events.push(url.pathname);
    if (url.pathname === '/v1/auth/login') { active = true; return json({ token: 'synthetic-owner-session' }); }
    if (url.pathname === '/v1/auth/me') return active ? json({ email: ownerWrong ? 'wrong@example.invalid' : 'owner@example.invalid', role: 'owner' }) : json({}, 401);
    if (url.pathname === '/v1/auth/logout') { if (cleanupFails) return json({}, 500); active = false; return json({}); }
    if (url.pathname === '/v1/credentials') {
      const key = url.searchParams.get('key');
      if (key === 'BW_GODADDY_PASSWORD') events.push('read_password');
      const value = key.endsWith('_RECORD') ? JSON.stringify({ id: 'source-id', login: { uris: [{ uri: 'https://sso.godaddy.com/' }] } }) : key.endsWith('_USERNAME') ? 'owner@example.invalid' : SECRET;
      return json({ credentials: [{ key, value }] });
    }
    throw new Error(SECRET);
  };
  const acquireLock = async () => { if (busy) throw new Error('busy'); locked = true; return 'synthetic-lock'; };
  const releaseLock = async () => { locked = false; };
  const bridge = createPrivateFillBridge({ driver, readJSON, fetchImpl, loadConfig: async () => cfg, acquireLock, releaseLock });
  return { bridge, events, password: () => password, active: () => active, locked: () => locked };
}

test('private prepare probes before reading credentials and returns no secret', async () => {
  const f = fixture();
  const result = await f.bridge.prepare();
  expect(result.state).toBe('prepared_awaiting_terms_approval');
  expect(result.ownerSessionRevoked).toBe(true);
  expect(JSON.stringify(result)).not.toContain(SECRET);
  expect(f.password()).toBe(SECRET);
  expect(f.active()).toBe(false);
  expect(f.events.indexOf('probe')).toBeLessThan(f.events.indexOf('read_password'));
  expect((await f.bridge.submit()).state).toBe('needs_terms_approval');
  expect(f.events).not.toContain('submit');
  expect((await f.bridge.cancel()).fieldsCleared).toBe(true);
  expect(f.password()).toBe('');
  expect(f.locked()).toBe(false);
});

test('approved submission is dispatched once; reuse is denied', async () => {
  const f = fixture();
  await f.bridge.prepare();
  const submitted = await f.bridge.submit({ termsApproved: true });
  expect(submitted.state).toBe('submitted');
  expect(submitted.identityVerified).toBe(false);
  expect(f.locked()).toBe(false);
  expect((await f.bridge.submit({ termsApproved: true })).reasonCode).toBe('already_used');
  expect(f.events.filter(e => e === 'submit')).toHaveLength(1);
});

test('wrong origins and human challenges read no vault credentials', async () => {
  for (const options of [{ origin: 'https://sso.godaddy.com.evil.invalid' }, { challenge: true }, { busy: true }]) {
    const f = fixture(options);
    const result = await f.bridge.prepare();
    expect(['denied', 'verification_required']).toContain(result.state);
    expect(f.events).not.toContain('/v1/auth/login');
    expect(f.events).not.toContain('fill_password');
    expect(f.events).not.toContain('clear');
  }
});

test('wrong owner/source binding never fills a password', async () => {
  for (const options of [{ ownerWrong: true }, { sourceWrong: true }]) {
    const f = fixture(options);
    const result = await f.bridge.prepare();
    expect(result.state).toBe('denied');
    expect(f.events).not.toContain('fill_password');
    expect(f.active()).toBe(false);
    expect(f.locked()).toBe(false);
  }
});

test('navigation between username and password blocks password delivery', async () => {
  const f = fixture({ navigateAfterUsername: true });
  const result = await f.bridge.prepare();
  expect(result.reasonCode).toBe('origin_changed');
  expect(f.events).not.toContain('fill_password');
  expect(f.active()).toBe(false);
});

test('browser exceptions containing a password are sanitized and fields cleared', async () => {
  const f = fixture({ throwFill: true });
  const result = await f.bridge.prepare();
  expect(result.state).toBe('denied');
  expect(JSON.stringify(result)).not.toContain(SECRET);
  expect(result.fieldsCleared).toBe(true);
  expect(f.active()).toBe(false);
  expect(f.locked()).toBe(false);
});

test('uncertain submission is never repeated and raw browser errors do not escape', async () => {
  const f = fixture({ throwSubmit: true });
  await f.bridge.prepare();
  const result = await f.bridge.submit({ termsApproved: true });
  expect(result.state).toBe('submission_uncertain');
  expect(JSON.stringify(result)).not.toContain(SECRET);
  expect((await f.bridge.submit({ termsApproved: true })).reasonCode).toBe('already_used');
  expect(f.events.filter(e => e === 'submit')).toHaveLength(1);
});

test('failed session cleanup denies preparation and clears provider fields', async () => {
  const f = fixture({ cleanupFails: true });
  const result = await f.bridge.prepare();
  expect(result.state).toBe('denied');
  expect(result.fieldsCleared).toBe(true);
  expect(JSON.stringify(result)).not.toContain(SECRET);
  expect(f.locked()).toBe(false);
});

test('GoDaddy browser rejection stops before vault or field access', async () => {
  const f = fixture({ providerBlocked: true });
  const result = await f.bridge.prepare();
  expect(result.state).toBe('provider_blocked');
  expect(result.reasonCode).toBe('browser_rejected');
  expect(f.events).toEqual([]);
});

test('the browser driver does not read protected authentication field values', async () => {
  const source = await readFile(new URL('../src/godaddy-driver.mjs', import.meta.url), 'utf8');
  expect(source).not.toMatch(/\.value\b|inputValue\(|getAttribute\(['"]value['"]/);
  expect(source).not.toMatch(/\.clipboard\b|\bpbcopy\b|\bpbpaste\b/);
});
