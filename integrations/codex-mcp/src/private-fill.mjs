// SPDX-License-Identifier: GPL-3.0-only
import { resolve, dirname } from 'node:path';
import { homedir } from 'node:os';
import { mkdir, rmdir } from 'node:fs/promises';
import { privateJSON } from './client.mjs';
import { bindGoDaddyDriver } from './godaddy-driver.mjs';

const ORIGIN = 'https://sso.godaddy.com';
const reasons = new Set(['invalid_binding', 'origin_changed', 'form_changed', 'verification_required', 'browser_rejected', 'credentials_rejected', 'selection_mismatch', 'private_input_invalid', 'engine_unavailable', 'cleanup_unverified', 'busy', 'expired', 'already_used', 'field_validation_failed', 'terms_approval_required']);

// This helper runs inside the local CUA JavaScript runtime. Secrets are delivered
// directly to supported Browser controls there, never returned as tool results
// or inserted into the model-visible invocation. This is owner-assisted,
// same-user custody; it is not a native isolated password manager.
export function createPrivateFillBridge({ driver, loadConfig, readJSON = privateJSON, fetchImpl = fetch, acquireLock, releaseLock } = {}) {
  const config = loadConfig ?? (() => readJSON(resolve(homedir(), '.config/vault2/codex-client.json')));
  const timings = { lookupMs: 0, probeMs: 0, fillMs: 0, cleanupMs: 0, submitMs: 0 };
  let phase = 'idle', expected, username, expires, lock, touched = false, operationStage = 'idle';
  const timed = async (key, operation) => { const start = performance.now(); try { return await operation(); } finally { timings[key] += performance.now() - start; } };
  const result = (state, extra = {}) => ({ state, identityVerified: false, ...extra, timings: { ...timings } });
  async function guard() {
    let current;
    try { current = await driver.inspect(); } catch { throw new Error('form_changed'); }
    if (current.tabId !== driver.binding.tabId) throw new Error('invalid_binding');
    if (current.origin !== ORIGIN || new URL(current.url).origin !== ORIGIN || (expected && current.url !== expected.url)) throw new Error('origin_changed');
    if (current.providerBlocked) throw new Error('browser_rejected');
    if (current.challenge) throw new Error('verification_required');
    if (current.rejected) throw new Error('credentials_rejected');
    if (!current.form) throw new Error('form_changed');
    return current;
  }
  async function unlock() {
    if (!lock) return true;
    try {
      if (releaseLock) await releaseLock(lock); else await rmdir(lock);
      lock = undefined;
      return true;
    } catch { return false; }
  }
  async function clear() { try { return await driver.clear(expected?.url) !== false; } catch { return false; } }
  async function api(cfg, path, body, token) {
    const response = await fetchImpl(new URL(path, cfg.apiBase), { method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (!response.ok) throw new Error('engine_unavailable');
    const raw = await response.text();
    if (raw.length > 2_000_000) throw new Error('engine_unavailable');
    return JSON.parse(raw);
  }
  async function selectedCredentials(cfg, action) {
    const endpoint = new URL(cfg.apiBase);
    if (endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' || !endpoint.port || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== '/' || cfg.vault !== 'bitwarden-import') throw new Error('private_input_invalid');
    const selected = cfg.registeredGoDaddy;
    if (!selected || !/^godaddy-[A-Za-z0-9_-]{1,80}$/.test(selected.alias) || selected.origin !== ORIGIN || typeof selected.username !== 'string' || !selected.sourceID) throw new Error('selection_mismatch');
    const manifest = await readJSON(cfg.manifest);
    const matches = manifest.records.filter(r => r.sourceID === selected.sourceID);
    if (matches.length !== 1 || !matches[0].usernameKey || !matches[0].passwordKey) throw new Error('selection_mismatch');
    const row = matches[0];
    const owner = await readJSON(cfg.ownerInput);
    const login = await api(cfg, '/v1/auth/login', { ...owner, device_label: 'Vault2 owner-assisted GoDaddy private fill' });
    if (typeof login.token !== 'string' || !login.token) throw new Error('engine_unavailable');
    const token = login.token;
    let secret;
    try {
      const me = await api(cfg, '/v1/auth/me', undefined, token);
      if (me.email !== owner.email || me.role !== 'owner') throw new Error('selection_mismatch');
      async function field(key) {
        if (!/^BW_[A-Z0-9_]{1,200}$/.test(key)) throw new Error('selection_mismatch');
        const data = await api(cfg, '/v1/credentials?' + new URLSearchParams({ vault: cfg.vault, reveal: 'true', key }), undefined, token);
        if (data.credentials?.length !== 1 || data.credentials[0].key !== key || typeof data.credentials[0].value !== 'string') throw new Error('selection_mismatch');
        return data.credentials[0].value;
      }
      await timed('lookupMs', async () => {
        const metadata = JSON.parse(await field(row.metadataKey));
        const allowed = (metadata.login?.uris ?? []).some(entry => { try { const u = new URL(entry.uri); return !u.username && !u.password && u.origin === ORIGIN; } catch { return false; } });
        if (metadata.id !== selected.sourceID || !allowed) throw new Error('selection_mismatch');
        username = await field(row.usernameKey);
        if (username !== selected.username) throw new Error('selection_mismatch');
        await guard();
        secret = await field(row.passwordKey);
        if (!secret) throw new Error('selection_mismatch');
      });
      return await action(secret);
    } finally {
      secret = undefined;
      await timed('cleanupMs', async () => {
        try {
          await api(cfg, '/v1/auth/logout', {}, token);
          const check = await fetchImpl(new URL('/v1/auth/me', cfg.apiBase), { headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(10_000) });
          if (check.status !== 401) throw new Error('cleanup_unverified');
        } catch { throw new Error('cleanup_unverified'); }
      });
    }
  }
  return {
    async prepare() {
      if (phase !== 'idle') return result('denied', { reasonCode: 'already_used' });
      phase = 'preparing';
      try {
        operationStage = 'browser_guard'; expected = await guard();
        operationStage = 'private_configuration';
        const cfg = await config();
        operationStage = 'lock';
        if (acquireLock) lock = await acquireLock();
        else { lock = resolve(dirname(cfg.ownerInput), 'godaddy-private-fill.lock'); try { await mkdir(lock, { mode: 0o700 }); } catch { lock = undefined; throw new Error('busy'); } }
        operationStage = 'nonsecret_probe'; touched = true;
        const probe = await timed('probeMs', () => driver.probe());
        if (!probe) throw new Error('field_validation_failed');
        await guard();
        operationStage = 'selected_account';
        await selectedCredentials(cfg, async password => timed('fillMs', async () => {
          operationStage = 'private_fill';
          await guard(); await driver.fillUsername(username);
          await guard(); await driver.fillPassword(password);
          await guard();
          if (!await driver.preparedFieldsReady()) throw new Error('field_validation_failed');
        }));
        await guard();
        phase = 'prepared'; expires = Date.now() + 300_000;
        return result(expected.termsRequired ? 'prepared_awaiting_terms_approval' : 'prepared', { ownerSessionRevoked: true, termsLink: expected.termsLink ?? null, termsRequired: expected.termsRequired === true });
      } catch (error) {
        const fieldsCleared = touched ? await clear() : false;
        const lockReleased = await unlock(); phase = 'closed';
        const reasonCode = reasons.has(error?.message) ? error.message : 'private_fill_failed';
        const failureCode = ['EACCES', 'EPERM', 'ENOENT', 'ENOTDIR', 'EEXIST'].includes(error?.code) ? error.code : undefined;
        return result(reasonCode === 'verification_required' ? 'verification_required' : reasonCode === 'browser_rejected' ? 'provider_blocked' : 'denied', { reasonCode, failureStage: operationStage, ...(failureCode ? { failureCode } : {}), fieldsCleared, lockReleased });
      }
    },
    async submit({ termsApproved = false } = {}) {
      if (phase !== 'prepared') return result('denied', { reasonCode: 'already_used' });
      if (expected.termsRequired && !termsApproved) return result('needs_terms_approval', { termsLink: expected.termsLink });
      try {
        if (Date.now() > expires) throw new Error('expired');
        const current = await guard();
        if (current.termsRequired !== expected.termsRequired || current.termsLink !== expected.termsLink) throw new Error('form_changed');
        if (!await driver.preparedFieldsReady()) throw new Error('field_validation_failed');
        // Consume before dispatch. Any uncertain result is never retried.
        phase = 'submitted';
        await timed('submitMs', () => driver.submit());
        const lockReleased = await unlock();
        return result('submitted', { ownerSessionRevoked: true, lockReleased });
      } catch (error) {
        const uncertain = phase === 'submitted';
        if (!uncertain) await clear();
        phase = 'closed';
        const lockReleased = await unlock();
        return result(uncertain ? 'submission_uncertain' : 'denied', { reasonCode: reasons.has(error?.message) ? error.message : 'browser_action_failed', lockReleased });
      }
    },
    async cancel() {
      const fieldsCleared = phase === 'prepared' || phase === 'preparing' ? await clear() : false;
      const lockReleased = await unlock(); phase = 'closed'; username = undefined;
      return result('cancelled', { fieldsCleared, lockReleased });
    },
  };
}

export function bindPrivateGoDaddyTab(tab, binding) {
  return createPrivateFillBridge({ driver: bindGoDaddyDriver(tab, binding) });
}
