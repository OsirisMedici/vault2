// SPDX-License-Identifier: GPL-3.0-only
import { lstat, readFile } from 'node:fs/promises';
import { dirname, resolve, parse } from 'node:path';
import { homedir, userInfo } from 'node:os';

const origins = new Set(['https://sso.godaddy.com', 'https://www.godaddy.com', 'https://account.godaddy.com']);
const text = (value, limit = 300) => typeof value === 'string' && value.length <= limit && !/[\x00-\x1f\x7f]/.test(value);

export async function privateJSON(path) {
  const file = resolve(path);
  let current = file;
  while (true) {
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error('private_input_invalid');
    if (current === file && (!info.isFile() || info.size > 2_000_000)) throw new Error('private_input_invalid');
    if (current === file || current === dirname(file)) {
      if (info.uid !== userInfo().uid || (info.mode & 0o077) !== 0) throw new Error('private_input_invalid');
    }
    if (current === parse(current).root) break;
    current = dirname(current);
  }
  return JSON.parse(await readFile(file, 'utf8'));
}

// Only reconstruct approved metadata. Source records include secrets and must
// never be serialized, logged, returned as errors, or passed to browser tools.
export function godaddyMetadata(record) {
  if (!record || !text(record.name) || !text(record.login?.username) || !record.login.username) return null;
  const matches = new Set();
  for (const entry of record.login.uris ?? []) {
    try {
      const url = new URL(entry.uri);
      if (!url.username && !url.password && origins.has(url.origin)) matches.add(url.origin);
    } catch { /* Invalid saved URLs are not eligible for sign-in. */ }
  }
  if (!matches.size) return null;
  return { name: record.name, username: record.login.username, origins: [...matches], privateSignInSupported: false };
}

export function createClient({ loadConfig, fetchImpl = fetch, readJSON = privateJSON } = {}) {
  const config = loadConfig ?? (() => readJSON(process.env.VAULT2_CLIENT_CONFIG ?? resolve(homedir(), '.config/vault2/codex-client.json')));
  async function settings() {
    const value = await config();
    const url = new URL(value.apiBase);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.pathname !== '/' || url.search || url.hash || value.vault !== 'bitwarden-import') throw new Error('configuration_invalid');
    return value;
  }
  async function api(cfg, path, { body, token } = {}) {
    const response = await fetchImpl(new URL(path, cfg.apiBase), {
      method: body === undefined ? 'GET' : 'POST', redirect: 'error',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error('engine_unavailable');
    const raw = await response.text();
    if (raw.length > 2_000_000) throw new Error('engine_response_invalid');
    return JSON.parse(raw);
  }
  async function ownerSession(cfg, action) {
    const owner = await readJSON(cfg.ownerInput);
    const login = await api(cfg, '/v1/auth/login', { body: { ...owner, device_label: 'Vault2 Codex selected metadata lookup' } });
    if (typeof login.token !== 'string' || !login.token) throw new Error('engine_response_invalid');
    const token = login.token;
    try {
      const me = await api(cfg, '/v1/auth/me', { token });
      if (me.email !== owner.email || me.role !== 'owner') throw new Error('owner_identity_mismatch');
      return await action(token);
    } finally {
      // Failed revocation is a failed operation. Never return partial results.
      await api(cfg, '/v1/auth/logout', { body: {}, token });
      const check = await fetchImpl(new URL('/v1/auth/me', cfg.apiBase), {
        headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(10_000),
      });
      if (check.status !== 401) throw new Error('cleanup_unverified');
    }
  }
  return {
    async status() {
      try {
        const cfg = await settings();
        const result = await api(cfg, '/v1/status');
        let providerState = 'not_tested';
        if (cfg.privateFillReceipt) {
          try {
            const receipt = await readJSON(cfg.privateFillReceipt);
            if (['browser_rejected', 'verification_required', 'signed_in', 'not_tested'].includes(receipt.providerState)) providerState = receipt.providerState;
          } catch { /* Missing evidence never establishes provider readiness. */ }
        }
        return { state: result.initialized ? 'lookup_available' : 'engine_not_initialized', privateFillBridgeAvailable: true, privateSignInReady: false, browserAdapter: 'owner_assisted_cua', providerState, supportedLookup: ['godaddy'] };
      } catch { return { state: 'unavailable', privateSignInReady: false }; }
    },
    async findAccounts(provider) {
      if (provider !== 'godaddy') return { state: 'unsupported_provider', accounts: [] };
      try {
        const cfg = await settings();
        const manifest = await readJSON(cfg.manifest);
        const candidates = manifest.records.filter(row => typeof row.metadataKey === 'string' && /^BW_[A-Z0-9_]{1,200}$/.test(row.metadataKey) && row.metadataKey.includes('GODADDY') && row.usernameKey && row.passwordKey).slice(0, 20);
        const accounts = await ownerSession(cfg, async token => {
          const matches = [];
          for (const row of candidates) {
            const query = new URLSearchParams({ vault: cfg.vault, reveal: 'true', key: row.metadataKey });
            const response = await api(cfg, '/v1/credentials?' + query, { token });
            if (response.credentials?.length !== 1 || response.credentials[0].key !== row.metadataKey) throw new Error('engine_response_invalid');
            const record = JSON.parse(response.credentials[0].value);
            if (record.id !== row.sourceID) throw new Error('record_binding_mismatch');
            const account = godaddyMetadata(record);
            if (account) matches.push(account);
          }
          return matches;
        });
        return { state: 'accounts_ready', accounts, selectionRequired: accounts.length > 1, privateSignInReady: false, cleanupVerified: true };
      } catch { return { state: 'lookup_failed', accounts: [], privateSignInReady: false }; }
    },
  };
}
