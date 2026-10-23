// SPDX-License-Identifier: GPL-3.0-only
import { test, expect } from 'bun:test';
import { mkdtemp, mkdir, writeFile, chmod, symlink, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createClient, godaddyMetadata, privateJSON } from '../src/client.mjs';
import { createServer } from '../src/server.mjs';

const secret = 'SYNTHETIC_PASSWORD_MUST_NEVER_ESCAPE';
const record = { id: 'synthetic-id', name: 'GoDaddy test', login: { username: 'owner@example.invalid', password: secret, totp: secret, uris: [{ uri: 'https://sso.godaddy.com/login?private=never-return' }] }, notes: secret };

function fixture({ badOwner = false, badRecord = false, logoutFails = false } = {}) {
  let active = false;
  const requests = [];
  const cfg = { apiBase: 'http://127.0.0.1:14521/', vault: 'bitwarden-import', ownerInput: 'owner', manifest: 'manifest' };
  const readJSON = async key => key === 'owner' ? { email: 'owner@example.invalid', password: secret } : { records: [{ sourceID: record.id, metadataKey: 'BW_GODADDY_TEST_RECORD', usernameKey: 'BW_GODADDY_TEST_USERNAME', passwordKey: 'BW_GODADDY_TEST_PASSWORD' }, { sourceID: 'other', metadataKey: 'BW_OTHER_RECORD', usernameKey: 'BW_OTHER_USERNAME', passwordKey: 'BW_OTHER_PASSWORD' }] };
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
  const fetchImpl = async (input, options = {}) => {
    const url = new URL(input);
    requests.push({ path: url.pathname, key: url.searchParams.get('key') });
    if (url.pathname === '/v1/status') return json({ initialized: true });
    if (url.pathname === '/v1/auth/login') { active = true; return json({ token: secret }); }
    if (url.pathname === '/v1/auth/me') return active ? json({ email: badOwner ? 'wrong@example.invalid' : 'owner@example.invalid', role: 'owner' }) : json({}, 401);
    if (url.pathname === '/v1/auth/logout') { if (logoutFails) return json({ error: secret }, 500); active = false; return json({}); }
    if (url.pathname === '/v1/credentials') return json({ credentials: [{ key: url.searchParams.get('key'), value: JSON.stringify({ ...record, ...(badRecord ? { id: 'mismatched' } : {}) }) }] });
    throw new Error(secret);
  };
  return { client: createClient({ loadConfig: async () => cfg, readJSON, fetchImpl }), requests, active: () => active };
}

test('metadata strips passwords, query strings, identifiers, notes and TOTP', () => {
  const metadata = godaddyMetadata(record);
  expect(metadata).toEqual({ name: 'GoDaddy test', username: 'owner@example.invalid', origins: ['https://sso.godaddy.com'], privateSignInSupported: false });
  expect(JSON.stringify(metadata)).not.toContain(secret);
  expect(JSON.stringify(metadata)).not.toContain('synthetic-id');
  expect(JSON.stringify(metadata)).not.toContain('private=');
});

test('lookalike, insecure, credential-bearing and foreign origins are rejected', () => {
  for (const uri of ['https://sso.godaddy.com.evil.invalid', 'http://sso.godaddy.com', 'https://u:p@sso.godaddy.com', 'https://sso.godaddy.com:8443', 'https://example.invalid']) {
    expect(godaddyMetadata({ ...record, login: { ...record.login, uris: [{ uri }] } })).toBeNull();
  }
});

test('lookup reads only selected provider metadata and revokes its session', async () => {
  const f = fixture();
  const result = await f.client.findAccounts('godaddy');
  expect(result.state).toBe('accounts_ready');
  expect(result.cleanupVerified).toBe(true);
  expect(result.accounts).toHaveLength(1);
  expect(f.active()).toBe(false);
  expect(f.requests.filter(x => x.path === '/v1/credentials').map(x => x.key)).toEqual(['BW_GODADDY_TEST_RECORD']);
  expect(JSON.stringify(result)).not.toContain(secret);
  expect(result.privateSignInReady).toBe(false);
});

test('wrong owner and mismatched import record fail closed with session cleanup', async () => {
  for (const setting of [{ badOwner: true }, { badRecord: true }]) {
    const f = fixture(setting);
    const result = await f.client.findAccounts('godaddy');
    expect(result.state).toBe('lookup_failed');
    expect(result.accounts).toEqual([]);
    expect(f.active()).toBe(false);
    expect(JSON.stringify(result)).not.toContain(secret);
    if (setting.badOwner) expect(f.requests.some(x => x.path === '/v1/credentials')).toBe(false);
  }
});

test('failed logout withholds all metadata and unapproved providers read nothing', async () => {
  const f = fixture({ logoutFails: true });
  expect((await f.client.findAccounts('godaddy')).accounts).toEqual([]);
  const fresh = fixture();
  expect((await fresh.client.findAccounts('gmail')).state).toBe('unsupported_provider');
  expect(fresh.requests).toEqual([]);
});

test('private inputs reject readable files and symlinked ancestors', async () => {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'vault2-mcp-'));
  try {
    await chmod(root, 0o700);
    await mkdir(join(root, 'private'), { mode: 0o700 });
    const file = join(root, 'private', 'config.json');
    await writeFile(file, '{}', { mode: 0o600 });
    expect(await privateJSON(file)).toEqual({});
    await chmod(file, 0o644);
    await expect(privateJSON(file)).rejects.toThrow('private_input_invalid');
    await chmod(file, 0o600);
    await symlink(join(root, 'private'), join(root, 'alias'));
    await expect(privateJSON(join(root, 'alias', 'config.json'))).rejects.toThrow('private_input_invalid');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('MCP handshake exposes metadata tools only and reports the missing fill adapter', async () => {
  const f = fixture();
  const server = createServer(f.client);
  const client = new Client({ name: 'fixture-client', version: '1.0.0' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  await client.connect(b);
  try {
    const tools = await client.listTools();
    expect(tools.tools.map(t => t.name).sort()).toEqual(['vault2_find_accounts', 'vault2_private_fill_info', 'vault2_status']);
    const status = await client.callTool({ name: 'vault2_status', arguments: {} });
    expect(status.structuredContent.privateSignInReady).toBe(false);
    expect(status.structuredContent.browserAdapter).toBe('owner_assisted_cua');
    expect(status.structuredContent.privateFillBridgeAvailable).toBe(true);
    const accounts = await client.callTool({ name: 'vault2_find_accounts', arguments: { provider: 'godaddy' } });
    expect(JSON.stringify(accounts)).not.toContain(secret);
    expect(accounts.structuredContent.accounts).toHaveLength(1);
  } finally { await client.close(); await server.close(); }
});
