// SPDX-License-Identifier: GPL-3.0-only
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { pathToFileURL } from 'node:url';
import { createClient } from './client.mjs';

export function createServer(client = createClient()) {
  const server = new McpServer({ name: 'Vault 2 local account lookup', version: '0.1.0' }, {
    instructions: 'This connector reads selected GoDaddy metadata from the local Vault 2 and describes its owner-assisted CUA private-fill helper. Use vault2_private_fill_info for the reviewed module. Bind that module to a fresh owned in-app Browser tab; passwords remain inside the helper and never belong in model-visible scripts, results, ordinary typing arguments or page evaluation. Do not read authentication field values back from the DOM. The helper is not an isolated native credential boundary. Stop at GoDaddy browser rejection, MFA or CAPTCHA; obtain action-time approval for Terms of Service; never retry an uncertain submission. Metadata lookup and private fill do not establish signed-in identity. No credential-return, clipboard, arbitrary URL, shell, role or grant tools are provided.',
  });
  const response = value => ({ content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value });
  server.registerTool('vault2_status', { description: 'Check the local Vault 2 engine and private browser integration separately. lookup_available does not mean private sign-in is ready.', inputSchema: {}, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } }, async () => response(await client.status()));
  server.registerTool('vault2_find_accounts', { description: 'Read only saved GoDaddy account names, usernames and approved origins. Use only for an owner-requested account lookup. Temporary owner sessions are revoked and checked before results are returned. Cannot sign in or return passwords.', inputSchema: { provider: z.literal('godaddy') }, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } }, async ({ provider }) => response(await client.findAccounts(provider)));
  server.registerTool('vault2_private_fill_info', { description: 'Describe the reviewed owner-assisted GoDaddy private-fill module for use inside the local CUA runtime with a fresh owned IAB tab. This tool does not read credentials or operate a browser. Provider rejection must be respected; it cannot be bypassed by this helper.', inputSchema: { provider: z.literal('godaddy') }, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } }, async () => response({ state: 'runtime_binding_required', provider: 'godaddy', module: new URL('./private-fill.mjs', import.meta.url).href, factory: 'bindPrivateGoDaddyTab', binding: ['browser=iab', 'actual owned tabId', 'actual current threadId'], accountSelection: 'registered GoDaddy alias in private configuration', termsConfirmationRequired: true, isolatedNativeBoundary: false, identityVerified: false }));
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  process.stdin.once('end', () => void server.close());
}
