// SPDX-License-Identifier: GPL-3.0-only
export const ORIGIN = 'https://app.gohighlevel.com';
export const LOGIN_URL = ORIGIN + '/';
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const codes = new Set(['selection_not_configured', 'selection_invalid', 'binding_changed',
  'origin_mismatch', 'form_unavailable', 'verification_required', 'credential_unavailable',
  'engine_unavailable', 'engine_rate_limited', 'browser_unavailable', 'session_invalid',
  'operation_busy', 'operation_failed', 'already_attempted', 'lock_unavailable',
  'identity_unverified', 'cleanup_unverified']);
export function fail(code) { throw Object.assign(new Error(code), {code}); }
// Never forward Playwright errors/call logs, engine bodies, paths or causes.
export function reason(error) { return codes.has(error?.code) ? error.code : 'operation_failed'; }
export function validateSelection(c) {
  if (!c || c.version !== 1 || c.origin !== ORIGIN || !UUID.test(c.accountId) ||
      typeof c.username !== 'string' || c.username.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.username)) fail('selection_not_configured');
  return Object.freeze({accountId:c.accountId, username:c.username, origin:ORIGIN});
}
