// SPDX-License-Identifier: GPL-3.0-only
// No secret values or raw failures belong in the public cleanup receipt.
export async function cleanupResources({hasSession, logout, sessionRejected, clearClipboard, releaseLock}) {
  const receipt = {session:'not_created', clipboard:'cleanup_unverified', lock:'release_unverified'};
  try { receipt.clipboard = await clearClipboard(); } catch { /* Preserve uncertainty. */ }
  try { receipt.lock = await releaseLock(); } catch { /* Preserve uncertainty. */ }
  if (hasSession) {
    receipt.session = 'revocation_unverified';
    try {
      await logout();
      // Logout 200 alone is insufficient: upstream ignores a DeleteSession error.
      if (await sessionRejected()) receipt.session = 'revoked';
    } catch { /* Never claim revocation on a failed request. */ }
  }
  return receipt;
}
