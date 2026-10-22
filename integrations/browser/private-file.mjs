// SPDX-License-Identifier: GPL-3.0-only
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

const reasons = new Set([
  'invalid_config', 'private_file_unavailable', 'invalid_reference',
  'invalid_login', 'engine_unavailable', 'engine_timeout', 'capability_denied',
  'credential_missing', 'invalid_response', 'request_rejected', 'consume_failed',
]);

export function engineError(reasonCode) {
  const code = reasons.has(reasonCode) ? reasonCode : 'engine_unavailable';
  // No cause, private path, native message or response body belongs here.
  return Object.assign(new Error(code), { name: 'EngineError', reasonCode: code });
}

export async function readPrivateFile(filename, maxBytes = 16384) {
  let handle;
  let buffer;
  try {
    if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw 0;
    const parent = path.dirname(filename);
    const directory = await lstat(parent);
    const uid = process.getuid();
    if (!directory.isDirectory() || directory.uid !== uid ||
        (directory.mode & 0o777) !== 0o700 || await realpath(parent) !== parent) throw 0;
    handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o777) !== 0o600 ||
        stat.nlink !== 1 || stat.size === 0 || stat.size > maxBytes) throw 0;
    buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length <= maxBytes) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (!length || length > maxBytes) throw 0;
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length));
  } catch {
    throw engineError('private_file_unavailable');
  } finally {
    buffer?.fill(0);
    await handle?.close().catch(() => {});
  }
}

export async function loadEngineConfig(filename) {
  let value;
  try { value = JSON.parse(await readPrivateFile(filename)); }
  catch { throw engineError('invalid_config'); }
  if (!value || value.version !== 1 ||
      Object.keys(value).some(key => !['version', 'address', 'vaultName', 'tokenFile'].includes(key)) ||
      !['address', 'vaultName', 'tokenFile'].every(key => typeof value[key] === 'string')) {
    throw engineError('invalid_config');
  }
  return { address: value.address, vaultName: value.vaultName, tokenFile: value.tokenFile };
}
