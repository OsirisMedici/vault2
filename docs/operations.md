# Vault 2 on Raven

This is the separately installed Infisical Agent Vault v0.40.2 instance and
Vault 2 branded frontend. The original custom Vault deployment and signed
Bitwarden installation remain separate. The GHL browser workflow has its own
acceptance; engine readiness does not establish website login.

## Daily use

Open `https://raven.tailf4bdfc.ts.net:9444/` while connected to Tailscale.
On Raven, these commands manage only the two Vault 2 services:

```sh
~/.local/bin/vault2 ready
~/.local/bin/vault2 start
~/.local/bin/vault2 restart
~/.local/bin/vault2 stop
~/.local/bin/vault2 backup
```

`ready` verifies the existing private state, protected unlock-input permissions,
engine health, installed frontend bytes, authenticated owner/vault access and
revocation of its temporary readiness session. It reports counts, not values.
An unavailable API or incorrect session does not become a ready result.

The two per-user LaunchAgents run at macOS login and restart failed processes.
They are `com.osiris.vault2.engine` and `com.osiris.vault2.web` under
`~/Library/LaunchAgents/`. `stop` unloads these jobs for the current login;
their files remain, so they run at the next login. No other job is changed.
An actual whole-Mac reboot/logout test remains an owner acceptance step.

The engine unlocks with the existing owner-only private input file. This is
automatic local unlock at login, protected by the macOS user and filesystem
permissions. It is not Touch ID, human approval on each action, or protection
from unrestricted programs running as the same macOS user. The signed
Bitwarden app and its Keychain enrollment are untouched. No password is put
in command arguments, LaunchAgent properties, environment variables or source.

Startup refuses missing/misbound state, a passwordless database, a missing
owner, unsafe private-file permissions, an invalid master input or a changed
engine binary. It checks these before invoking upstream, so this launcher
does not silently initialize a replacement vault. Restore a missing private
input through the owner's recovery procedure; do not initialize or reimport.

## Installed runtime

Private data and operational files are below
`~/.local/share/agent-vault-upstream-raven/` (owner-only directory).

- `state/`: existing database, encrypted CA key and upstream state. The
  existing `~/.agent-vault` symlink continues to point here.
- `service/bin/`: installed copies of the reviewed launch/recovery scripts.
- `service/releases/<branding-patch-sha>/`: immutable copy of the already
  built frontend. Runtime no longer depends on Vite, its development checkout
  or `node_modules`.
- `service/configuration.json`: build identity and frontend file digests.
- `service/logs/`: owner-only engine and frontend logs.

Engine API/UI binds `127.0.0.1:14321`; the upstream proxy binds
`127.0.0.1:14322`; the branded web server binds `127.0.0.1:14421`.
The web server serves built files and forwards only the existing API routes
to that engine. Authentication, credential encryption and service policy
remain upstream responsibilities. Request bodies and credentials are not
logged by the frontend server.

Existing private Tailscale Serve handlers are retained:
9443 points to 14321, and 9444 points to 14421. Other ports and mappings are
unchanged; no Funnel is enabled. Service availability requires Raven awake,
the macOS user logged in, Tailscale connected, and those services healthy.
Checking Raven does not establish another Mac's browser access.

## Recovery

`vault2 backup` takes a consistent SQLite online backup, includes the existing
encrypted CA material, import mapping, protected owner/unlock recovery inputs
and the local agent configuration when present. Browser/CLI sessions, PID
files, logs and the original plaintext export are excluded. The entire bundle
is encrypted and authenticated with AES-256-GCM using a new random key.
No recovery key or decrypted content is printed.

The command returns two paths: `backups/<timestamp>.vault2` and
`recovery-keys/<timestamp>.key`. Both are owner-only; the key is kept outside
the encrypted bundle. Keep an off-device copy of the bundle and protect a
separate copy of its key. Copies on Raven alone do not protect against losing
Raven. No cloud destination or sharing was configured, and old copies are
never deleted automatically. Take another backup after credential changes.

To verify a bundle, supply the printed paths and a **new** private destination:

```sh
~/.local/bin/vault2 verify-backup \
  --backup /absolute/private/path/snapshot.vault2 \
  --key-file /absolute/private/path/snapshot.key \
  --destination /absolute/private/path/new-restore-check
```

This authenticates the bundle, rejects altered ciphertext, restores only an
encrypted database copy, runs SQLite integrity checks, derives the upstream
Argon2id key, verifies master unlock and owner password, and decrypts all
imported fields in memory. It validates record IDs, required field presence
and counts against the preserved import mapping/receipt. Recovery inputs
are not extracted in plaintext. It never switches the live state symlink,
starts a second engine or contacts a provider.

OpenSSL's maintained [Argon2id implementation](https://docs.openssl.org/3.6/man7/EVP_KDF-ARGON2/)
and AES-GCM primitives are used through local bindings. This Raven setup
uses the existing Homebrew OpenSSL 3.6 library and Python; no cryptography
package or engine rebuild is installed by these scripts.

Passing this check establishes isolated **data** restoration and decryption.
It does not establish a running restored engine, browser login, off-device
recovery or a second-Mac restore. Before a real cutover, stop all credential
consumers, verify the bundle, preserve the old state, restore through an
explicitly reviewed operator procedure, then verify engine and website
identity. Do not overlay files on a running database or copy a bare SQLite
database while ignoring its WAL.

## Installation and source boundaries

From this independent repository, after building the branded frontend in `web/`:

```sh
python3 scripts/vault2/service.py install --candidate .
```

Installation refuses an existing release/command/LaunchAgent rather than
overwriting it. It requires the source checkout at this repository's current commit, copies the built frontend and scripts, and writes the two private
LaunchAgent definitions; it does not stop/start an existing runtime. Before
the first `vault2 start`, stop only the verified old Vault 2 processes during
a coordinated window. Updating an installation requires a separately reviewed
replacement of its owned files, followed by a restart/readiness check.

The agent `t3-raven` has instance role `no-access` and vault role `proxy` only
on the imported vault. Its token stays in an owner-only runtime file outside
source. The live proxy-role credential-reveal request was denied with 403.
There are no imported-vault service rules, so registration alone grants no
working website-login flow. Never elevate it to member/admin merely to make
password retrieval convenient. Review actual service needs separately.

Publish only source, branding patch, pin, license and operational instructions.
Keep runtime databases, recovery bundles/keys, owner/agent files, exports,
logs and browser evidence outside Git. Push an explicit branch and verify its
exact remote commit. Source publication is separate from deployment of the
original custom Vault or replacement of any installed desktop app.

## Recorded Raven verification, 23 October 2026

- Both login-managed services started, and a subsequent `vault2 restart` reached
  authenticated readiness in 1.687 seconds. This is local service restart time,
  not GHL login time. No whole-Mac reboot was performed.
- Private HTTPS owner authentication through the managed frontend succeeded;
  logout was verified by a subsequent 401. The Agents page rendered after
  reload, including the persisted active proxy agent.
- Isolated recovery passed authenticated bundle/tamper checks, SQLite integrity,
  master unlock, owner-password verification, all 755 imported encrypted fields,
  256 login records and four folders. The restored proxy grant was preserved.
  No restored engine or provider login was launched.
- The agent token remained accepted after restart, while credential reveal
  remained denied with 403. No imported-vault service rule was added.
- Three focused safety checks passed: recovery tamper/wrong-key rejection;
  private-file permission/symlink/overwrite rejection; and refusal to create or
  start a replacement instance when state is missing.
- The branding patch reproduced against the clean pinned original. Publication
  review found no private credential values or private-key/token patterns in
  the selected source files. Runtime and recovery files remain outside Git.
