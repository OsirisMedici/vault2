# Native Codex private-fill adapter

`integrations/browser/native-codex/server.mjs` is a local stdio MCP server for
Codex. It owns a separate Chrome process with a new owner-only temporary profile
for each session. It does not extend Codex's in-app browser or attach to existing
IAB, T3, personal Chrome, CDP endpoints or browser profiles. It does not copy
cookies, tokens, browser authorization or storage state.

## Installation

Requirements: Bun 1.4.4 or compatible, and installed Google Chrome. Dependencies
are isolated from the upstream web app and pinned in the adapter's `bun.lock`.
No browser download, Vault service install/restart, grant change or agent role
change is required. Chrome's sandbox remains enabled.

From the repository root:

```sh
cd integrations/browser/native-codex
~/.bun/bin/bun install --frozen-lockfile --ignore-scripts
```

Register with the native Codex CLI using absolute paths for this checkout:

```sh
codex mcp add vault2-native -- \
  /Users/pranshisharma/.bun/bin/bun \
  '/Users/pranshisharma/Desktop/Code Project/Vault2/integrations/browser/native-codex/server.mjs'
codex mcp get vault2-native --json
```

This registers an on-demand stdio command; it does not install a daemon or
change tool approval policy. Keep other MCP entries unchanged. A running chat
may retain its old tool catalog. Configuration and a successful stdio check
alone do not establish that the current chat has loaded the native tools. Do
not start extra chats automatically to refresh them.

## Tool workflow

1. `vault2_open({})` opens the fixed GHL origin in an empty isolated profile.
   It reads no Vault credentials. Keep its `sessionId` for subsequent calls.
2. `vault2_select({sessionId})` binds the loaded, empty login form and selects
   only the exact account in the existing private `ghl-selection.json`. It
   checks the imported record ID, metadata origin and exact stored username.
   It returns nonsecret account metadata and a five-minute, single-use
   `selectionId`. It never returns a password.
3. With the owner's explicit login authorization,
   `vault2_sign_in({sessionId, selectionId})` consumes the selection before I/O,
   revalidates private selection, obtains the existing shared browser lock,
   privately fills the bound form and submits once. An error or uncertain
   response never permits a second attempt with that session. No resend or
   provider retry is implemented.
4. The owner completes MFA, CAPTCHA, recovery or consent privately in the
   separate working Chrome window. Never ask for codes in chat or retrieve
   them through Gmail. `vault2_inspect({sessionId})` returns only a state enum
   and a screenshot with editable fields masked.
5. `vault2_verify({sessionId})` requires a successfully issued submission,
   exact selected email in the visible profile menu, a reload, and the same
   exact email again. The current provider marker is an accessible button
   named `Open Profile Menu` with the exact email in a visible `menu` role.
   If GHL does not expose those markers, it fails closed as unverified; a
   separately inspected provider-specific marker is needed. The synthetic
   test validates this policy, not GHL's authenticated menu implementation.
6. Always `vault2_close({sessionId})`. It revokes any temporary Vault owner
   session and requires a subsequent 401, releases only its acquired lock,
   closes its own browser and removes only its generated temporary profile.
   Unverified cleanup retains the server session so close can be retried.

Only session/selection UUIDs are accepted as tool arguments. There is no
arbitrary account override, origin, URL, selector, script, credential, browser
attachment, storage export or API-proxy tool. MCP schemas reject extra fields.
An opaque session is scoped to this server connection and internally owned
context/page objects; it cannot attach another client's tab. This replaces
T3's transport-specific thread/tab/profile checks with private ownership of
the complete browser process. It is not a host attestation of a chat/thread
identifier, and clients must not share returned session handles across chats.

The guard checks the fixed origin, full bound URL, navigation/control generation,
same document/form/controls, unique visible inputs, expected input types, exact
username, and no intervening trusted human input. Form replacement or navigation
invalidates the selection even at the same URL. Dialogs and extra tabs stop
automation. Owner interaction after submission is allowed for verification,
and never authorizes another fill or submission.

## Custody and cleanup

Credential reads happen inside the local MCP process through the existing
owner-assisted mechanism. The `t3-raven` proxy agent and its grants are not
used or changed. Only the selected metadata, username and password keys are
read; passwords remain inside the process/browser transport and never enter
model-visible MCP arguments/results. Callback results cannot return a password.
Raw engine errors, Playwright call logs, page text and network responses are
not forwarded. Browser tracing, HAR/video recording, console capture and
debug logging are not enabled. The clipboard is not used at all.

This retains the existing same-user trust model: owner inputs and credentials
are accessible to authorized local code running as that macOS user. It is not
an isolation boundary against an unrestricted local agent. JavaScript strings
cannot be guaranteed zeroized. Chrome's temporary profile can contain its own
browser state until verified close/removal. Masked screenshots are retained
separately under `~/.local/share/vault2-native-evidence/`, outside Git, with
owner-only directories/files. They may include nonsecret account identity.

The browser session expires after ten minutes and also closes on stdio EOF,
SIGINT or SIGTERM. Close waits for an active operation rather than racing it.
SIGKILL, power loss or host crashes cannot run cleanup. Do not claim those cases
were cleaned or remove another process's profile/lock to recover automatically.

## Measurements and focused validation

Results include UTC start/end boundaries and durations for open, lookup, private
fill, submission, provider observation, identity verification and cleanup.
`credentialLookupMs` includes the selected single-key engine reads;
`privateFillMs` measures only private browser insertion. `sessionElapsedMs`
runs from session construction to the response. `loginEndToEndMs` stays null
until exact identity survives reload, then measures from selection lookup to
that verification, including owner MFA wait. Do not equate any one phase with
complete login time.

```sh
~/.bun/bin/bun test integrations/browser
python3 scripts/vault2/test_operations.py
cd integrations/browser/native-codex
~/.bun/bin/bun check.mjs
# Optional public-page check: opens isolated GHL, inspects, closes; no Vault use.
~/.bun/bin/bun check.mjs --page
```

The browser tests render a clearly labeled synthetic app with all requests
intercepted, synthetic credentials, and no live engine/provider calls. They
exercise private fill, identity after reload, independent profiles, changed
forms/URLs/input types and human control. They are not saved-account browser
acceptance. `check.mjs --page` validates real unauthenticated GHL loading and
profile cleanup only. A real saved-account submission, owner MFA and exact
GHL identity after reload remain a separate acceptance gate.

References: [Codex MCP configuration](https://developers.openai.com/learn/docs-mcp),
[Playwright isolated contexts](https://playwright.dev/docs/api/class-browsercontext),
[Playwright temporary persistent contexts](https://playwright.dev/docs/api/class-browsertype#browser-type-launch-persistent-context).
