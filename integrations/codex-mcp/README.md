# Codex connection and owner-assisted GoDaddy fill

This connector supports GoDaddy account metadata lookup and a reviewed local
helper that fills a selected saved login inside the CUA JavaScript runtime.
The helper has completed a real private fill. **GoDaddy sign-in is unverified:**
the provider displayed "Your browser is a bit unusual..." before submission.

## Tools and custody

- `vault2_status` separates engine lookup, helper availability and provider state.
- `vault2_find_accounts` returns only approved names, usernames and origins.
- `vault2_private_fill_info` identifies the reviewed module and its binding
  requirements. It does not read credentials or operate a browser.

The original `vault` connector and its T3 socket remain separate. The local
`vault2` helper reads the existing owner-only configuration and imported vault;
it creates no agent, grant, role, service rule or second credential store.

The helper uses supported, tab-scoped in-app Browser operations. Credential
lookup and delivery occur inside its local runtime. Model-visible calls contain
only the module invocation and actual tab/chat binding, never a password literal.
Raw browser exceptions are replaced with bounded reason codes. Authentication
fields are not read back from the DOM, and no clipboard, native-app automation,
browser storage, cookies or secret-bearing browser network responses are read.

This is **owner-assisted, same-user custody**, not an isolated native password
manager. The browser necessarily receives the password to fill its field. The
current Browser API does not expose a T3-style native control-generation lease;
this adapter uses a fresh CUA-owned tab handle, exact URL/origin and form checks
before and after actions, plus a private helper lock. It does not protect against
an unrestricted program running as the same macOS user or a compromised browser
host. A successful API fill acknowledgement is not a read-back content check.

## Reusable flow

1. Require an explicit owner request to use the saved GoDaddy account.
2. Call `vault2_status`. Respect a recorded provider block; a fresh website
   attempt requires owner authorization after its prerequisite is addressed.
3. Obtain the reviewed module URI from `vault2_private_fill_info`.
4. Create a fresh owned `iab` tab at `https://sso.godaddy.com/`. Inspect its
   public form and stop for browser rejection, MFA or CAPTCHA.
5. Import the module inside `cua_repl`, then bind its `bindPrivateGoDaddyTab`
   factory to that actual tab object and `{ browser: 'iab', tabId, threadId }`.
   Use the actual current IDs. Never use another chat's tab.
6. Call the bound helper's `prepare()`. It probes with harmless text, checks the
   exact registered source record and username from private configuration,
   retrieves only selected fields, fills through scoped Browser controls, and
   revokes/checks its temporary owner session before returning.
7. Inspect the fresh visible page. GoDaddy currently states that Sign in accepts
   its Terms of Service. Obtain the required action-time owner confirmation
   before `submit({ termsApproved: true })`. Preparation expires after five
   minutes. Never retry `submission_uncertain`.
8. Inspect for the precise next human step or exact signed-in identity. Verify
   visible identity after reload before claiming success. `submitted` always
   has `identityVerified: false`.
9. `cancel()` clears the owned form when still safely bound and releases the
   lock. If a provider warning replaces the form, close the owned credential
   tab instead. Do not switch to personal Chrome or bypass the provider block.

No password, source account UUID, actual selected identity, owner input or
private state is embedded in this source. The registered account selection and
latest provider receipt live in owner-only local configuration outside Git.

## Development

Use the installed Bun. Preserve existing upstream lockfiles.

```sh
bun install --frozen-lockfile --ignore-scripts
bun test
```

Register through the supported `codex mcp add` CLI with the installed Bun and
the server's absolute path. Verify MCP initialization, tool discovery and a real
call in the current chat. Source changes in an already-running MCP process need
the host's connection refresh; do not restart the entire app or other chats.

## Verification on 23 October 2026

- Seventeen synthetic privacy/protocol tests pass, including origin and account
  binding, cleanup, secret-bearing error redaction, single submission, terms
  approval gating and provider rejection before credential access.
- Live account lookup found four GoDaddy records; the exact registered record
  was bound privately for the fill, rather than selecting an ambiguous match.
- The live helper acknowledged the real username/password fill and verified
  owner-session revocation. Lookup took 29.6 ms; fill took 59.8 ms. These are
  bounded helper measurements, **not complete website-login time**.
- The next visible state was GoDaddy's unusual-browser warning. No Sign in
  click occurred. In-page clearing was unavailable after the warning; the owned
  credential tab was closed and the private helper lock released.
- Real nonsecret evidence and the operational receipt are private local files.
  No website signed-in identity or native isolated private-fill boundary is
  claimed. Browser compatibility with GoDaddy is the remaining acceptance gate.

### Fresh browser investigation, 23 October 2026

A new owner-authorized attempt reproduced the provider warning before Sign in.
The fresh owned in-app tab initially rendered its JavaScript login form without
the warning. Disposable username entry, password focus, and disposable password
entry/clearing also left the form usable. After the real private helper fill,
the next visible state was the unusual-browser modal. This establishes the
sequence, not a specific cause. The helper's immediate prepared result does not
prove the provider's asynchronous browser checks have accepted the page.

The temporary owner session was revoked, the helper cancelled, its lock released,
and the credential tab closed. No submission, terms acceptance or signed-in
identity was observed. No further credential retry is appropriate until the
browser prerequisite is addressed and the owner authorizes a fresh attempt.

The supported in-app Browser capability inventory exposes visibility and
viewport controls, plus tab-scoped page assets and WebMCP. It exposes no site
cookie, popup, extension or privacy settings. Tailscale was running without a
configured or active exit node, so disabling Tailscale is not an evidence-backed
fix. Other networking/privacy causes remain untested. No settings were weakened,
browser fingerprint changed, or alternative browser controlled.

GoDaddy's official troubleshooting reference is
https://www.godaddy.com/en-uk/help/your-browser-is-a-bit-unusual-faq-41807.
Its possible fixes require browser configuration access outside this adapter's
supported controls. The remaining handoff is an in-app Browser compatibility
fix or provider support; Vault source changes alone do not establish acceptance.
