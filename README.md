# Vault 2

Vault 2 is an independent project built on
[Infisical Agent Vault](https://github.com/Infisical/agent-vault).
It combines the upstream credential broker with a branded interface, private
Raven operations tools and experimental T3 browser integration.

The product goal is: **save an account once, then ask an agent to use the correct
account without typing or copying its password yourself.** The agent should
fill privately, verify the signed-in identity, explain failures accurately and
hand control to the owner when MFA, CAPTCHA or recovery is required.

## Current status

- The upstream engine provides encrypted credential storage, API credential
  brokering, agent identities, vault roles, service rules and access proposals.
- The Vault 2 interface and local startup/readiness/recovery controls work on
  the existing Raven installation. The source split does not relocate its state.
- A real saved-password GHL attempt privately filled and submitted the selected
  account and reached email OTP verification. Clipboard cleanup, temporary
  owner-session revocation and helper exit were verified.
- Full website sign-in and exact signed-in identity are **not yet verified**.
  That fill-and-submit command took about 22 seconds; it is not a 1–3 second
  login result. Universal website login and unattended MFA are not implemented.
- Existing Figma connector access works separately. It is not proof of a
  Vault-driven browser login.

Read [product direction and acceptance gates](docs/product-direction.md),
[browser workflow](docs/browser-access.md) and [Raven operations](docs/operations.md).
The [native Codex adapter](docs/native-codex-browser.md) adds isolated temporary
Chrome profiles through a local stdio MCP server, without reusing T3 state.
Real saved-account login acceptance remains pending.

## Original tool and intended product

Agent Vault brokers credentials into configured HTTP/API requests. That can
include headers and declared request-body substitutions. It does not itself
operate arbitrary website forms or verify a browser's signed-in identity.

Vault 2's additional work is the complete chat-to-account workflow: select the
account, check browser ownership and origin, privately fill, submit once, handle
owner verification and prove the resulting identity. API access is useful but
does not substitute for this website-password acceptance gate.

## Source layout

The complete pinned upstream source is present, with Vault 2 changes applied
directly to `web/`. Original history and attribution are retained.

| Path | Purpose |
| --- | --- |
| `web/` | Branded React interface and retained upstream package lock |
| `cmd/`, `internal/` | Upstream CLI/server source; engine behavior unchanged |
| `integrations/browser/` | Owner-assisted GHL helper, guarded probes and tests |
| `integrations/browser/native-codex/` | Local stdio MCP adapter with private fill and isolated Chrome profiles |
| `scripts/vault2/` | Local startup, readiness and encrypted recovery tools |
| `branding/vault2/` | Original branding patch, upstream pin and license receipt |
| `docs/upstream/` | Preserved upstream README, agent protocol and workflow references |

## Development checks

Use Bun for JavaScript and TypeScript. From this checkout:

```sh
~/.bun/bin/bun test integrations/browser
python3 scripts/vault2/test_operations.py
```

These are focused fixture/safety checks, not website-login acceptance.
The recovery checks require the existing Homebrew OpenSSL 3 library on Raven.

When a frontend build is actually needed:

```sh
cd web
~/.bun/bin/bun install --frozen-lockfile --ignore-scripts
~/.bun/bin/bun run build
```

No dependency install, engine rebuild, deployment, runtime restart or new login
is performed simply by cloning or registering this project. Existing upstream
CI/release workflows are retained as disabled references, rather than triggering
release behavior in this new repository.

## Privacy and custody

Credentials, exports, owner inputs, agent tokens, browser sessions, databases,
backups and recovery keys belong outside Git. No real account selection or
password is embedded in the public browser helper. Its selected identity is
loaded from an owner-only local configuration file.

The current helper keeps passwords out of model-visible tool arguments and
results. It runs as the same macOS user and uses the shared clipboard; it is
**not** a strong isolation boundary against unrestricted local programs or
agents. A native trusted private-fill interface and isolated credential custody
are priorities before making stronger security claims.

## Attribution and licenses

Upstream base: `Infisical/agent-vault` v0.40.2, commit
`d5836ec3bb2315de38043d742ae5daca11a4944a`.
The original [LICENSE](LICENSE) and third-party/enterprise exceptions remain.
Vault-specific contributions carry GPL-3.0-only terms as mapped in
[LICENSING.md](LICENSING.md). The original product and authors are credited;
this repository does not claim authorship of the upstream engine.
