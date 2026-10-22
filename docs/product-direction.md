# Product direction and acceptance

## Intended experience

The owner asks a chat to use a saved account. The agent selects the intended
identity, opens the approved website, fills privately and proves which account
signed in. The owner does not copy/type the password for each request. MFA,
CAPTCHA, recovery and provider consent remain explicit human steps when needed.

The normal loaded-page path should target 1–3 seconds where feasible. Measure
lookup, fill, navigation, provider authentication, cleanup and total time with
clear boundaries. A fast credential lookup or existing connector action cannot
stand in for complete login timing.

## Verified starting point

This project separates the full upstream source and Vault 2 additions from the
older Vault repository. The existing Raven app and private state remain in
place. The source split itself is not a deployment or a new login result.

- Branded UI and managed local engine/frontend startup work on Raven.
- Authenticated readiness, controlled service restart, encrypted backup and
  isolated data decryption/restoration were tested. Whole-Mac reboot, off-device
  recovery and a running restored engine are still unverified.
- A real owner-assisted GHL run selected the stored account, filled username and
  password privately, submitted once and reached email OTP verification.
  Clipboard clear, owner-session revocation and helper/lock cleanup passed.
- The fill-and-submit command took 21.698 seconds. It is not total login time;
  identity verification remains incomplete. No 1–3 second login acceptance exists.
- Figma's existing authenticated connector works separately; Figma has no saved
  login pair in the imported inventory. Do not request a Figma password merely
  to manufacture a Vault test.

Actual account IDs, usernames, screenshots and operational receipts remain
private. The next chat must inspect current state rather than treating the
historical OTP page as a current authenticated session.

## What to build first

1. Finish one complete password-based browser workflow. Require exact account
   selection, private fill, one submission, honest verification-required state,
   owner completion when necessary and exact visible signed-in identity.
2. Make the T3 entry point reusable in a fresh chat. It must discover readiness
   and selected accounts without copying runtime capabilities or returning
   passwords to the model. A chat should not manually assemble dozens of tool
   exchanges. Prefer a supported trusted host private-fill action when available.
3. Reduce measured transport/fill overhead while preserving all binding checks.
   The experimental nonsecret batched input probe demonstrates a possible path,
   but must never receive real credentials without a separately reviewed adapter.
4. Add providers one at a time under fixed origins and identity rules. Any
   suitable owner-selected saved account may be used; the product is not GHL-only.
5. Strengthen custody and owner controls. The current same-user clipboard helper
   is owner-assisted; it is not an isolation boundary against an unrestricted
   local agent. Native private fill and revocable constrained actions precede
   team/admin expansion or claims that agents cannot access the secret store.

Avoid a new branding round, broad grants, live sync or API-only demonstrations
as substitutes for the first complete browser acceptance gate.

## Completion gate

From a fresh registered T3 project chat, one selected supported account request
must end in either exact verified website identity or one specific required
human step. Record real nonsecret screenshots, request/tab/account binding,
timings, clipboard/session cleanup and runtime lifetime. Verify after reload
when claiming a persisted result. Never equate `submitted` with `signed_in`.
