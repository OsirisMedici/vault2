# Browser integration status

`integrations/browser/ghl-session.mjs` is an owner-assisted local helper using
the existing engine's selected single-key reads. It has fixed GHL origin/form
rules and exact current thread, tab, profile, URL/control and account binding.
It never emits passwords in tool requests or results. It is a draft local
workflow, not a supported native T3 private-fill API.

The owner-selected GHL identity is loaded from the owner-only local
`ghl-selection.json` below the existing private runtime root. The configuration
contains version 1, the fixed GHL origin, selected imported account ID and exact
expected username. Real values stay outside public source. Missing/invalid
configuration fails closed before engine access. Never substitute another
account merely because the form accepts its email.

The helper's `probe-input` uses harmless text and no vault access. `discover`
obtains a short-lived, one-use selection. `sign-in` rechecks the binding, performs
private fill and submits once. `submitted` always has `identityVerified:false`.
The working page must then be inspected for a required owner step or exact
identity. Close the helper after any attempt; successful cleanup requires
clipboard compare/clear, lock release and logout followed by rejected auth.

The retained `browser-probe.mjs`/`probe-policy.mjs` are credential-free Figma
experiments. They only fill and clear a random invalid email, do not import
vault code, do not fill passwords and have no submit action. They test a
batched clipboard transaction when browser permission is already granted.
They are not authorized containers for real credentials.

The relay handles coalesced independent status/list reads and records tool
timings. Mutations remain sequential. It must not drop a second request from
the same stdout chunk or accept arbitrary tool names.

On Raven a real GHL password submission reached email OTP. Full sign-in and
identity are pending. The owner enters verification privately in the working
page; do not retrieve codes from email, ask for them in chat, resend or repeat
the login while a challenge is pending. The old thread's tabs are not owned by
a new continuation. Profile continuity does not prove current authentication.

The standalone source extraction changes the private-file import to a local
module and moves expected account metadata out of source. Focused tests and
syntax checks cover that extraction. It is not a fresh live login acceptance
for this repository. Do not rerun authentication simply to validate a repo move.
