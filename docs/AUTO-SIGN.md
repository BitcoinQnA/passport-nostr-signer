# Auto-sign Policy Plan

Auto-sign is for repeated, low-risk Nostr events where requiring a physical
swipe every time makes the app feel broken. It is intentionally narrower than a
general permission system: the browser extension cannot create rules, wildcard
rules are not supported, and failed matches fall back to the normal approval
screen.

## Current implementation

- Rules are configured on Passport Prime from a key's detail screen.
- A rule matches only when all of these fields match:
  - the live key UUID,
  - the exact HTTP(S) site origin, normalized without a path,
  - the exact Nostr event kind.
- Each rule has:
  - enabled/disabled state,
  - expiry time (`0` means no expiry),
  - maximum uses per hour,
  - usage counters and last-used metadata.
- Auto-sign is checked only for `sign_event`. Encryption and decryption still
  require on-device approval.
- If a rule is missing, disabled, expired, over its hourly cap, malformed, or
  cannot be persisted, the engine asks for normal on-device approval.
- Archiving a key disables its auto-sign rules. Deleting a key removes its
  auto-sign rules.
- The policy file is authenticated with an HMAC key derived from the KeyOS app
  seed. If verification fails, policies are discarded for that session and the
  app falls back to manual approval.
- The policy audit log stores the last 100 auto-signed event IDs with origin,
  kind, key UUID, rule ID, and timestamp.

## Storage

Simulator state lives beside the keystore in `.passport-nostr-signer-keyos` as
`autosign.json`. On Prime, it lives in the app data directory.

Auto-sign rules are device-local authorization state, not seed-derived key
material. Restoring the device backup and reinstalling the same app ID recovers
deterministic Nostr keys, but a user
should recreate auto-sign rules deliberately on the restored device.

## Recommended defaults

- Use short expiries for test rules, such as 24 hours.
- Start with small hourly caps, such as 10 per hour.
- Prefer event kind `22242` (NIP-42 auth) as the first no-swipe candidate.
- Keep kind `1` notes, encrypted DMs, deletions, zaps, and list updates on the
  manual approval path unless the UX and threat model are revisited.

## Future hardening

- Show a readable audit-history screen instead of only counters.
- Add optional relay/tag constraints for event kinds where kind alone is too
  broad.
- Add a one-tap "create rule from this approval" flow after a manually approved
  event, with the same exact-origin/exact-kind/rate-limit constraints.
- Add an explicit backup/export story for policies if product decides they
  should migrate between devices.
- Add integration tests around the app engine once the KeyOS workspace can be
  built in CI for this app.
