# Passport Prime Nostr Signer — Wire Protocol

Status: v0.1 draft. Normative for the browser extension and the KeyOS app.
Both sides implement this with types from the `protocol` crate.

## Layers

1. **Transport.** WebSocket is implemented for the simulator. A production
   device transport is pending a public QuantumLink app API.
2. **Framing.** WebSocket uses one text frame per JSON message. The historical
   WebUSB proposal used newline-delimited JSON across 64-byte transfers.
3. **Messages.** JSON requests and responses, described below.

## 1. Transport

### WebUSB (historical proposal)

This interface is not compiled into the standalone SDK app. It remains a wire
format proposal for a future public host transport.

- Vendor-class USB interface advertised with class/subclass/protocol
  `0xFF/0xFF/0xFF`.
- Two interrupt endpoints: one OUT (host → device), one IN (device → host),
  both max packet length 64 bytes.
- WebUSB Platform Capability vendor code: `0x1E`.
- Dedicated production VID/PID: TBD. Dev builds pair by WebUSB device picker
  and interface-class matching.

### WebSocket (simulator)

- `ws://localhost:9876` by default.
- Text frames. One frame = one JSON message.
- No newline framing layer is needed beyond the WebSocket text frame.

## 2. WebUSB framing

Each WebUSB message is a single JSON blob followed by `\n`. The host and device
split the byte stream into 64-byte interrupt transfers and reassemble until the
newline delimiter.

Receivers MUST:
- Ignore empty lines.
- Reject invalid UTF-8/JSON with `invalid_request`.
- Cap a single line at 16 KiB and drop the in-progress line on overflow.

Senders SHOULD:
- Emit exactly one trailing `\n` after each JSON message.
- Keep one request in flight per device connection unless/until the protocol
  grows explicit multiplexing semantics.

The `protocol::frame` HID report framer remains as a host-testable utility for
older experiments, but it is not the production WebUSB wire format.

### Legacy HID framing

The earlier proof-of-concept used fixed 64-byte HID reports:

```
offset  0      1    2..=3    4..=63
field   flags  rsv  len_be   payload
```

- `flags`  bit 7 `INIT` (first report in a message), bit 0 `FINAL` (last
  report in a message). Other bits reserved, must be 0.
- `rsv`    reserved, must be 0.
- `len_be` big-endian `u16`; number of valid payload bytes in this report,
  0..=60.
- `payload` the JSON bytes; bytes beyond `len` are ignored.

A single-report message sets both `INIT` and `FINAL`.

Legacy HID receivers MUST:
- Start assembly on `INIT`, discarding any in-progress buffer.
- Reject continuation reports that arrive without a prior `INIT`.
- Cap total payload at 16 KiB and error out on overflow.

Legacy HID senders SHOULD:
- Emit reports in order. HID guarantees in-order delivery, so no sequence
  number is needed on the wire.

## 3. Messages

Messages are UTF-8 JSON. The two envelope types are `Request` and
`Response`, with matching `id` strings for correlation.

### 3.1 Request

```json
{
  "id": "<unique-string>",
  "method": "<method-name>",
  "params": { ... }      // optional, shape depends on method
}
```

The `id` is echoed verbatim in the response. Senders choose it (a
monotonic counter or short random string).

### 3.2 Response

Either success:

```json
{ "id": "<same-as-request>", "result": { ... } }
```

or error:

```json
{ "id": "<same-as-request>",
  "error": { "code": <int>, "message": "<str>" } }
```

### 3.3 Error codes

| Code | Name              | Meaning |
|------|-------------------|---------|
| 1    | `invalid_request` | Bad JSON, unknown fields, wrong types. |
| 2    | `unknown_method`  | Method name not recognised. |
| 3    | `unknown_key`     | No stored identity matches the supplied uuid. |
| 4    | `user_rejected`   | User declined the on-device approval prompt. |
| 5    | `timeout`         | User did not respond within the device's timeout. |
| 6    | `not_unlocked`    | Device is locked; user must enter PIN. |
| 99   | `internal`        | Unexpected device-side failure. |

## 4. Methods

All method names are snake_case. The method surface is intentionally close
to NIP-46 so the vocabulary carries over to a relay-proxied transport
without breaking clients.

### `ping`

Liveness check. Returns `{ "pong": true }`.

### `list_keys`

Returns the public metadata for every stored identity. Does **not** require
the device to be unlocked beyond initial login — no ciphertext is touched.

Response result:

```json
{
  "keys": [
    { "uuid": "<hex16>", "label": "QnA", "pubkey": "<hex32>",
      "created_at": 1714078911 }
  ]
}
```

### `select_key`

Picks a default identity for subsequent calls. No user prompt.

```json
{ "method": "select_key", "params": { "uuid": "<hex16>" } }
```

Response: `{ "selected": "<hex16>" }`.

### `get_public_key`

Returns the x-only pubkey of the currently-selected identity, or the one
referenced by `uuid` in `params` if provided.

Response: `{ "pubkey": "<hex32>" }`.

### `sign_event`

Signs a NIP-01 event. Requires physical approval on the device unless the event
matches an owner-configured auto-sign policy stored locally on the device.

```json
{
  "method": "sign_event",
  "params": {
    "uuid":   "<hex16>",                  // optional
    "origin": "https://nostrudel.ninja",  // optional, surfaced in prompt
    "event": {
      "pubkey":     "<hex32>",
      "created_at": 1714078911,
      "kind":       1,
      "tags":       [],
      "content":    "gm"
    }
  }
}
```

Response: the complete signed event including `id` and `sig`.

### Local auto-sign policies

Auto-sign is not exposed as a wire method. Browser clients and the extension
cannot create, edit, or delete policies.

Before showing the approval screen, the device checks local policy for
`sign_event` only. A policy matches exactly by live key UUID, normalized HTTP(S)
origin, and event kind. Matched policies must be enabled, unexpired, and under
their hourly usage cap. If any check fails, the request returns to the normal
manual approval path.

Policy storage is authenticated with a MAC key derived from the KeyOS app seed.
If the policy file fails verification, auto-sign is disabled for that session
and signing remains manual.

### `nip04_encrypt` / `nip04_decrypt`

Legacy DM cryptography. `plaintext`/`ciphertext` are strings in NIP-04
format (base64 + `?iv=` suffix). Both directions require physical approval on
the device before ciphertext or plaintext is returned to the browser.

### `nip44_encrypt` / `nip44_decrypt`

NIP-44 v2 cryptography used for NIP-17 DMs and NIP-46 transport.

Both encrypt and decrypt methods require physical approval. A future explicit
per-origin DM-reading policy may relax repeated decrypt prompts, but the public
default is fail-closed.

## 5. Security notes

- The nsec never leaves the device. `get_public_key` and `list_keys` only
  surface public material.
- Every `nip*_encrypt` and `nip*_decrypt` request shows the user:
  - the origin, if supplied,
  - a content preview, truncated to the display width,
  - the key label and peer pubkey.
- Every `sign_event` request either shows the same approval details (origin,
  event kind, content preview, tag count, and npub) or matches an explicit
  on-device auto-sign rule.
- Auto-sign rules are intentionally narrow: no wildcards, no browser-created
  grants, exact origin and kind matching, expiry, hourly cap, and audit log.
- The USB cable is the trust boundary. The transport layer has no
  encryption; an attacker with physical access to both the device and a
  malicious host can observe signing-request contents (though not the
  nsec). This matches the trust model of the existing FIDO app.
