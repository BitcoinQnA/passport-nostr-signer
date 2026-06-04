# Passport Prime Nostr Signer — Wire Protocol

Status: v0.1 draft. Normative for the browser extension and the KeyOS app.
Both sides implement this with types from the `protocol` crate.

## Layers

1. **Transport.** USB-HID in production; WebSocket for the macOS simulator.
   Transports carry opaque byte frames.
2. **Framing.** Fixed 64-byte HID reports assembled into JSON blobs. Bypassed
   on the WebSocket transport, where a single WebSocket text frame is one
   JSON blob.
3. **Messages.** JSON requests and responses, described below.

## 1. Transport

### USB-HID (production)

- Custom HID device. VID/PID: TBD (Foundation VID + new PID).
- Two reports: one `Output` (host → device), one `Input` (device → host),
  both 64 bytes.
- Report ID: 0 (no report-ID prefix).
- Usage page: vendor-defined (to avoid collision with FIDO on the same
  device; FIDO keeps its existing interface).

### WebSocket (simulator)

- `ws://localhost:9876` by default.
- Text frames. One frame = one JSON message.
- No framing layer is needed; HID framing is bypassed.

## 2. HID framing

Each HID report is 64 bytes:

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

Receivers MUST:
- Start assembly on `INIT`, discarding any in-progress buffer.
- Reject continuation reports that arrive without a prior `INIT`.
- Cap total payload at 16 KiB and error out on overflow.

Senders SHOULD:
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

Signs a NIP-01 event. Requires physical approval on the device.

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

### `nip04_encrypt` / `nip04_decrypt`

Legacy DM cryptography. `plaintext`/`ciphertext` are strings in NIP-04
format (base64 + `?iv=` suffix).

### `nip44_encrypt` / `nip44_decrypt`

NIP-44 v2 cryptography used for NIP-17 DMs and NIP-46 transport.

Both encrypt methods require physical approval. Decrypt methods do **not**
(otherwise reading a DM thread would require hundreds of taps); however
the device displays a running count of decrypt operations per origin and
rate-limits abusive sources.

## 5. Security notes

- The nsec never leaves the device. `get_public_key` and `list_keys` only
  surface public material.
- Every `sign_event` and `nip*_encrypt` request shows the user:
  - the origin, if supplied,
  - the event kind (with friendly label),
  - a content preview, truncated to the display width,
  - the npub being used.
- Approval decisions are not cached. Every request is confirmed unless the
  user has opted in to a per-origin auto-approve policy (out of scope in
  v1).
- The USB cable is the trust boundary. The transport layer has no
  encryption; an attacker with physical access to both the device and a
  malicious host can observe signing-request contents (though not the
  nsec). This matches the trust model of the existing FIDO app.
