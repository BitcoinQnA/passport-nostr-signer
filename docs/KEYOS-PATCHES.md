# PIO endpoint reliability — two fixes

Found and fixed while getting the Nostr Signer app working over a runtime-registered
second CDC-ACM interface. Both apply to any PIO endpoint (EPs 8–15 on SAMA5D27
UDPHS, i.e. any endpoint that couldn't get a DMA slot), not just the nostr-signer.
Before the fixes a second PIO OUT endpoint was unusable for non-trivial traffic:
the first bug panicked the kernel on the first host→device packet; the second
silently truncated any payload that spanned more than one USB bulk packet.

Each fix is isolated and can be landed independently.

---

## Fix 1 — Mask the per-endpoint top-level IRQ while status bits are latched

**Symptom:** Kernel panics / watchdog reboots on the first OUT packet to a
runtime-registered second HID/CDC interface. System becomes unresponsive under
load: user-space is starved because the USB IRQ never stops firing.

**Root cause:** `handle_pio_irq` forwards the per-endpoint status word to the
USB server thread via message, but the per-endpoint status register's
`received_out` / `transmission_complete` bits stay latched until the server has
actually processed the message and cleared them. As long as those bits are set,
UDPHS keeps asserting its top-level IRQ line, and the handler re-enters
immediately on every return. The server thread never gets a CPU cycle to read
its message queue, so the status is never cleared, so the storm never ends.
Eventually the watchdog trips.

(Background endpoint 0 and DMA endpoints are fine because DMA auto-clears; PIO
has no such mechanism.)

**Fix:** In the IRQ handler, mask the top-level interrupt for that one
endpoint (clear bit `ep_number + 8` in `IEN`) after queueing the message. In
the server-side message handler, re-arm the bit after the status bits have
been cleared. Net effect: one IRQ per packet, delivered to user-space, no
storm.

**Files:**

- `imports/atsama5d27/src/udphs.rs`
  New public method mirroring `enable_endpoint_interrupt`:

  ```rust
  #[inline]
  pub fn disable_endpoint_interrupt(&mut self, ep_number: usize) {
      assert!(ep_number < 16);
      let ien = self.csr.r(IEN) & !(1 << (ep_number + 8));
      self.csr.wo(IEN, ien);
  }
  ```

- `os/usb/src/device/implementation.rs`
  - In the PIO IRQ handler loop, after queueing the status message for
    user-space, call `context.hw.disable_endpoint_interrupt(pio_endpoint)`.
  - In the server-side PIO IRQ message handler, after clearing the per-EP
    status bits, call `self.hw.enable_endpoint_interrupt(ep_num as usize)`
    to re-arm for the next packet.

**Risk:** Low — change only affects the IRQ arming sequence for PIO endpoints.
DMA endpoints are unchanged. The masked bit is guaranteed to be re-armed
because user-space always reaches the clear-status path (or the endpoint is
torn down on disconnect).

---

## Fix 2 — Queue PIO RX when no reader is posted

**Symptom:** Multi-packet host→device payloads get silently truncated. The
downstream app sees only the first packet's bytes concatenated with the next
packet's bytes, with whatever arrived in between dropped. Easily reproduced
with any JSON request whose encoded form spans multiple USB bulk packets
(~100 bytes is enough).

**Observable signature:**

```
PIO IRQ EP9: rx_out=true byte_count=40
PIO IRQ EP9: rx_out=true byte_count=7
PIO EP9 RXOUT with no reader; dropping 7 bytes    ← here
PIO IRQ EP9: rx_out=true byte_count=47
cdc dispatcher: got 86 byte payload               ← 40 + 47, middle lost
cdc parse error id=0: expected ',' or '}' at line 1 column 43
```

**Root cause:** `RuntimeEndpointData` only has a single `ongoing_read` slot.
Between a `read_buf` returning and the next `read_buf` call (the userspace
reader doing any work at all), there is no destination to copy new RX bytes
into. The IRQ handler drops the packet outright. For PIO endpoints there is
no on-chip DMA buffer to catch the data — the bank just gets overwritten on
the next packet.

The user-space reader can't avoid the race by being fast enough: USB bulk
packet-to-packet gaps at high-speed are microseconds, shorter than the IPC
round-trip to post another read.

**Fix:** Add a small bounded per-endpoint queue. When RXOUT fires and no
`ongoing_read` is posted, copy bank memory into a freshly allocated `Vec<u8>`
and push it onto the queue instead of dropping. On the next `ReadEndpoint`
request, if the queue is non-empty, pop front, copy into the user's buffer,
and resolve synchronously without waiting for a new IRQ.

Bound is 8 packets per endpoint — enough to cover the largest realistic
burst (a ~4KB payload split into 512-byte max-packet chunks ≈ 8), and small
enough that a runaway host can't OOM the kernel. Queue overflows log a
warning and drop the bytes (same behaviour as today; visible but not
silent).

**Files:**

- `os/usb/src/device/implementation.rs`
  - Add `rx_queue: VecDeque<Vec<u8>>` to `RuntimeEndpointData`; initialize
    empty in `register_interface`'s endpoint construction.
  - Add `RX_QUEUE_MAX_PACKETS: usize = 8` constant.
  - In the PIO IRQ handler's "no reader" branch, allocate a `Vec`, copy
    bank memory into it, push to `rx_queue` (honour the bound; drop + warn
    on overflow). Clear the status bit either way.
  - In `DeferredLendMutHandler<ReadEndpoint>` for PIO endpoints, drain a
    queued packet synchronously (copy into the user's buffer, set response,
    early-return) before parking the deferred message on `ongoing_read`.
  - In `send_disconnected`, `rx_queue.clear()` per endpoint so stale bytes
    don't survive across host reconnects.

**Risk:** Low-medium. The queue is per-endpoint with a hard bound. DMA
endpoints are entirely unaffected (the PIO branch is explicitly gated by
`is_pio_endpoint`). The synchronous-drain path resolves the deferred
message on the server thread the same way the IRQ handler would have —
same API, same ordering guarantees. Memory bound is
`16 endpoints × 8 packets × 512 bytes = 64 KiB` worst case per server.

---

## Validation

Both fixes were exercised end-to-end via:

1. A runtime-registered CDC-ACM interface (PIO EP9 OUT / EP10 IN on a
   SAMA5D27 with an already-present boot log CDC on the DMA endpoints).
2. Browser-extension host speaking newline-delimited JSON over Web Serial.
3. Full NIP-07 signing flow: `list_keys`, `get_public_key`, `sign_event`
   (with on-device approval prompt).

Before fix 1: kernel panic on first OUT packet, watchdog reboot.
After fix 1: stable; PIO reads + writes work for single-packet payloads.
Before fix 2: multi-packet JSON requests get corrupted silently.
After fix 2: sign_event (~90 byte JSON split across two bulk packets)
round-trips cleanly, user sees approval UI, signature returns to host.
