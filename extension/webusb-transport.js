// SPDX-License-Identifier: GPL-3.0-or-later
// WebUSB transport. Speaks newline-delimited JSON to the Nostr Signer
// app on Passport Prime, which exposes a vendor-class USB interface
// (class/subclass/protocol = 0xFF/0xFF/0xFF) with two 64-byte Interrupt
// endpoints plus WebUSB + MS OS 2.0 Platform Capability descriptors.
// Retained for a future public KeyOS host transport; SDK 1.4 has no device side.
//
// Pairing model: the options page calls navigator.usb.requestDevice()
// (which needs a user gesture) to get a persistent grant. Subsequent
// connects from this offscreen document use getDevices().

const REQUEST_TIMEOUT_MS = 5 * 60 * 1000; // allow for on-device approval tap
const PROBE_TIMEOUT_MS = 1500;

// Match on class/subclass/protocol. Prime's VID/PID is not yet a
// dedicated pair — KeyOS uses its default, which will vary between
// firmware builds — so class-based filtering is the portable choice.
// Once a dedicated VID/PID is allocated this filter should tighten.
const DEVICE_FILTER = {
  classCode: 0xff,
  subclassCode: 0xff,
  protocolCode: 0xff,
};

export class WebUsbTransport {
  constructor() {
    this.device = null;
    this.ifaceNumber = null;
    this.inEp = null;
    this.outEp = null;
    this.readLoop = null;
    this.lineBuffer = "";
    this.pending = new Map(); // request id -> { resolve, reject }
    this.readAbort = false;
  }

  async connect() {
    // Offscreen document has no user gesture, so requestDevice() is not
    // callable here — we rely on a device having already been paired via
    // the options page. If no granted device probes successfully, bail
    // with a clear error telling the user to re-pair.
    const granted = await navigator.usb.getDevices();
    console.log(
      "[prime-signer/webusb] connect: granted devices =",
      granted.map((d) => ({ vid: d.vendorId, pid: d.productId, name: d.productName })),
    );
    if (granted.length === 0) {
      throw new Error("No Passport Prime paired yet");
    }
    const failures = [];
    for (const d of granted) {
      console.log("[prime-signer/webusb] trying device", d.productName || `${d.vendorId}:${d.productId}`);
      const { ok, reason } = await this._tryOpen(d);
      console.log("[prime-signer/webusb] device result:", ok ? "ok" : reason);
      if (ok) return;
      failures.push(reason);
    }
    // Prefer the most informative single reason — concatenating reasons
    // across multiple paired devices is overwhelming and almost never
    // useful (users typically have one Prime paired).
    throw new Error(failures[0] || "Couldn't connect to Passport Prime");
  }

  async _tryOpen(device) {
    try {
      if (!device.opened) await device.open();
      if (device.configuration === null) await device.selectConfiguration(1);
    } catch (e) {
      const raw = String(e?.message || e);
      console.warn("[prime-signer/webusb] open failed:", raw);
      const friendly = /disconnected/i.test(raw)
        ? "Passport Prime disconnected. Reconnect it via USB and try again."
        : "Couldn't open Passport Prime. Unplug and replug it, then try again.";
      return { ok: false, reason: friendly };
    }

    // Find the vendor-class interface we registered on the device side.
    // The same device may expose other interfaces (e.g. FIDO on the
    // existing CTAP-HID server), so we locate ours by matching the
    // interface class triple.
    let ifaceNumber = null;
    let inEpNumber = null;
    let outEpNumber = null;
    for (const iface of device.configuration.interfaces) {
      const alt = iface.alternate;
      if (
        alt.interfaceClass === DEVICE_FILTER.classCode &&
        alt.interfaceSubclass === DEVICE_FILTER.subclassCode &&
        alt.interfaceProtocol === DEVICE_FILTER.protocolCode
      ) {
        const inEp = alt.endpoints.find((e) => e.direction === "in");
        const outEp = alt.endpoints.find((e) => e.direction === "out");
        if (inEp && outEp) {
          ifaceNumber = iface.interfaceNumber;
          inEpNumber = inEp.endpointNumber;
          outEpNumber = outEp.endpointNumber;
          break;
        }
      }
    }
    if (ifaceNumber === null) {
      try { await device.close(); } catch {}
      return { ok: false, reason: "Open the Nostr Signer app on your Passport Prime, then click the extension again." };
    }

    try {
      await device.claimInterface(ifaceNumber);
    } catch (e) {
      try { await device.close(); } catch {}
      console.warn("[prime-signer/webusb] claim iface", ifaceNumber, "failed:", e?.message || e);
      return { ok: false, reason: "Another browser tab or extension is using your Passport Prime. Close it and try again." };
    }

    this.device = device;
    this.ifaceNumber = ifaceNumber;
    this.inEp = inEpNumber;
    this.outEp = outEpNumber;
    this.readAbort = false;
    this.lineBuffer = "";
    this.readLoop = this._readLoop();

    // Probe with a ping. If it doesn't answer in PROBE_TIMEOUT_MS we're
    // almost certainly on the wrong interface or the Nostr Signer app
    // is not running on Prime.
    try {
      await this._rawRpc("ping", null, PROBE_TIMEOUT_MS);
      return { ok: true };
    } catch (e) {
      console.warn("[prime-signer/webusb] ping failed:", e?.message || JSON.stringify(e));
      await this._tearDown();
      return {
        ok: false,
        reason: "The Nostr Signer app didn't respond. Make sure it's open on your Passport Prime.",
      };
    }
  }

  async _tearDown() {
    this.readAbort = true;
    try {
      if (this.device && this.ifaceNumber !== null) {
        await this.device.releaseInterface(this.ifaceNumber);
      }
    } catch {}
    try {
      if (this.device && this.device.opened) await this.device.close();
    } catch {}
    this.device = null;
    this.ifaceNumber = null;
    this.inEp = null;
    this.outEp = null;
    this.lineBuffer = "";
    for (const [, entry] of this.pending) entry.reject({ code: 99, message: "disconnected" });
    this.pending.clear();
  }

  async disconnect() {
    await this._tearDown();
  }

  isConnected() {
    return !!this.device && this.device.opened;
  }

  async _readLoop() {
    const decoder = new TextDecoder();
    let endedCleanly = false;
    try {
      while (!this.readAbort && this.device && this.device.opened) {
        let result;
        try {
          // Read one report at a time. The device writes the response
          // in 64-byte chunks; we accumulate until we see a newline.
          result = await this.device.transferIn(this.inEp, 64);
        } catch (e) {
          console.warn("[prime-signer/webusb] transferIn errored:", e);
          break;
        }
        if (result.status !== "ok") {
          console.warn("[prime-signer/webusb] transferIn status:", result.status);
          if (result.status === "stall") {
            try { await this.device.clearHalt("in", this.inEp); } catch {}
            continue;
          }
          break;
        }
        if (!result.data || result.data.byteLength === 0) continue;
        this.lineBuffer += decoder.decode(result.data.buffer, { stream: true });
        let idx;
        while ((idx = this.lineBuffer.indexOf("\n")) >= 0) {
          const line = this.lineBuffer.slice(0, idx).replace(/\r$/, "");
          this.lineBuffer = this.lineBuffer.slice(idx + 1);
          if (line.length === 0) continue;
          this._onLine(line);
        }
      }
      endedCleanly = true;
    } catch (e) {
      console.warn("[prime-signer/webusb] read loop errored:", e);
    }
    // If the read loop exited because the device went away, tear down
    // so the next rpc() goes through connect() again.
    if (!this.readAbort && !endedCleanly) {
      this._tearDown().catch(() => {});
    }
  }

  _onLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch {
      // Stray non-JSON — ignore (unlikely on WebUSB vs. WebSerial, but
      // free insurance).
      return;
    }
    if (!msg || typeof msg.id !== "string") return;
    const entry = this.pending.get(msg.id);
    if (!entry) return;
    this.pending.delete(msg.id);
    if (msg.error) entry.reject(msg.error); else entry.resolve(msg.result);
  }

  async rpc(method, params) {
    if (!this.device) await this.connect();
    try {
      return await this._rawRpc(method, params, REQUEST_TIMEOUT_MS);
    } catch (e) {
      const msg = String(e?.message || e);
      const transient =
        msg.includes("device has been lost") ||
        msg.includes("disconnected") ||
        msg.includes("closed") ||
        msg.includes("not opened");
      if (!transient) throw e;
      console.warn("[prime-signer/webusb] transient error, retrying once:", msg);
      await this._tearDown();
      await this.connect();
      return await this._rawRpc(method, params, REQUEST_TIMEOUT_MS);
    }
  }

  async _rawRpc(method, params, timeoutMs) {
    const id = randomId();
    const payload = { id, method };
    if (params && Object.keys(params).length > 0) payload.params = params;
    const line = JSON.stringify(payload) + "\n";
    const bytes = new TextEncoder().encode(line);

    const promise = new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject({ code: 5, message: "signer timeout" });
        }
      }, timeoutMs);
    });

    // The device's OUT endpoint is 64 bytes — chunk writes.
    try {
      for (let off = 0; off < bytes.length; off += 64) {
        const chunk = bytes.slice(off, off + 64);
        const res = await this.device.transferOut(this.outEp, chunk);
        if (res.status !== "ok") {
          throw new Error(`transferOut status: ${res.status}`);
        }
      }
    } catch (e) {
      this.pending.delete(id);
      throw e;
    }
    return promise;
  }
}

function randomId() {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
