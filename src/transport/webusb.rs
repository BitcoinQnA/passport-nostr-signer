// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebUSB transport for the Nostr Signer on Passport Prime.
//!
//! Registers a vendor-class USB interface with two 64-byte Interrupt
//! endpoints and the two Platform Capability descriptors (WebUSB and
//! Microsoft OS 2.0) that `browser-extension-1.3` filters on
//! (`classCode/subclassCode/protocolCode = 0xFF`). Wire format is
//! newline-delimited JSON, chunked across 64-byte transfers.
//!
//! Structure mirrors `apps/gui-app-vaults/src/transport/webusb.rs`. The
//! two apps coexist in the same firmware so they pick distinct vendor
//! codes for the WebUSB Platform Capability: vaults uses 0x1F, the
//! signer uses 0x1E.

use std::sync::{mpsc, Arc};

use keystore::MasterKeySource;
use protocol::{ErrorCode, Request, Response};
use server::{BlockingArchiveHandler, Server, ServerContext, ServerMessages};
use usb::device::{
    api::{EndpointDirection, EndpointType},
    messages::{EndpointProperties, SetupPacketCallback},
};

use crate::engine::Engine;

usb::use_device_api!();

// --- USB descriptors --------------------------------------------------------

const WEBUSB_IFCE_CLASS: u8 = 0xFF;
const WEBUSB_IFCE_SUBCLASS: u8 = 0xFF;
const WEBUSB_IFCE_PROTOCOL: u8 = 0xFF;
const WEBUSB_INTERFACE_NUMBER: u8 = 0;

/// Hard cap on a single newline-delimited request, in bytes. A host that
/// sends more without ever emitting `\n` is faulty or hostile; drop the
/// in-progress line and continue.
const MAX_LINE_BYTES: usize = 16 * 1024;

/// Vendor code embedded in the WebUSB Platform Capability descriptor.
/// Distinct from `gui-app-vaults`'s 0x1F so this firmware can host both
/// apps without their setup responders being confused.
const WEBUSB_VENDOR_CODE: u8 = 0x1E;

/// 64-byte Interrupt endpoints, interval = 1 (1ms service interval).
/// `use_dma: false` routes through PIO; runtime-registered second
/// interfaces land on EPs 8-15 (no DMA slot) and the dev-v1.3.0 USB
/// stack handles multi-packet PIO OUT correctly.
const WEBUSB_ENDPOINTS: [EndpointProperties; 2] = [
    EndpointProperties {
        ep_type: EndpointType::Interrupt,
        ep_direction: EndpointDirection::In,
        max_packet_len: 64,
        interval: 1,
        use_dma: false,
    },
    EndpointProperties {
        ep_type: EndpointType::Interrupt,
        ep_direction: EndpointDirection::Out,
        max_packet_len: 64,
        interval: 1,
        use_dma: false,
    },
];

// --- Setup responder -------------------------------------------------------

/// Responds to WebUSB's vendor control request for the URL descriptor.
/// No landing page (`iLandingPage = 0`) so the URL descriptor is empty;
/// returning a clean 3-byte ack avoids the STALL that shows up in host
/// system logs.
#[derive(Default)]
struct SetupResponder;

impl ServerMessages for SetupResponder {
    const NAME: &'static str = "";

    fn messages() -> &'static [server::MessageDef<Self>] {
        use server::MessageId;
        &[(SetupPacketCallback::ID, server::handle_blocking_archive_message::<SetupPacketCallback, _>)]
    }
}
impl Server for SetupResponder {}

impl BlockingArchiveHandler<SetupPacketCallback> for SetupResponder {
    fn handle(
        &mut self,
        SetupPacketCallback(msg): SetupPacketCallback,
        _sender: xous::PID,
        _ctx: &mut ServerContext<Self>,
    ) -> Option<Vec<u8>> {
        // bmRequestType=0xC0 (vendor, device, IN),
        // bRequest=WEBUSB_VENDOR_CODE,
        // wIndex=2 (URL descriptor index).
        if msg.request_type == 0xc0 && msg.request == WEBUSB_VENDOR_CODE && msg.index == 2 {
            // bLength=3, bDescriptorType=3 (WEBUSB_URL), bScheme=0xff
            // (no scheme prefix), zero URL bytes.
            return Some(vec![3, 3, 0xff]);
        }
        None
    }
}

// --- Transport loop --------------------------------------------------------

pub async fn serve<M: MasterKeySource + Send + Sync + 'static>(
    engine: Arc<Engine<M>>,
    _unused_bind: &str,
) -> anyhow::Result<()> {
    serve_blocking(engine)
}

fn serve_blocking<M: MasterKeySource + Send + Sync + 'static>(engine: Arc<Engine<M>>) -> anyhow::Result<()> {
    crate::transport::set_status("WebUSB: init");
    let mut usb = UsbDeviceEmulation::default();

    // WebUSB Platform Capability descriptor.
    // UUID per https://wicg.github.io/webusb/#webusb-platform-capability-descriptor.
    if let Err(e) = usb.register_capability(
        16, // bDescriptorType: DEVICE CAPABILITY
        5,  // bDevCapabilityType: PLATFORM
        uuid::uuid!("3408b638-09a9-47a0-8bfd-a0768815b665"),
        &[
            0x00,
            0x01, // bcdVersion: 1.00
            WEBUSB_VENDOR_CODE,
            0x00, // iLandingPage: 0 (none)
        ],
    ) {
        let msg = format!("WebUSB: register WebUSB capability failed: {e:?}");
        log::warn!("{msg}");
        crate::transport::set_status(msg);
        std::thread::park();
        return Ok(());
    }

    // Microsoft OS 2.0 Platform Capability descriptor (inert on macOS /
    // Linux; lets Windows auto-bind to WinUSB if/when a descriptor set
    // is added behind the vendor code).
    if let Err(e) = usb.register_capability(
        16,
        5,
        uuid::uuid!("d8dd60df-4589-4cc7-9cd2-659d9e648a9f"),
        &[0x00, 0x00, 0x03, 0x06, 0xb2, 0x00, 0x77, 0x00],
    ) {
        let msg = format!("WebUSB: register MS OS 2.0 capability failed: {e:?}");
        log::warn!("{msg}");
        crate::transport::set_status(msg);
        std::thread::park();
        return Ok(());
    }

    crate::transport::set_status("WebUSB: registering interface");
    let (_webusb_interface, [mut ep_in, ep_out]) = match usb.register_interface(
        UsbInterfaceConfig::new(
            WEBUSB_INTERFACE_NUMBER,
            WEBUSB_IFCE_CLASS,
            WEBUSB_IFCE_SUBCLASS,
            WEBUSB_IFCE_PROTOCOL,
            &WEBUSB_ENDPOINTS,
        )
        .with_setup_responder(Some(SetupResponder)),
    ) {
        Ok(eps) => eps,
        Err(e) => {
            let msg = format!("WebUSB: register interface failed: {e:?}");
            log::warn!("{msg}");
            crate::transport::set_status(msg);
            std::thread::park();
            return Ok(());
        }
    };

    let ep_out_num = ep_out.endpoint_number();
    let ep_in_num = ep_in.endpoint_number();
    log::info!("nostr-signer webusb endpoints registered (out={ep_out_num}, in={ep_in_num})");

    // Force a short device-side reset once the interface is added, so
    // the host re-enumerates and picks up the new vendor-class interface
    // (descriptors registered at runtime aren't visible to the host
    // until it re-enumerates).
    crate::transport::set_status("WebUSB: resetting USB");
    usb.reset_controller();

    crate::transport::set_status(format!("WebUSB ready (EP out={ep_out_num}, in={ep_in_num})"));

    let (payload_tx, payload_rx) = mpsc::channel::<Vec<u8>>();

    std::thread::spawn(move || reader_loop(ep_out, ep_out_num, ep_in_num, payload_tx));

    // Dispatcher + writer fused on the same thread. The Nostr Signer
    // protocol is strictly single-flight (one request, one response),
    // and serialising the write inline avoids the mpsc-over-IPC hop
    // that proved flaky on the older CDC transport.
    let usb_api = UsbDeviceEmulation::default();
    let mut write_buf = xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W)
        .map_err(|e| anyhow::anyhow!("webusb map write buf: {e:?}"))?;

    while let Ok(payload) = payload_rx.recv() {
        log::trace!("webusb dispatcher: got {} byte payload", payload.len());
        let response = slint_keyos_platform::futures_lite::future::block_on(dispatch(&engine, &payload));
        let mut response_bytes = match serde_json::to_vec(&response) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("webusb serialise response: {e}");
                continue;
            }
        };
        response_bytes.push(b'\n');
        log::trace!("webusb dispatcher: writing {} bytes to EP IN", response_bytes.len());
        for chunk in response_bytes.chunks(64) {
            write_buf.as_slice_mut::<u8>()[..chunk.len()].copy_from_slice(chunk);
            match ep_in.write_buf(write_buf, chunk.len()) {
                Ok(_) => {}
                Err(usb::error::UsbError::HostDisconnected) => {
                    log::info!("webusb writer: host disconnected — waiting for reconnection");
                    if let Err(e) = usb_api.wait_for_connection() {
                        log::warn!("webusb wait_for_connection: {e:?}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => log::warn!("webusb write_buf: {e:?}"),
            }
        }
    }
    Ok(())
}

fn reader_loop(
    mut ep_out: UsbEmulatedEndpoint,
    ep_out_num: u8,
    ep_in_num: u8,
    payload_tx: mpsc::Sender<Vec<u8>>,
) {
    let usb_api = UsbDeviceEmulation::default();
    let read_buf = match xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W) {
        Ok(b) => b,
        Err(e) => {
            log::error!("webusb reader: map read buf: {e:?}");
            return;
        }
    };
    let mut line = Vec::<u8>::new();
    loop {
        let got = match ep_out.read_buf(read_buf, 64) {
            Ok(n) => n,
            Err(usb::error::UsbError::HostDisconnected) => {
                log::info!("webusb: host disconnected, waiting for reconnection");
                crate::transport::set_status("WebUSB: waiting for host");
                line.clear();
                if let Err(e) = usb_api.wait_for_connection() {
                    log::warn!("webusb wait_for_connection: {e:?}");
                }
                crate::transport::set_status(format!("WebUSB ready (EP out={ep_out_num}, in={ep_in_num})"));
                continue;
            }
            Err(e) => {
                log::warn!("webusb read_buf: {e:?}");
                continue;
            }
        };
        if got == 0 {
            continue;
        }
        let chunk = &read_buf.as_slice::<u8>()[..got];
        for &b in chunk {
            if b == b'\n' {
                if line.is_empty() {
                    continue;
                }
                let payload = std::mem::take(&mut line);
                if payload_tx.send(payload).is_err() {
                    log::warn!("webusb dispatcher gone, reader exiting");
                    return;
                }
            } else if b != b'\r' {
                if line.len() >= MAX_LINE_BYTES {
                    log::warn!("webusb: line exceeded {MAX_LINE_BYTES} bytes, dropping");
                    line.clear();
                    continue;
                }
                line.push(b);
            }
        }
    }
}

async fn dispatch<M: MasterKeySource + Send + Sync + 'static>(
    engine: &Engine<M>,
    payload: &[u8],
) -> Response {
    let req: Request = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            let id = serde_json::from_slice::<serde_json::Value>(payload)
                .ok()
                .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "0".to_string());
            log::warn!("webusb parse error id={id}: {e}");
            return Response::err(id, ErrorCode::InvalidRequest, format!("bad json: {e}"));
        }
    };
    log::info!("webusb → {} (id={})", method_name(&req), req.id);
    engine.handle(req).await
}

fn method_name(req: &Request) -> &'static str {
    use protocol::message::Method;
    match req.method {
        Method::Ping => "ping",
        Method::ListKeys => "list_keys",
        Method::SelectKey(_) => "select_key",
        Method::GetPublicKey => "get_public_key",
        Method::SignEvent(_) => "sign_event",
        Method::Nip04Encrypt(_) => "nip04_encrypt",
        Method::Nip04Decrypt(_) => "nip04_decrypt",
        Method::Nip44Encrypt(_) => "nip44_encrypt",
        Method::Nip44Decrypt(_) => "nip44_decrypt",
    }
}
