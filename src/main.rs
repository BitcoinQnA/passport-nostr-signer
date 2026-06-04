// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

mod approval;
mod engine;
mod master_key;
mod transport;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use async_trait::async_trait;
use keystore::Keystore;
use nostr_core::{PublicKey, SecretKey};
use slint_keyos_platform::{
    app,
    gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult},
    navigation::open_qr_scanner,
    slint::{ComponentHandle, ModelRc, VecModel},
};

use crate::master_key::KeyOsAppSeedSource;

// Gives us a `Security` type alias inside this module, distinct from the
// one `master_key.rs` uses.
security::use_api!();

use crate::{
    approval::{ApprovalDecision, ApprovalRequest, Approver, ArcApprover},
    engine::{Engine, EngineConfig},
};

app!("Nostr Signer");

const WS_BIND: &str = "127.0.0.1:9876";
#[allow(dead_code)]
const DATA_SUBDIR: &str = ".passport-nostr-signer-keyos";

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Starting Nostr Signer");

    let data_dir = data_dir();
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log::error!("cannot create data dir {}: {e}", data_dir.display());
    }
    let keys_path = data_dir.join("keys.json");

    // Auto-seed a dev key on first launch so the UI has something to show.
    let keystore = match ensure_dev_keystore(&keys_path) {
        Ok(k) => Arc::new(Mutex::new(k)),
        Err(e) => {
            log::error!("keystore init failed: {e}");
            ui.global::<Callbacks>().set_server_status(format!("keystore init error: {e}").into());
            ui.run().expect("UI running");
            return;
        }
    };

    // Shared slot for the currently-selected identity (hex uuid).
    // We mirror this in the engine + UI + persisted file.
    let selected_path = data_dir.join("selected.txt");

    // Shared slot for the currently-awaiting approval decision.
    let pending_tx: Arc<Mutex<Option<oneshot::Sender<ApprovalDecision>>>> =
        Arc::new(Mutex::new(None));

    // Wire UI → Rust
    {
        let pending_tx = pending_tx.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_approve(move || {
            if let Some(tx) = pending_tx.lock().unwrap().take() {
                let _ = tx.send(ApprovalDecision::Approve);
            }
            clear_approval(&weak);
        });
    }
    {
        let pending_tx = pending_tx.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_reject(move || {
            if let Some(tx) = pending_tx.lock().unwrap().take() {
                let _ = tx.send(ApprovalDecision::Reject);
            }
            clear_approval(&weak);
        });
    }

    // Approver plugged into the engine.
    let approver: ArcApprover = Arc::new(SlintApprover {
        ui_weak: ui.as_weak(),
        pending_tx: pending_tx.clone(),
    });

    let engine = Arc::new(Engine::new(keystore, approver, EngineConfig::default()));

    // Populate the UI keys model + restore the previously-selected identity.
    refresh_keys_ui(&ui, &engine);
    if let Ok(prev) = std::fs::read_to_string(&selected_path) {
        if let Ok(bytes) = hex::decode(prev.trim()) {
            if bytes.len() == 16 {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&bytes);
                if engine.select(uuid) {
                    ui.global::<Callbacks>().set_selected_uuid(prev.trim().to_string().into());
                }
            }
        }
    }
    // If nothing restored, default to the first key.
    if engine.selected().is_none() {
        if let Some((uuid_hex, _, _, _, _)) = engine.key_list().into_iter().next() {
            if let Ok(bytes) = hex::decode(&uuid_hex) {
                if bytes.len() == 16 {
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&bytes);
                    if engine.select(uuid) {
                        ui.global::<Callbacks>().set_selected_uuid(uuid_hex.clone().into());
                        let _ = std::fs::write(&selected_path, &uuid_hex);
                    }
                }
            }
        }
    }

    // UI select-key callback.
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        let selected_path = selected_path.clone();
        ui.global::<Callbacks>().on_select_key(move |uuid_hex| {
            if let Ok(bytes) = hex::decode(uuid_hex.as_str()) {
                if bytes.len() == 16 {
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&bytes);
                    if engine.select(uuid) {
                        if let Some(ui) = weak.upgrade() {
                            ui.global::<Callbacks>()
                                .set_selected_uuid(uuid_hex.as_str().to_string().into());
                        }
                        let _ = std::fs::write(&selected_path, uuid_hex.as_str());
                        log::info!("selected key {uuid_hex}");
                    } else {
                        log::warn!("select_key: uuid not found in keystore");
                    }
                }
            }
        });
    }

    // Live label validation. The Slint side calls this on every edit; we
    // still re-validate on save before mutating state.
    ui.global::<Callbacks>().on_validate_label(move |text| {
        validate_label(text.as_str()).unwrap_or_default().into()
    });

    // Create a new identity. `method` is "generate" or "qr".
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        let selected_path = selected_path.clone();
        ui.global::<Callbacks>().on_save_new(move |label, color, method, account| {
            let Some(ui) = weak.upgrade() else { return };
            let label = label.as_str().trim().to_string();
            if let Some(err) = validate_label(&label) {
                ui.global::<Callbacks>().set_editing_error(err.into());
                return;
            }
            let color_u8 = color.clamp(0, 255) as u8;

            let method = method.as_str();
            let sk = match method {
                "generate" => match derive_nostr_from_device_seed(account.max(0) as u32) {
                    Ok(sk) => sk,
                    Err(e) => {
                        log::warn!("generate failed: {e}");
                        ui.global::<Callbacks>().set_editing_error(format!("{e}").into());
                        return;
                    }
                },
                "qr" => {
                    let scanned = match scan_nsec_via_qr() {
                        Ok(Some(s)) => s,
                        Ok(None) => return, // cancelled
                        Err(e) => {
                            log::warn!("qr scan failed: {e}");
                            ui.global::<Callbacks>().set_editing_error(format!("{e}").into());
                            return;
                        }
                    };
                    match parse_nsec_or_hex(&scanned) {
                        Ok(sk) => sk,
                        Err(msg) => {
                            ui.global::<Callbacks>().set_editing_error(msg.into());
                            return;
                        }
                    }
                }
                other => {
                    log::warn!("unknown save-new method: {other}");
                    return;
                }
            };

            match engine.add_key(label, &sk, color_u8) {
                Ok(uuid_hex) => {
                    refresh_keys_ui(&ui, &engine);
                    let _ = std::fs::write(&selected_path, &uuid_hex);
                    ui.global::<Callbacks>().set_selected_uuid(uuid_hex.into());
                    ui.global::<Callbacks>().set_editing_error("".into());
                    ui.global::<Navigate>().invoke_backward();
                }
                Err(e) => {
                    ui.global::<Callbacks>().set_editing_error(e.to_string().into());
                }
            }
        });
    }

    // Save edits to an existing identity.
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_edit_save(move |uuid_hex, new_label, new_color| {
            let Some(ui) = weak.upgrade() else { return };
            let label = new_label.as_str().trim().to_string();
            if let Some(err) = validate_label(&label) {
                ui.global::<Callbacks>().set_editing_error(err.into());
                return;
            }
            let uuid = match parse_uuid_arg(uuid_hex.as_str()) {
                Some(u) => u,
                None => {
                    ui.global::<Callbacks>().set_editing_error("Bad uuid.".into());
                    return;
                }
            };
            let color_u8 = new_color.clamp(0, 255) as u8;
            if let Err(e) = engine.rename(&uuid, label) {
                ui.global::<Callbacks>().set_editing_error(e.to_string().into());
                return;
            }
            if let Err(e) = engine.set_color(&uuid, color_u8) {
                ui.global::<Callbacks>().set_editing_error(e.to_string().into());
                return;
            }
            refresh_keys_ui(&ui, &engine);
            ui.global::<Callbacks>().set_editing_error("".into());
            ui.global::<Navigate>().invoke_backward();
        });
    }

    // Archive a key.
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_archive(move |uuid_hex| {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(uuid) = parse_uuid_arg(uuid_hex.as_str()) {
                if let Err(e) = engine.set_archived(&uuid, true) {
                    log::warn!("archive failed: {e}");
                    return;
                }
                // If this was the active key, clear selection.
                if engine.selected() == Some(uuid) {
                    ui.global::<Callbacks>().set_selected_uuid("".into());
                }
                refresh_keys_ui(&ui, &engine);
            }
        });
    }

    // Restore an archived key.
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_restore(move |uuid_hex| {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(uuid) = parse_uuid_arg(uuid_hex.as_str()) {
                if let Err(e) = engine.set_archived(&uuid, false) {
                    log::warn!("restore failed: {e}");
                    return;
                }
                refresh_keys_ui(&ui, &engine);
            }
        });
    }

    // Reveal an nsec on demand (gated by the on-device confirmation modal
    // in Slint).
    {
        let engine = engine.clone();
        ui.global::<Callbacks>().on_reveal_nsec(move |uuid_hex| {
            let Some(uuid) = parse_uuid_arg(uuid_hex.as_str()) else {
                return "".into();
            };
            match engine.reveal_nsec(&uuid) {
                Ok(s) => s.into(),
                Err(e) => {
                    log::warn!("reveal_nsec failed: {e}");
                    "".into()
                }
            }
        });
    }

    // Permanently delete an archived key.
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        let selected_path = selected_path.clone();
        ui.global::<Callbacks>().on_delete_forever(move |uuid_hex| {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(uuid) = parse_uuid_arg(uuid_hex.as_str()) {
                let was_selected = engine.selected() == Some(uuid);
                if let Err(e) = engine.delete(&uuid) {
                    log::warn!("delete failed: {e}");
                    return;
                }
                if was_selected {
                    ui.global::<Callbacks>().set_selected_uuid("".into());
                    let _ = std::fs::remove_file(&selected_path);
                }
                refresh_keys_ui(&ui, &engine);
            }
        });
    }

    // Spawn the transport worker. On hosted (macOS) we drive it from a
    // tokio runtime. On hardware (Xous) we block on futures_lite. Both
    // paths call the same `transport::serve()` and hand back to the same
    // engine.
    let engine_for_server = engine.clone();
    let weak_for_status = ui.as_weak();
    thread::Builder::new()
        .name("nostr-signer-transport".into())
        .spawn(move || run_transport(engine_for_server, weak_for_status))
        .expect("spawn nostr-signer-transport thread");

    // Poll the transport's shared status string and mirror it to the UI
    // banner. Replaces the old optimistic one-shot timer; now the banner
    // reflects real state transitions (registering, EP assignment, errors).
    let weak_for_ready = ui.as_weak();
    let status_timer = slint_keyos_platform::slint::Timer::default();
    let mut last_shown = String::new();
    status_timer.start(
        slint_keyos_platform::slint::TimerMode::Repeated,
        Duration::from_millis(500),
        move || {
            let current = transport::status()
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            if current != last_shown {
                last_shown = current.clone();
                if let Some(ui) = weak_for_ready.upgrade() {
                    ui.global::<Callbacks>().set_server_status(current.into());
                }
            }
        },
    );
    // Hold on to the timer so it isn't dropped.
    std::mem::forget(status_timer);

    ui.run().expect("UI running");
}

// ---------------------------------------------------------------------------
// SlintApprover: awaits the user's on-device tap and resolves the engine.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "xous"))]
fn run_transport(
    engine: std::sync::Arc<Engine<KeyOsAppSeedSource>>,
    weak_for_status: slint_keyos_platform::slint::Weak<AppWindow>,
) {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("tokio runtime build failed: {e}");
            return;
        }
    };
    rt.block_on(async move {
        match transport::serve(engine, WS_BIND).await {
            Ok(()) => {}
            Err(e) => {
                log::error!("ws server exited: {e}");
                let msg = format!("ws error: {e}");
                let _ = slint_keyos_platform::slint::invoke_from_event_loop(move || {
                    if let Some(ui) = weak_for_status.upgrade() {
                        ui.global::<Callbacks>().set_server_status(msg.into());
                    }
                });
            }
        }
    });
}

#[cfg(target_os = "xous")]
fn run_transport(
    engine: std::sync::Arc<Engine<KeyOsAppSeedSource>>,
    weak_for_status: slint_keyos_platform::slint::Weak<AppWindow>,
) {
    use slint_keyos_platform::futures_lite::future::block_on;
    match block_on(transport::serve(engine, WS_BIND)) {
        Ok(()) => {}
        Err(e) => {
            log::error!("usb-hid transport exited: {e}");
            let msg = format!("usb error: {e}");
            let _ = slint_keyos_platform::slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak_for_status.upgrade() {
                    ui.global::<Callbacks>().set_server_status(msg.into());
                }
            });
        }
    }
}

struct SlintApprover {
    ui_weak: slint_keyos_platform::slint::Weak<AppWindow>,
    pending_tx: Arc<Mutex<Option<oneshot::Sender<ApprovalDecision>>>>,
}

#[async_trait]
impl Approver for SlintApprover {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        let (tx, rx) = oneshot::channel();

        // Park the tx for the UI thread to drain when the user taps.
        *self.pending_tx.lock().unwrap() = Some(tx);

        let weak = self.ui_weak.clone();
        let req_for_ui = req.clone();
        let scheduled = slint_keyos_platform::slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                populate_approval(&ui, &req_for_ui);
                ui.global::<Navigate>().invoke_approve_page(NavigateOptions::default());
            }
        });
        if scheduled.is_err() {
            // Event loop gone; revoke the parked tx and reject.
            *self.pending_tx.lock().unwrap() = None;
            return ApprovalDecision::Reject;
        }

        // The `oneshot` crate's receiver is a plain blocking/polling type;
        // wrap it in a future so we can await inside async contexts on
        // both tokio (hosted) and futures_lite (hardware).
        OneshotFuture::new(rx).await
    }
}

struct OneshotFuture<T> {
    rx: oneshot::Receiver<T>,
}

impl<T> OneshotFuture<T> {
    fn new(rx: oneshot::Receiver<T>) -> Self { Self { rx } }
}

impl<T> core::future::Future for OneshotFuture<T> {
    type Output = T;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<T> {
        match self.rx.try_recv() {
            Ok(v) => core::task::Poll::Ready(v),
            Err(oneshot::TryRecvError::Empty) => {
                // Wake ourselves shortly. Not ideal, but portable — and
                // approval requests are user-driven so the wake latency
                // doesn't matter.
                let waker = cx.waker().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    waker.wake();
                });
                core::task::Poll::Pending
            }
            Err(oneshot::TryRecvError::Disconnected) => {
                // Sender dropped — treat as reject. This is generic T so
                // we can't materialise a Reject here; callers that wrap
                // ApprovalDecision should handle via their own default.
                // Polling again won't change; yield a Pending that never
                // resolves would leak — but we only use this with
                // ApprovalDecision whose default we set in the caller.
                core::task::Poll::Ready(panic_on_disconnect::<T>())
            }
        }
    }
}

fn panic_on_disconnect<T>() -> T {
    // The SlintApprover always holds the sender alive until the UI fires,
    // so reaching this would be a bug. Panic rather than ignore.
    panic!("approver oneshot sender dropped without firing")
}

fn populate_approval(ui: &AppWindow, req: &ApprovalRequest) {
    let (origin, key_label, key_short, kind, kind_label, tag_count, content) = match req {
        ApprovalRequest::SignEvent {
            origin,
            key_label,
            npub_hex,
            kind,
            content_preview,
            tag_count,
        } => (
            origin.clone().unwrap_or_default(),
            key_label.clone(),
            short_hex(npub_hex),
            *kind as i32,
            kind_friendly(*kind).to_string(),
            *tag_count as i32,
            content_preview.clone(),
        ),
        ApprovalRequest::Nip04Encrypt {
            origin,
            key_label,
            peer_pubkey_hex,
            plaintext_preview,
        } => (
            origin.clone().unwrap_or_default(),
            key_label.clone(),
            short_hex(peer_pubkey_hex),
            0,
            "NIP-04 encrypt".into(),
            0,
            plaintext_preview.clone(),
        ),
        ApprovalRequest::Nip44Encrypt {
            origin,
            key_label,
            peer_pubkey_hex,
            plaintext_preview,
        } => (
            origin.clone().unwrap_or_default(),
            key_label.clone(),
            short_hex(peer_pubkey_hex),
            0,
            "NIP-44 encrypt".into(),
            0,
            plaintext_preview.clone(),
        ),
    };
    let state = ApprovalState {
        active: true,
        action: req.action().into(),
        origin: origin.into(),
        key_label: key_label.into(),
        key_short: key_short.into(),
        kind,
        kind_label: kind_label.into(),
        tag_count,
        content_preview: content.into(),
    };
    ui.global::<Callbacks>().set_approval(state);
}

fn refresh_keys_ui<M: keystore::MasterKeySource>(ui: &AppWindow, engine: &Engine<M>) {
    let rows = engine.key_list();
    let mut live = 0i32;
    let mut archived = 0i32;
    let keys: Vec<StoredKey> = rows
        .into_iter()
        .map(|(uuid, label, npub_hex, color, is_archived)| {
            if is_archived {
                archived += 1;
            } else {
                live += 1;
            }
            let npub_full = match PublicKey::from_hex(&npub_hex)
                .and_then(|pk| nostr_core::bech32::encode_npub(&pk))
            {
                Ok(s) => s,
                Err(_) => npub_hex.clone(),
            };
            StoredKey {
                uuid: uuid.into(),
                label: label.into(),
                npub_short: short_hex(&npub_hex).into(),
                npub_full: npub_full.into(),
                color: color as i32,
                archived: is_archived,
            }
        })
        .collect();
    let model = ModelRc::new(VecModel::from(keys));
    ui.global::<Callbacks>().set_keys(model);
    ui.global::<Callbacks>().set_live_count(live);
    ui.global::<Callbacks>().set_archived_count(archived);
}

fn validate_label(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Some("Give this key a label.".into());
    }
    if trimmed.chars().count() > 40 {
        return Some("Label is too long (40 characters max).".into());
    }
    None
}

fn parse_uuid_arg(s: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn clear_approval(ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
    if let Some(ui) = ui_weak.upgrade() {
        let mut s = ui.global::<Callbacks>().get_approval();
        s.active = false;
        ui.global::<Callbacks>().set_approval(s);
    }
}

// ---------------------------------------------------------------------------
// Keystore bootstrap
// ---------------------------------------------------------------------------

fn ensure_dev_keystore(keys: &std::path::Path) -> anyhow::Result<Keystore<KeyOsAppSeedSource>> {
    // Load whatever the user has on-device. First boot lands them on the
    // empty-state UI, which prompts them to create their first key.
    Ok(keystore::load(KeyOsAppSeedSource, keys)?)
}

#[cfg(not(target_os = "xous"))]
fn data_dir() -> PathBuf {
    dirs::home_dir().map(|h| h.join(DATA_SUBDIR)).unwrap_or_else(|| {
        let mut p = std::env::temp_dir();
        p.push(DATA_SUBDIR);
        p
    })
}

#[cfg(target_os = "xous")]
fn data_dir() -> PathBuf {
    // On Xous the fs server mounts user-writable storage; apps address
    // their own sandboxed area by name. The keystore uses std::fs
    // through KeyOS's stdlib shim.
    PathBuf::from(concat!("/data/", env!("CARGO_PKG_NAME")))
}

// ---------------------------------------------------------------------------
// Presentation helpers
// ---------------------------------------------------------------------------

fn short_hex(h: &str) -> String {
    if h.len() > 16 {
        format!("{}…{}", &h[..8], &h[h.len() - 8..])
    } else {
        h.to_string()
    }
}

fn derive_nostr_from_device_seed(account: u32) -> anyhow::Result<SecretKey> {
    let security = Security::default();
    let seed = security
        .seed()
        .map_err(|_| anyhow::anyhow!("access denied to device seed (is the device set up?)"))?
        .ok_or_else(|| anyhow::anyhow!("no seed on this device"))?;
    let mnemonic = bip39::Mnemonic::from_entropy(seed.bytes())
        .map_err(|e| anyhow::anyhow!("seed → mnemonic: {e}"))?;
    let sk = nostr_core::nip06::derive(&mnemonic.to_string(), "", account)
        .map_err(|e| anyhow::anyhow!("nip06 derive: {e}"))?;
    Ok(sk)
}

fn scan_nsec_via_qr() -> anyhow::Result<Option<String>> {
    let options = ScanQrOptions {
        header_title: "Scan nsec".into(),
        message: "Show the signer your nsec QR code".into(),
        ..ScanQrOptions::default()
    };
    let result = open_qr_scanner::<gui_permissions::GuiPermissions>(options)
        .map_err(|e| anyhow::anyhow!("open_qr_scanner: {e:?}"))?;
    let Some(result) = result else {
        return Ok(None);
    };
    match result {
        ScanQrResult::Qr(data) => {
            let s = std::str::from_utf8(&data)
                .map_err(|e| anyhow::anyhow!("qr payload not utf-8: {e}"))?
                .trim()
                .to_string();
            Ok(Some(s))
        }
        ScanQrResult::Ur2(_, _) => {
            // UR2 isn't used for nsec; surface an empty result so the UI
            // doesn't think the scan succeeded with junk.
            Ok(None)
        }
        ScanQrResult::LeftClicked | ScanQrResult::RightClicked | ScanQrResult::ButtonClicked => {
            Ok(None)
        }
    }
}

fn parse_nsec_or_hex(s: &str) -> Result<SecretKey, String> {
    if s.is_empty() {
        return Err("Secret is required.".into());
    }
    if s.starts_with("nsec1") {
        nostr_core::bech32::decode_nsec(s).map_err(|e| format!("Bad nsec1: {e}"))
    } else if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        SecretKey::from_hex(s).map_err(|e| format!("Bad hex: {e}"))
    } else {
        Err("Expected nsec1… or a 64-char hex secret.".into())
    }
}

fn kind_friendly(k: u32) -> &'static str {
    match k {
        0 => "profile metadata",
        1 => "text note",
        3 => "follow list",
        4 => "legacy DM",
        5 => "deletion",
        6 => "repost",
        7 => "reaction",
        20 => "picture post",
        1111 => "comment",
        9734 => "zap request",
        9735 => "zap receipt",
        30023 => "long-form article",
        _ => "custom kind",
    }
}
