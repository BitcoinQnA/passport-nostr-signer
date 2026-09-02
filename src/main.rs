// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

mod approval;
mod autosign;
mod engine;
mod master_key;
mod transport;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use keystore::{Keystore, MasterKeySource};
use nostr_core::{PublicKey, SecretKey};
use slint_keyos_platform::{
    app_ui2,
    gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult},
    navigation::open_qr_scanner,
    slint::{ComponentHandle, ModelRc, VecModel},
};

use crate::master_key::KeyOsAppSeedSource;

use crate::{
    approval::{ApprovalDecision, ApprovalRequest, Approver, ArcApprover},
    engine::{Engine, EngineConfig},
};

app_ui2!("Nostr Signer");

const WS_BIND: &str = "127.0.0.1:9876";
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[allow(dead_code)]
const DATA_SUBDIR: &str = ".passport-nostr-signer-keyos";

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Starting Nostr Signer");

    ui.global::<Utils>()
        .on_qrcode(slint_keyos_platform::qrcode::render);

    let data_dir = data_dir();
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log::error!("cannot create data dir {}: {e}", data_dir.display());
    }
    let keys_path = data_dir.join("keys.json");
    let autosign_path = data_dir.join("autosign.json");
    let autosign_mac_key = autosign_mac_key();

    // Auto-seed a dev key on first launch so the UI has something to show.
    let keystore = match ensure_dev_keystore(&keys_path) {
        Ok(k) => Arc::new(Mutex::new(k)),
        Err(e) => {
            log::error!("keystore init failed: {e}");
            ui.global::<Callbacks>()
                .set_server_status(format!("keystore init error: {e}").into());
            ui.run().expect("UI running");
            return;
        }
    };

    let autosign = match autosign_mac_key.as_ref() {
        Some(mac_key) => match autosign::load(&autosign_path, mac_key) {
            Ok(store) => Arc::new(Mutex::new(store)),
            Err(e) => {
                log::warn!("auto-sign policy load failed; starting with no policies: {e}");
                Arc::new(Mutex::new(autosign::AutoSignStore::default()))
            }
        },
        None => {
            log::warn!("auto-sign unavailable: app seed could not be read");
            Arc::new(Mutex::new(autosign::AutoSignStore::default()))
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

    let engine = Arc::new(Engine::new(
        keystore,
        keys_path.clone(),
        autosign,
        autosign_path.clone(),
        autosign_mac_key,
        approver,
        EngineConfig::default(),
    ));

    // Populate the UI keys model + restore the previously-selected identity.
    refresh_keys_ui(&ui, &engine);
    if let Ok(prev) = std::fs::read_to_string(&selected_path) {
        if let Ok(bytes) = hex::decode(prev.trim()) {
            if bytes.len() == 16 {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&bytes);
                if engine.select(uuid) {
                    ui.global::<Callbacks>()
                        .set_selected_uuid(prev.trim().to_string().into());
                }
            }
        }
    }
    // If nothing restored, default to the first key.
    if engine.selected().is_none() {
        if let Some((uuid_hex, _, _, _, _)) = engine
            .key_list()
            .into_iter()
            .find(|(_, _, _, _, archived)| !archived)
        {
            if let Ok(bytes) = hex::decode(&uuid_hex) {
                if bytes.len() == 16 {
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&bytes);
                    if engine.select(uuid) {
                        ui.global::<Callbacks>()
                            .set_selected_uuid(uuid_hex.clone().into());
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
    ui.global::<Callbacks>()
        .on_validate_label(move |text| validate_label(text.as_str()).unwrap_or_default().into());

    // Create a new identity. `method` is "generate" or "qr".
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        let selected_path = selected_path.clone();
        ui.global::<Callbacks>()
            .on_save_new(move |label, color, method, account| {
                let Some(ui) = weak.upgrade() else { return };
                let label = label.as_str().trim().to_string();
                if let Some(err) = validate_label(&label) {
                    ui.global::<Callbacks>().set_editing_error(err.into());
                    return;
                }
                let color_u8 = color.clamp(0, 255) as u8;

                let method = method.as_str();
                let sk = match method {
                    "generate" => match derive_nostr_from_app_seed(account.max(0) as u32) {
                        Ok(sk) => sk,
                        Err(e) => {
                            log::warn!("generate failed: {e}");
                            ui.global::<Callbacks>()
                                .set_editing_error(format!("{e}").into());
                            return;
                        }
                    },
                    "qr" => {
                        let scanned = match scan_nsec_via_qr() {
                            Ok(Some(s)) => s,
                            Ok(None) => return, // cancelled
                            Err(e) => {
                                log::warn!("qr scan failed: {e}");
                                ui.global::<Callbacks>()
                                    .set_editing_error(format!("{e}").into());
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
                        ui.global::<Callbacks>()
                            .set_editing_error(e.to_string().into());
                    }
                }
            });
    }

    // Save edits to an existing identity.
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_edit_save(move |uuid_hex, new_label, new_color| {
                let Some(ui) = weak.upgrade() else { return };
                let label = new_label.as_str().trim().to_string();
                if let Some(err) = validate_label(&label) {
                    ui.global::<Callbacks>().set_editing_error(err.into());
                    return;
                }
                let uuid = match parse_uuid_arg(uuid_hex.as_str()) {
                    Some(u) => u,
                    None => {
                        ui.global::<Callbacks>()
                            .set_editing_error("Bad uuid.".into());
                        return;
                    }
                };
                let color_u8 = new_color.clamp(0, 255) as u8;
                if let Err(e) = engine.rename(&uuid, label) {
                    ui.global::<Callbacks>()
                        .set_editing_error(e.to_string().into());
                    return;
                }
                if let Err(e) = engine.set_color(&uuid, color_u8) {
                    ui.global::<Callbacks>()
                        .set_editing_error(e.to_string().into());
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
        let selected_path = selected_path.clone();
        ui.global::<Callbacks>().on_archive(move |uuid_hex| {
            let Some(ui) = weak.upgrade() else { return };
            if let Some(uuid) = parse_uuid_arg(uuid_hex.as_str()) {
                let was_selected = engine.selected() == Some(uuid);
                if let Err(e) = engine.set_archived(&uuid, true) {
                    log::warn!("archive failed: {e}");
                    return;
                }
                // If this was the active key, clear selection.
                if was_selected {
                    ui.global::<Callbacks>().set_selected_uuid("".into());
                    let _ = std::fs::remove_file(&selected_path);
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

    // Auto-sign rules are configured only from the device UI. Browser requests
    // can match them, but cannot create, relax, or delete them.
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_refresh_auto_sign_rules(move |uuid_hex| {
                let Some(ui) = weak.upgrade() else { return };
                refresh_auto_sign_ui(&ui, &engine, uuid_hex.as_str());
            });
    }
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_add_auto_sign_rule(
            move |uuid_hex, origin, kind, expiry_hours, max_per_hour| {
                let Some(ui) = weak.upgrade() else { return };
                let Some(uuid) = parse_uuid_arg(uuid_hex.as_str()) else {
                    ui.global::<Callbacks>()
                        .set_auto_sign_error("Bad key uuid.".into());
                    return;
                };
                let kind = match ui_u32(kind, "Kind", 0, i32::MAX as u32) {
                    Ok(v) => v,
                    Err(e) => {
                        ui.global::<Callbacks>().set_auto_sign_error(e.into());
                        return;
                    }
                };
                let expiry_hours = match ui_u32(expiry_hours, "Expiry hours", 0, 24 * 365) {
                    Ok(v) => v,
                    Err(e) => {
                        ui.global::<Callbacks>().set_auto_sign_error(e.into());
                        return;
                    }
                };
                let max_per_hour = match ui_u32(max_per_hour, "Max per hour", 1, 1_000) {
                    Ok(v) => v,
                    Err(e) => {
                        ui.global::<Callbacks>().set_auto_sign_error(e.into());
                        return;
                    }
                };

                match engine.add_auto_sign_rule(
                    &uuid,
                    origin.as_str().to_string(),
                    kind,
                    expiry_hours,
                    max_per_hour,
                ) {
                    Ok(()) => {
                        ui.global::<Callbacks>().set_auto_sign_error("".into());
                        refresh_auto_sign_ui(&ui, &engine, uuid_hex.as_str());
                    }
                    Err(e) => {
                        ui.global::<Callbacks>().set_auto_sign_error(e.into());
                    }
                }
            },
        );
    }
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_delete_auto_sign_rule(move |uuid_hex, rule_id_hex| {
                let Some(ui) = weak.upgrade() else { return };
                let Some(rule_id) = parse_uuid_arg(rule_id_hex.as_str()) else {
                    ui.global::<Callbacks>()
                        .set_auto_sign_error("Bad auto-sign rule id.".into());
                    return;
                };
                match engine.delete_auto_sign_rule(&rule_id) {
                    Ok(()) => {
                        ui.global::<Callbacks>().set_auto_sign_error("".into());
                        refresh_auto_sign_ui(&ui, &engine, uuid_hex.as_str());
                    }
                    Err(e) => {
                        ui.global::<Callbacks>().set_auto_sign_error(e.into());
                    }
                }
            });
    }
    {
        let engine = engine.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_toggle_auto_sign_rule(move |uuid_hex, rule_id_hex, enabled| {
                let Some(ui) = weak.upgrade() else { return };
                let Some(rule_id) = parse_uuid_arg(rule_id_hex.as_str()) else {
                    ui.global::<Callbacks>()
                        .set_auto_sign_error("Bad auto-sign rule id.".into());
                    return;
                };
                match engine.set_auto_sign_enabled(&rule_id, enabled) {
                    Ok(()) => {
                        ui.global::<Callbacks>().set_auto_sign_error("".into());
                        refresh_auto_sign_ui(&ui, &engine, uuid_hex.as_str());
                    }
                    Err(e) => {
                        ui.global::<Callbacks>().set_auto_sign_error(e.into());
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

    // Hosted mode runs WebSocket; device mode reports that no public SDK host
    // transport is available.
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
            log::error!("device transport exited: {e}");
            // TODO: localize
            let msg = format!("host transport error: {e}");
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
        {
            let mut pending = self.pending_tx.lock().unwrap();
            if pending.is_some() {
                log::warn!("approval rejected: another request is already pending");
                return ApprovalDecision::Reject;
            }
            *pending = Some(tx);
        }

        let weak = self.ui_weak.clone();
        let req_for_ui = req.clone();
        let scheduled = slint_keyos_platform::slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                populate_approval(&ui, &req_for_ui);
                ui.global::<Navigate>()
                    .invoke_approve_page(NavigateOptions::default());
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
        let decision = ApprovalFuture::new(rx, APPROVAL_TIMEOUT).await;
        if decision == ApprovalDecision::Reject {
            *self.pending_tx.lock().unwrap() = None;
        }
        decision
    }
}

struct ApprovalFuture {
    rx: oneshot::Receiver<ApprovalDecision>,
    deadline: Instant,
}

impl ApprovalFuture {
    fn new(rx: oneshot::Receiver<ApprovalDecision>, timeout: Duration) -> Self {
        Self {
            rx,
            deadline: Instant::now() + timeout,
        }
    }
}

impl core::future::Future for ApprovalFuture {
    type Output = ApprovalDecision;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<ApprovalDecision> {
        let this = self.get_mut();
        match this.rx.try_recv() {
            Ok(v) => core::task::Poll::Ready(v),
            Err(oneshot::TryRecvError::Empty) => {
                let now = Instant::now();
                if now >= this.deadline {
                    log::warn!("approval timed out");
                    return core::task::Poll::Ready(ApprovalDecision::Reject);
                }
                let waker = cx.waker().clone();
                let sleep_for = (this.deadline - now).min(Duration::from_millis(50));
                std::thread::spawn(move || {
                    std::thread::sleep(sleep_for);
                    waker.wake();
                });
                core::task::Poll::Pending
            }
            Err(oneshot::TryRecvError::Disconnected) => {
                core::task::Poll::Ready(ApprovalDecision::Reject)
            }
        }
    }
}

fn populate_approval(ui: &AppWindow, req: &ApprovalRequest) {
    let (
        origin,
        key_label,
        key_short,
        peer_short,
        kind,
        kind_label,
        tag_count,
        content_label,
        content,
    ) = match req {
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
            "".to_string(),
            *kind as i32,
            kind_friendly(*kind).to_string(),
            *tag_count as i32,
            "Content".to_string(),
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
            "".to_string(),
            short_hex(peer_pubkey_hex),
            0,
            "NIP-04 encrypt".to_string(),
            0,
            "Plaintext".to_string(),
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
            "".to_string(),
            short_hex(peer_pubkey_hex),
            0,
            "NIP-44 encrypt".to_string(),
            0,
            "Plaintext".to_string(),
            plaintext_preview.clone(),
        ),
        ApprovalRequest::Nip04Decrypt {
            origin,
            key_label,
            peer_pubkey_hex,
            ciphertext_preview,
        } => (
            origin.clone().unwrap_or_default(),
            key_label.clone(),
            "".to_string(),
            short_hex(peer_pubkey_hex),
            0,
            "NIP-04 decrypt".to_string(),
            0,
            "Ciphertext".to_string(),
            ciphertext_preview.clone(),
        ),
        ApprovalRequest::Nip44Decrypt {
            origin,
            key_label,
            peer_pubkey_hex,
            ciphertext_preview,
        } => (
            origin.clone().unwrap_or_default(),
            key_label.clone(),
            "".to_string(),
            short_hex(peer_pubkey_hex),
            0,
            "NIP-44 decrypt".to_string(),
            0,
            "Ciphertext".to_string(),
            ciphertext_preview.clone(),
        ),
    };
    let state = ApprovalState {
        active: true,
        action: req.action().into(),
        origin: origin.into(),
        key_label: key_label.into(),
        key_short: key_short.into(),
        peer_short: peer_short.into(),
        kind,
        kind_label: kind_label.into(),
        tag_count,
        content_label: content_label.into(),
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

fn refresh_auto_sign_ui<M: keystore::MasterKeySource>(
    ui: &AppWindow,
    engine: &Engine<M>,
    uuid_hex: &str,
) {
    let Some(uuid) = parse_uuid_arg(uuid_hex) else {
        let model = ModelRc::new(VecModel::from(Vec::<AutoSignRuleRow>::new()));
        ui.global::<Callbacks>().set_auto_sign_rules(model);
        ui.global::<Callbacks>().set_auto_sign_rule_count(0);
        return;
    };
    let now = now_secs();
    let rows: Vec<AutoSignRuleRow> = engine
        .auto_sign_rules_for_key(&uuid)
        .into_iter()
        .map(|rule| AutoSignRuleRow {
            rule_id: hex::encode(rule.id).into(),
            origin: rule.origin.into(),
            kind: rule.kind.min(i32::MAX as u32) as i32,
            enabled: rule.enabled,
            expires_at_label: format_expiry(rule.expires_at, now).into(),
            max_per_hour: rule.max_per_hour.min(i32::MAX as u32) as i32,
            used_in_window: rule.used_in_window.min(i32::MAX as u32) as i32,
            total_uses: rule.total_uses.min(i32::MAX as u64) as i32,
            last_used_label: format_last_used(rule.last_used_at, now).into(),
        })
        .collect();
    let count = rows.len().min(i32::MAX as usize) as i32;
    let model = ModelRc::new(VecModel::from(rows));
    ui.global::<Callbacks>().set_auto_sign_rules(model);
    ui.global::<Callbacks>().set_auto_sign_rule_count(count);
}

fn ui_u32(value: i32, label: &str, min: u32, max: u32) -> Result<u32, String> {
    if value < 0 {
        return Err(format!("{label} must be at least {min}."));
    }
    let value = value as u32;
    if value < min || value > max {
        return Err(format!("{label} must be between {min} and {max}."));
    }
    Ok(value)
}

fn format_expiry(expires_at: u64, now: u64) -> String {
    if expires_at == 0 {
        "never".into()
    } else if expires_at <= now {
        "expired".into()
    } else {
        format!("in {}", human_duration(expires_at - now))
    }
}

fn format_last_used(last_used_at: u64, now: u64) -> String {
    if last_used_at == 0 {
        "never".into()
    } else if last_used_at >= now {
        "just now".into()
    } else {
        format!("{} ago", human_duration(now - last_used_at))
    }
}

fn human_duration(seconds: u64) -> String {
    let minutes = seconds / 60;
    if minutes < 1 {
        return "less than 1m".into();
    }
    if minutes < 60 {
        return format!("{minutes}m");
    }
    let hours = minutes / 60;
    if hours < 48 {
        return format!("{hours}h");
    }
    format!("{}d", hours / 24)
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn autosign_mac_key() -> Option<[u8; 32]> {
    match KeyOsAppSeedSource.app_seed() {
        Ok(seed) => Some(autosign::derive_mac_key(&seed)),
        Err(e) => {
            log::warn!("app seed unavailable for auto-sign policy MAC: {e}");
            None
        }
    }
}

#[cfg(not(target_os = "xous"))]
fn data_dir() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(DATA_SUBDIR))
        .unwrap_or_else(|| {
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

fn derive_nostr_from_app_seed(account: u32) -> anyhow::Result<SecretKey> {
    // TODO: localize
    let seed = KeyOsAppSeedSource
        .app_seed()
        .map_err(|e| anyhow::anyhow!("app key unavailable: {e}"))?;
    // TODO: localize
    let mnemonic = bip39::Mnemonic::from_entropy(&seed)
        .map_err(|e| anyhow::anyhow!("app key to mnemonic: {e}"))?;
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
        ScanQrResult::Qr { data, .. } => {
            let s = std::str::from_utf8(&data)
                .map_err(|e| anyhow::anyhow!("qr payload not utf-8: {e}"))?
                .trim()
                .to_string();
            Ok(Some(s))
        }
        ScanQrResult::Ur2 { .. } => {
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
