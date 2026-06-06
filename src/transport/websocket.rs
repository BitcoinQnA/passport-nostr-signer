// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket transport for the hosted-mode simulator. One text frame = one
//! JSON message. The production hardware uses USB-HID instead (see
//! `usb_hid.rs`).

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use keystore::MasterKeySource;
use protocol::{ErrorCode, Request, Response};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use crate::engine::Engine;

pub async fn serve<M: MasterKeySource + Send + Sync + 'static>(
    engine: Arc<Engine<M>>,
    bind: &str,
) -> anyhow::Result<()> {
    crate::transport::set_status(format!("ws://{bind} binding…"));
    let listener = match TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            crate::transport::set_status(format!("ws://{bind} bind failed: {e}"));
            return Err(e.into());
        }
    };
    crate::transport::set_status(format!("ws://{bind} ready"));
    log::info!("nostr-signer ws listening on {bind}");
    loop {
        let (stream, addr) = listener.accept().await?;
        let engine = engine.clone();
        tokio::spawn(async move {
            log::info!("nostr-signer ws client connected from {addr}");
            if let Err(e) = handle_client(engine, stream).await {
                log::info!("nostr-signer ws client {addr} disconnected: {e}");
            }
        });
    }
}

async fn handle_client<M: MasterKeySource + Send + Sync + 'static>(
    engine: Arc<Engine<M>>,
    stream: tokio::net::TcpStream,
) -> anyhow::Result<()> {
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut sink, mut source) = ws.split();
    while let Some(msg) = source.next().await {
        let msg = msg?;
        match msg {
            Message::Text(text) => {
                let response = dispatch_text(&engine, &text).await;
                sink.send(Message::Text(serde_json::to_string(&response)?))
                    .await?;
            }
            Message::Binary(_) => {
                let err = Response::err(
                    "0".to_string(),
                    ErrorCode::InvalidRequest,
                    "binary frames not supported; send JSON text",
                );
                sink.send(Message::Text(serde_json::to_string(&err)?))
                    .await?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
}

async fn dispatch_text<M: MasterKeySource + Send + Sync + 'static>(
    engine: &Engine<M>,
    text: &str,
) -> Response {
    let req: Request = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(e) => {
            let id = serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "0".to_string());
            log::warn!("parse error on request id={id}: {e}");
            return Response::err(id, ErrorCode::InvalidRequest, format!("bad json: {e}"));
        }
    };
    log::info!("→ {} (id={})", method_name(&req), req.id);
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
