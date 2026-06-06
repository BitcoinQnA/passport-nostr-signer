// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! User-approval abstraction. The engine delegates every "does the user
//! allow this?" decision to an [`Approver`]. Inside the KeyOS simulator we
//! wire up a Slint-backed approver that navigates to the on-device
//! approval screen and waits for the physical button tap.

use std::sync::Arc;

use async_trait::async_trait;

#[derive(Debug, Clone)]
pub enum ApprovalRequest {
    SignEvent {
        origin: Option<String>,
        key_label: String,
        npub_hex: String,
        kind: u32,
        content_preview: String,
        tag_count: usize,
    },
    Nip04Encrypt {
        origin: Option<String>,
        key_label: String,
        peer_pubkey_hex: String,
        plaintext_preview: String,
    },
    Nip44Encrypt {
        origin: Option<String>,
        key_label: String,
        peer_pubkey_hex: String,
        plaintext_preview: String,
    },
    Nip04Decrypt {
        origin: Option<String>,
        key_label: String,
        peer_pubkey_hex: String,
        ciphertext_preview: String,
    },
    Nip44Decrypt {
        origin: Option<String>,
        key_label: String,
        peer_pubkey_hex: String,
        ciphertext_preview: String,
    },
}

impl ApprovalRequest {
    #[allow(dead_code)]
    pub fn origin(&self) -> Option<&str> {
        match self {
            Self::SignEvent { origin, .. }
            | Self::Nip04Encrypt { origin, .. }
            | Self::Nip44Encrypt { origin, .. }
            | Self::Nip04Decrypt { origin, .. }
            | Self::Nip44Decrypt { origin, .. } => origin.as_deref(),
        }
    }

    pub fn action(&self) -> &'static str {
        match self {
            Self::SignEvent { .. } => "sign_event",
            Self::Nip04Encrypt { .. } => "nip04_encrypt",
            Self::Nip44Encrypt { .. } => "nip44_encrypt",
            Self::Nip04Decrypt { .. } => "nip04_decrypt",
            Self::Nip44Decrypt { .. } => "nip44_decrypt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[async_trait]
pub trait Approver: Send + Sync {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision;
}

pub type ArcApprover = Arc<dyn Approver>;
