// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Passport Prime Nostr Signer — wire protocol.
//!
//! Two layers live in this crate:
//!   - [`message`] the JSON request/response types exchanged between the browser extension and the device
//!   - [`frame`]   HID-report chunking and reassembly for the JSON blobs
//!
//! Both are pure Rust and have no platform dependencies. See
//! `protocol/SPEC.md` for the normative spec.

pub mod frame;
pub mod message;

pub use frame::{Defragmenter, FrameError, Framer, PAYLOAD_PER_REPORT, REPORT_SIZE};
pub use message::{
    ErrorCode, ErrorPayload, KeyInfo, Method, Request, Response, ResponseBody, SignEventParams, UnsignedEvent,
};
