// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! USB-HID report framing for JSON payloads.
//!
//! Each HID report is exactly [`REPORT_SIZE`] bytes. A message is a sequence
//! of reports with an INIT flag on the first and FINAL flag on the last.
//! Intermediate reports have neither. HID delivery is in-order and reliable,
//! so no explicit sequence number is needed — reports are reassembled by
//! arrival order.
//!
//! Layout of a single report (64 bytes):
//!
//!   offset  0        1    2..=3    4..=63
//!   field   flags    rsv  len_be   payload
//!
//! - `flags`    bit 7 = INIT, bit 0 = FINAL. Other bits reserved.
//! - `rsv`      reserved, must be 0.
//! - `len_be`   big-endian u16; valid payload bytes in this report (0..=60).
//! - `payload`  up to [`PAYLOAD_PER_REPORT`] bytes of the JSON blob.
//!
//! A message starts with one INIT report. If an INIT arrives mid-session,
//! the receiver discards any in-progress buffer and starts fresh — this
//! lets a sender recover from a lost tail without explicit state.

use thiserror::Error;

pub const REPORT_SIZE: usize = 64;
pub const HEADER_SIZE: usize = 4;
pub const PAYLOAD_PER_REPORT: usize = REPORT_SIZE - HEADER_SIZE;

pub const FLAG_FINAL: u8 = 0b0000_0001;
pub const FLAG_INIT: u8 = 0b1000_0000;

/// Upper bound on reassembled payload size to prevent OOM from a malicious
/// host. 16 KiB is well above anything we expect; `sign_event` with long-form
/// content runs a few KiB at most.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("report must be exactly {REPORT_SIZE} bytes, got {0}")]
    BadReportSize(usize),
    #[error("declared chunk length {0} exceeds payload space {PAYLOAD_PER_REPORT}")]
    BadChunkLen(u16),
    #[error("continuation report received with no active message")]
    UnexpectedContinuation,
    #[error("payload exceeds max size of {MAX_PAYLOAD_BYTES} bytes")]
    PayloadTooLarge,
}

/// Chunks a byte slice into a vector of 64-byte reports.
pub struct Framer;

impl Framer {
    pub fn frame(payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
        if payload.is_empty() {
            let mut r = [0u8; REPORT_SIZE];
            r[0] = FLAG_INIT | FLAG_FINAL;
            return vec![r];
        }
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = payload.chunks(PAYLOAD_PER_REPORT).collect();
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.iter().enumerate() {
            let mut report = [0u8; REPORT_SIZE];
            let mut flags = 0u8;
            if i == 0 {
                flags |= FLAG_INIT;
            }
            if i == last {
                flags |= FLAG_FINAL;
            }
            report[0] = flags;
            let len = chunk.len() as u16;
            report[2..4].copy_from_slice(&len.to_be_bytes());
            report[HEADER_SIZE..HEADER_SIZE + chunk.len()].copy_from_slice(chunk);
            out.push(report);
        }
        out
    }
}

/// Reassembles multi-report messages. One instance per peer.
#[derive(Debug, Default)]
pub struct Defragmenter {
    buf: Vec<u8>,
    in_message: bool,
}

impl Defragmenter {
    pub fn new() -> Self { Self::default() }

    /// Feed one 64-byte HID report. Returns `Ok(Some(payload))` when the
    /// message is complete; `Ok(None)` if more reports are expected;
    /// `Err(..)` on framing errors.
    pub fn feed(&mut self, report: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        if report.len() != REPORT_SIZE {
            return Err(FrameError::BadReportSize(report.len()));
        }
        let flags = report[0];
        let len = u16::from_be_bytes([report[2], report[3]]);
        if len as usize > PAYLOAD_PER_REPORT {
            self.reset();
            return Err(FrameError::BadChunkLen(len));
        }

        let is_init = flags & FLAG_INIT != 0;
        let is_final = flags & FLAG_FINAL != 0;

        if is_init {
            self.buf.clear();
            self.in_message = true;
        } else if !self.in_message {
            return Err(FrameError::UnexpectedContinuation);
        }

        let payload = &report[HEADER_SIZE..HEADER_SIZE + len as usize];
        if self.buf.len() + payload.len() > MAX_PAYLOAD_BYTES {
            self.reset();
            return Err(FrameError::PayloadTooLarge);
        }
        self.buf.extend_from_slice(payload);

        if is_final {
            let out = core::mem::take(&mut self.buf);
            self.reset();
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.in_message = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(payload: &[u8]) {
        let reports = Framer::frame(payload);
        let mut d = Defragmenter::new();
        let mut got = None;
        for (i, r) in reports.iter().enumerate() {
            let out = d.feed(r).unwrap();
            if i == reports.len() - 1 {
                got = out;
            } else {
                assert_eq!(out, None);
            }
        }
        assert_eq!(got.as_deref(), Some(payload));
    }

    #[test]
    fn empty_payload() { roundtrip(&[]); }

    #[test]
    fn single_chunk_payload() { roundtrip(b"hello world"); }

    #[test]
    fn exact_one_chunk() { roundtrip(&vec![0x42u8; PAYLOAD_PER_REPORT]); }

    #[test]
    fn just_over_one_chunk() { roundtrip(&vec![0x42u8; PAYLOAD_PER_REPORT + 1]); }

    #[test]
    fn ten_chunks() { roundtrip(&vec![0xABu8; PAYLOAD_PER_REPORT * 10]); }

    #[test]
    fn large_but_bounded() { roundtrip(&vec![0x7Fu8; MAX_PAYLOAD_BYTES - 1]); }

    #[test]
    fn spans_more_than_256_reports() {
        // Previously failed with 8-bit sequence numbering.
        roundtrip(&vec![0x33u8; PAYLOAD_PER_REPORT * 260]);
    }

    #[test]
    fn init_flag_resets_mid_session() {
        let mut d = Defragmenter::new();
        // A partial message (INIT but no FINAL).
        let mut mid = [0u8; REPORT_SIZE];
        mid[0] = FLAG_INIT;
        mid[2..4].copy_from_slice(&(PAYLOAD_PER_REPORT as u16).to_be_bytes());
        mid[HEADER_SIZE..].fill(b'A');
        assert_eq!(d.feed(&mid).unwrap(), None);

        // New INIT mid-session: discards previous, starts fresh.
        let mut fresh = [0u8; REPORT_SIZE];
        fresh[0] = FLAG_INIT | FLAG_FINAL;
        fresh[2..4].copy_from_slice(&(3u16).to_be_bytes());
        fresh[HEADER_SIZE..HEADER_SIZE + 3].copy_from_slice(b"gm!");
        assert_eq!(d.feed(&fresh).unwrap().as_deref(), Some(&b"gm!"[..]));
    }

    #[test]
    fn continuation_without_init_errors() {
        let mut d = Defragmenter::new();
        let mut cont = [0u8; REPORT_SIZE];
        cont[0] = 0; // neither INIT nor FINAL
        cont[2..4].copy_from_slice(&(1u16).to_be_bytes());
        assert_eq!(d.feed(&cont), Err(FrameError::UnexpectedContinuation));
    }

    #[test]
    fn rejects_bad_report_size() {
        let mut d = Defragmenter::new();
        assert_eq!(d.feed(&[0u8; 32]), Err(FrameError::BadReportSize(32)));
    }

    #[test]
    fn rejects_oversized_chunk_len() {
        let mut d = Defragmenter::new();
        let mut r = [0u8; REPORT_SIZE];
        r[0] = FLAG_INIT;
        r[2..4].copy_from_slice(&(100u16).to_be_bytes());
        assert_eq!(d.feed(&r), Err(FrameError::BadChunkLen(100)));
    }

    #[test]
    fn rejects_payload_too_large() {
        // Build reports by hand that claim valid chunk sizes but exceed the cap.
        let mut d = Defragmenter::new();
        let mut init = [0u8; REPORT_SIZE];
        init[0] = FLAG_INIT;
        init[2..4].copy_from_slice(&(PAYLOAD_PER_REPORT as u16).to_be_bytes());
        // Accept lots of middle reports until we trip the limit.
        let reports_needed = MAX_PAYLOAD_BYTES / PAYLOAD_PER_REPORT + 2;
        for i in 0..reports_needed {
            let mut r = [0u8; REPORT_SIZE];
            r[0] = if i == 0 { FLAG_INIT } else { 0 };
            r[2..4].copy_from_slice(&(PAYLOAD_PER_REPORT as u16).to_be_bytes());
            match d.feed(&r) {
                Ok(_) => continue,
                Err(FrameError::PayloadTooLarge) => return,
                Err(e) => panic!("unexpected error {e:?}"),
            }
        }
        panic!("expected PayloadTooLarge");
    }
}
