// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! [`MasterKeySource`] backed by KeyOS's `security.app_seed()`.
//!
//! The returned 32-byte value is device-bound and — on real hardware — only
//! accessible once the user is logged in with PIN. In the hosted-mode
//! simulator the security server returns a deterministic seed derived from
//! the app id even when not logged in (with a warning), which is fine for
//! development.

use keystore::{Error, MasterKeySource, Result};

security::use_api!();

pub struct KeyOsAppSeedSource;

impl MasterKeySource for KeyOsAppSeedSource {
    fn app_seed(&self) -> Result<[u8; 32]> {
        let security = Security::default();
        security
            .app_seed()
            .map_err(|_| Error::Aead("security.app_seed: access denied"))
    }
}
