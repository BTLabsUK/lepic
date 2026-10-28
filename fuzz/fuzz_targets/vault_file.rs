// SPDX-License-Identifier: Apache-2.0
//! The vault file header and framing, read before any key is derived.

#![no_main]

use lepic_keychain::vault::VaultFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = VaultFile::decode(data) {
        assert_eq!(
            file.encode(),
            data,
            "an accepted vault does not write back what was read"
        );
    }
});
