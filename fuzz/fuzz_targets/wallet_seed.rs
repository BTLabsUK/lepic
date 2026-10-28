// SPDX-License-Identifier: Apache-2.0
//! The `wallet.seed` file `epic-wallet` writes, parsed and decrypted.

#![no_main]

use lepic_keychain::WalletSeedFile;
use libfuzzer_sys::fuzz_target;

/// The password of the wallet seed vectors, so seeded files decrypt.
const PASSWORD: &[u8] = b"lepic test password";

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(file) = WalletSeedFile::parse(text) {
        let _ = file.decrypt(PASSWORD);
    }
});
