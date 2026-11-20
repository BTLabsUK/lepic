// SPDX-License-Identifier: Apache-2.0
//! The `WFEH` app data file a user picks to restore: header, key check and AEAD body.

#![no_main]

use std::sync::LazyLock;

use lepic_keychain::app_data::{self, NONCE_LEN, SALT_LEN};
use lepic_keychain::{Keychain, Seed};
use lepic_primitives::params::Network;
use libfuzzer_sys::fuzz_target;

/// The wallet of the `wfeh_seed_a` vector, so the seeded golden files open.
static KEYCHAIN: LazyLock<Keychain> = LazyLock::new(|| {
    let entropy: Vec<u8> = (0..32).collect();
    let seed = Seed::from_entropy(&entropy).expect("32 bytes of entropy make a seed");
    Keychain::from_seed(&seed, Network::Mainnet).expect("a fixed seed makes a keychain")
});

// The first byte picks the mode: 0 opens the rest as a file; anything else seals the rest
// (salt, nonce, payload) and must open it back to the same payload.
fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    if *mode == 0 {
        let _ = app_data::open(&KEYCHAIN, rest);
        return;
    }
    let Some((salt, rest)) = rest.split_first_chunk::<SALT_LEN>() else {
        return;
    };
    let Some((nonce, payload)) = rest.split_first_chunk::<NONCE_LEN>() else {
        return;
    };
    let file = app_data::seal(&KEYCHAIN, *salt, *nonce, payload).expect("a fuzz input is small");
    let opened = app_data::open(&KEYCHAIN, &file).expect("a sealed file opens");
    assert_eq!(opened.as_slice(), payload, "open(seal(x)) is x");
});
