//! The slate text the app reads without a wallet (`inspect_slate`), on both chains.

#![no_main]

use lepic_ffi::api::types::Chain;
use lepic_ffi::api::wallet::inspect_slate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for chain in [Chain::Mainnet, Chain::Floonet] {
        if let Ok(info) = inspect_slate(text.to_owned(), chain) {
            assert!(
                matches!(info.version, 2 | 3),
                "an inspected slate declares a version other than 2 or 3"
            );
        }
    }
});
