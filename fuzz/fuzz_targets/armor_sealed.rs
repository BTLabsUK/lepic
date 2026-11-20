// SPDX-License-Identifier: Apache-2.0
//! Armored sealed text of either marker pair as it arrives in a file, a paste or a mailbox.

#![no_main]

use lepic_seal::{ArmorMarker, armor, armor_tx, dearmor_marked, looks_sealed};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = looks_sealed(text);
    if let Ok((envelope, marker)) = dearmor_marked(text) {
        let armored = match marker {
            ArmorMarker::Sealed => armor(&envelope),
            ArmorMarker::Tx => armor_tx(&envelope),
        };
        assert_eq!(looks_sealed(&armored), marker == ArmorMarker::Sealed);
        assert_eq!(dearmor_marked(&armored), Ok((envelope, marker)));
    }
});
