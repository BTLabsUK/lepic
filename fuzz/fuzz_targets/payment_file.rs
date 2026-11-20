// SPDX-License-Identifier: Apache-2.0
//! Payment files as they arrive from disk or a paste: the classifier (RFC 0003 5.12), then the
//! armor of either marker pair for a file it calls armour.

#![no_main]

use lepic_seal::{ArmorMarker, PaymentFile, armor, armor_tx, classify, dearmor_marked};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(PaymentFile::Armour) = classify(data) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok((envelope, marker)) = dearmor_marked(text) {
        let armored = match marker {
            ArmorMarker::Sealed => armor(&envelope),
            ArmorMarker::Tx => armor_tx(&envelope),
        };
        assert_eq!(classify(armored.as_bytes()), Ok(PaymentFile::Armour));
        assert_eq!(dearmor_marked(&armored), Ok((envelope, marker)));
    }
});
