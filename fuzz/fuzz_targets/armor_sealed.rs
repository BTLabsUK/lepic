// SPDX-License-Identifier: Apache-2.0
//! Armored sealed text as it arrives in a file, a paste or a mailbox.

#![no_main]

use lepic_contact::{armor, dearmor, looks_sealed};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = looks_sealed(text);
    if let Ok(envelope) = dearmor(text) {
        let armored = armor(&envelope);
        assert!(looks_sealed(&armored));
        assert_eq!(dearmor(&armored).as_ref(), Ok(&envelope));
    }
});
