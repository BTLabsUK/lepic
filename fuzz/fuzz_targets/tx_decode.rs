//! `Transaction::decode`, the read a node runs on a pushed transaction, with its consensus checks.
//!
//! Input: one byte choosing the protocol version (odd is version 1, even is version 2), then the
//! encoding.

#![no_main]

use lepic_primitives::ser::{ProtocolVersion, ser_vec};
use lepic_primitives::tx::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [version, bytes @ ..] = data else {
        return;
    };
    let version = if version % 2 == 1 {
        ProtocolVersion::V1
    } else {
        ProtocolVersion::V2
    };
    if let Ok(transaction) = Transaction::decode(bytes, version) {
        assert_eq!(
            ser_vec(&transaction, version),
            bytes,
            "an accepted transaction does not write back what was read"
        );
    }
});
