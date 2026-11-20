// SPDX-License-Identifier: Apache-2.0
//! The rows of an `epic-wallet` database the legacy history import reads: accounts,
//! transactions, outputs and derivation counters, from a folder the user picks.

#![no_main]

use libfuzzer_sys::fuzz_target;

// The first byte picks the parser: 0 an account, 1 a transaction, 2 an output, anything else a
// derivation counter, whose row key runs up to the first newline and whose value follows it.
fuzz_target!(|data: &[u8]| {
    let Some((kind, rest)) = data.split_first() else {
        return;
    };
    let (key, row) = match rest.iter().position(|byte| *byte == b'\n') {
        Some(at) if *kind > 2 => (&rest[..at], &rest[at + 1..]),
        _ => (&[][..], rest),
    };
    lepic_store::fuzz::legacy_row(*kind, key, row);
});
