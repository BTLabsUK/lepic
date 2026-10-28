// SPDX-License-Identifier: Apache-2.0
//! Node JSON-RPC response bodies through every pure decoder of `lepic_node::decode`.

#![no_main]

use std::collections::BTreeSet;

use lepic_fuzz::commitments_in;
use lepic_node::decode;
use lepic_primitives::amount::Height;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A client checks answers against what it asked for. Treating the commitments in the body
    // as the request lets the fuzzer reach validation past "not requested".
    let commitments = commitments_in(data);
    let requested: BTreeSet<_> = commitments.iter().copied().collect();

    let _ = decode::version(data);
    let _ = decode::tip(data);
    if let Some(excess) = commitments.first() {
        let _ = decode::kernel(data, excess, None, None);
        let _ = decode::kernel(data, excess, Some(Height::new(1)), Some(Height::new(1_000)));
    }
    let _ = decode::outputs(data, &requested);
    let _ = decode::unspent_outputs(data, 1, None, 1_000);
    let _ = decode::unspent_outputs(data, 1, Some(100), 10);
    let _ = decode::pmmr_indices(data);
    let _ = decode::push_transaction(data);
});
