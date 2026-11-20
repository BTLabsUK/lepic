// SPDX-License-Identifier: Apache-2.0
//! The foreign API's JSON-RPC decoders: requests from any HTTP caller, answers from any
//! remote listener. The first byte picks the decoder.

#![no_main]

use lepic_legacy_rpc::rpc::{decode_request, decode_slate_response, decode_version_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&which, body)) = data.split_first() else {
        return;
    };
    match which % 3 {
        0 => drop(decode_request(body)),
        1 => drop(decode_slate_response(body)),
        _ => drop(decode_version_response(body)),
    }
});
