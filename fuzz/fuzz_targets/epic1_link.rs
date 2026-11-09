// SPDX-License-Identifier: Apache-2.0
//! Arbitrary text through the epic1 link and address readers. A link that parses must write back
//! to a link that parses to the same address, transports, amount, message and label.

#![no_main]

use lepic_epic1::{Epic1Address, Epic1Link, MAX_TRANSPORTS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(address) = Epic1Address::decode_any(text) {
        assert_eq!(address.encode(), text, "an address reads back to its text");
    }
    let Ok(link) = Epic1Link::parse(text) else {
        return;
    };
    assert!(
        link.transports.len() <= MAX_TRANSPORTS,
        "more transports read than the limit"
    );
    let Ok(again) = Epic1Link::parse(&link.to_uri()) else {
        panic!("a link written by to_uri does not parse");
    };
    assert_eq!(again.address, link.address, "address survives");
    assert_eq!(again.transports, link.transports, "transports survive");
    assert_eq!(again.amount, link.amount, "amount survives");
    assert_eq!(again.message, link.message, "message survives");
    assert_eq!(again.label, link.label, "label survives");
});
