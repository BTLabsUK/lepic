// SPDX-License-Identifier: Apache-2.0
//! Lines from the tor control port: replies assembled line by line, asynchronous events and
//! their keyword arguments.

#![no_main]

use lepic_tor::control::{ReplyAssembler, parse_event, parse_keywords};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut replies = ReplyAssembler::default();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if replies.push_line(line).is_err() {
            replies = ReplyAssembler::default();
        }
        drop(parse_event(line));
        drop(parse_keywords(line));
    }
});
