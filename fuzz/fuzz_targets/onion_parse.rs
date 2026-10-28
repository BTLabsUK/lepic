//! Onion addresses typed by users or named by peers, and the head of a SOCKS reply from tor.

#![no_main]

use lepic_tor::OnionAddress;
use lepic_tor::socks::parse_connect_head;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(head) = data.first_chunk::<4>() {
        drop(parse_connect_head(*head));
    }
    let text = String::from_utf8_lossy(data);
    if let Ok(onion) = OnionAddress::parse(&text) {
        let again = OnionAddress::parse(&onion.host()).expect("an onion's host parses");
        assert_eq!(again.host(), onion.host(), "an onion's host round-trips");
    }
});
