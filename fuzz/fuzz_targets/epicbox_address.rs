//! Epicbox address text on both networks.

#![no_main]

use lepic_epicbox::{DEFAULT_PORT, EpicboxAddress, Network};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for network in [Network::Mainnet, Network::Floonet] {
        let Ok(address) = EpicboxAddress::parse(text, network) else {
            continue;
        };
        // Display leaves out the default port, so that one reads back as no port.
        let shown = address.to_string();
        let reparsed = EpicboxAddress::parse(&shown, network);
        let expected_port = address.port().filter(|port| *port != DEFAULT_PORT);
        match reparsed {
            Ok(reparsed) => {
                assert_eq!(reparsed.public_key(), address.public_key());
                assert_eq!(reparsed.domain(), address.domain());
                assert_eq!(reparsed.port(), expected_port);
            }
            Err(error) => panic!("an accepted address displays as {shown:?}, rejected: {error}"),
        }
    }
});
