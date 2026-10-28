//! A relay's onion discovery answer: relay-controlled HTTP read through tor.

#![no_main]

use lepic_epicbox::tunnel::parse_discovery;
use lepic_epicbox::{Domain, RelayEndpoint, Security};
use lepic_tor::RelayTor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(domain) = Domain::parse("epicbox.example") else {
        return;
    };
    let endpoint = RelayEndpoint::new(domain, None, Security::Tls);
    if let Ok(target) = parse_discovery(data, &endpoint, RelayTor::is_onion) {
        assert!(RelayTor::is_onion(&target.host), "only a valid onion is named");
        assert_ne!(target.port, 0, "never port 0");
    }
});
