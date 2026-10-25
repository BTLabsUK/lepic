//! The relays LEPIC ships with, per network. Pairing words (RFC 0002 7.7) are offered only on
//! these and looked for on these, in this order.

use crate::address::{Domain, Network};
use crate::session::{RelayEndpoint, Security};

/// Each built-in relay's network, domain and TLS port, in the order they are tried.
pub const BUILT_IN_RELAYS: &[(Network, &str, u16)] = &[
    (Network::Mainnet, "epicbox.epiccash.com", 443),
    (Network::Mainnet, "epicbox.epicnet.us", 443),
    (Network::Mainnet, "epicbox.stackwallet.com", 443),
    (Network::Floonet, "flooepicbox.btlabs.uk", 443),
];

/// The built-in relays of `network`, over TLS, in the order they are tried.
pub fn built_in_relays(network: Network) -> Vec<RelayEndpoint> {
    BUILT_IN_RELAYS
        .iter()
        .filter(|(relay_network, _, _)| *relay_network == network)
        .filter_map(|(_, domain, port)| {
            Some(RelayEndpoint::new(
                Domain::parse(domain).ok()?,
                Some(*port),
                Security::Tls,
            ))
        })
        .collect()
}

/// Whether `endpoint` is one of the built-in relays of `network`, by domain and port.
pub fn is_built_in_relay(network: Network, endpoint: &RelayEndpoint) -> bool {
    built_in_relays(network)
        .iter()
        .any(|known| known.domain() == endpoint.domain() && known.port() == endpoint.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_built_in_relay_parses_and_belongs_to_its_network() {
        let mainnet = built_in_relays(Network::Mainnet);
        let floonet = built_in_relays(Network::Floonet);
        assert_eq!(mainnet.len() + floonet.len(), BUILT_IN_RELAYS.len());
        assert_eq!(mainnet[0].domain().as_str(), "epicbox.epiccash.com");
        assert_eq!(floonet[0].domain().as_str(), "flooepicbox.btlabs.uk");
        assert!(is_built_in_relay(Network::Floonet, &floonet[0]));
        assert!(!is_built_in_relay(Network::Mainnet, &floonet[0]));
        let other_port = RelayEndpoint::new(
            Domain::parse("epicbox.epiccash.com").unwrap(),
            Some(3420),
            Security::Tls,
        );
        assert!(!is_built_in_relay(Network::Mainnet, &other_port));
    }
}
