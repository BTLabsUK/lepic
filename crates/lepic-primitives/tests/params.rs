// SPDX-License-Identifier: Apache-2.0
use lepic_primitives::amount::{ArithmeticError, Height};
use lepic_primitives::params::{ChainParams, Network};

#[test]
fn networks_have_independent_parameters() {
    let mainnet = ChainParams::for_network(Network::Mainnet);
    let floonet = ChainParams::for_network(Network::Floonet);
    assert_eq!(mainnet.network(), Network::Mainnet);
    assert_eq!(floonet.network(), Network::Floonet);
    assert_ne!(mainnet.coinbase_maturity(), floonet.coinbase_maturity());
    assert_eq!(Network::Mainnet.params(), mainnet);
}

#[test]
fn coinbase_lock_height_adds_the_maturity() {
    let params = Network::Floonet.params();
    assert_eq!(
        params.coinbase_lock_height(Height::new(100)),
        Ok(Height::new(130))
    );
    assert_eq!(
        params.coinbase_lock_height(Height::new(u64::MAX)),
        Err(ArithmeticError::Overflow)
    );
}

#[test]
fn networks_display_their_lowercase_names() {
    assert_eq!(Network::Mainnet.to_string(), "mainnet");
    assert_eq!(Network::Floonet.to_string(), "floonet");
}

#[test]
fn header_version_changes_at_each_network_first_hard_fork() {
    for (network, fork) in [(Network::Mainnet, 9_000_000), (Network::Floonet, 25_800)] {
        let params = network.params();
        assert_eq!(params.first_hard_fork(), Height::new(fork));
        assert_eq!(params.block_header_version(Height::ZERO), 6);
        assert_eq!(params.block_header_version(Height::new(fork - 1)), 6);
        assert_eq!(params.block_header_version(Height::new(fork)), 7);
        assert_eq!(params.block_header_version(Height::new(u64::MAX)), 7);
    }
}
