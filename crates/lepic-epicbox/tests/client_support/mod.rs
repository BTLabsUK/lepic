// SPDX-License-Identifier: Apache-2.0
// Helpers outside `#[test]` functions are not covered by clippy's in-tests settings, and tests may
// unwrap, index and use plain arithmetic (docs/rules.md).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::future::Future;
use std::time::Duration;

use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{
    Backoff, ClientSettings, ConnectionState, Domain, EpicboxAddress, EpicboxClient, Identity,
    Network, Nonce, RelayEndpoint, Salt, Security, SignedMessage, Subscription,
};
use tokio::sync::watch;

pub const ALICE: u8 = 1;
pub const BOB: u8 = 2;
pub const CAROL: u8 = 3;

pub fn secret(byte: u8) -> SecretKey {
    SecretKey::from_array([byte; 32]).unwrap()
}

pub fn address(byte: u8) -> EpicboxAddress {
    EpicboxAddress::new(
        PublicKey::from_secret_key(&secret(byte)).unwrap(),
        Network::Mainnet,
        Domain::parse("relay.test").unwrap(),
        Some(443),
    )
}

/// Short limits so failures show quickly; generous enough for a loaded machine.
pub fn settings() -> ClientSettings {
    let mut settings = lepic_epicbox::testing::client_settings(RelayEndpoint::new(
        Domain::parse("relay.test").unwrap(),
        None,
        Security::Plain,
    ));
    settings.connect_timeout = Duration::from_secs(5);
    settings.response_timeout = Duration::from_secs(5);
    settings.ping_interval = Duration::from_secs(5);
    settings.backoff = Backoff {
        initial: Duration::from_millis(20),
        max: Duration::from_millis(100),
    };
    settings
}

pub fn client_with(relay: &MockRelay, byte: u8, settings: ClientSettings) -> EpicboxClient {
    let identity = Identity::new(secret(byte), address(byte)).unwrap();
    EpicboxClient::new(settings, identity, relay.connector())
}

pub fn client(relay: &MockRelay, byte: u8) -> EpicboxClient {
    client_with(relay, byte, settings())
}

/// A message from `from` to `to`, sealed with fixed salt and nonce.
pub fn sealed(from: u8, to: u8, plaintext: &str) -> SignedMessage {
    SignedMessage::seal(
        plaintext,
        &address(to),
        &secret(from),
        Salt::from([4; 8]),
        Nonce::from([5; 12]),
    )
    .unwrap()
}

pub async fn within<T>(limit: Duration, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(limit, future)
        .await
        .expect("timed out")
}

pub async fn reach(subscription: &Subscription, wanted: impl Fn(ConnectionState) -> bool) {
    let mut state: watch::Receiver<ConnectionState> = subscription.state();
    within(Duration::from_secs(5), state.wait_for(|s| wanted(*s)))
        .await
        .unwrap();
}

pub async fn until(condition: impl Fn() -> bool) {
    within(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}
