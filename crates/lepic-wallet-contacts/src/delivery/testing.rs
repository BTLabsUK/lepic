// SPDX-License-Identifier: Apache-2.0
//! Keys, relays and watch rows for the tests of the delivery layer and its readers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::Timestamp;
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::sessions::PushedConfig;
use lepic_epicbox::testing::client_settings;
use lepic_epicbox::{
    Connector, Domain, EpicboxAddress, Identity, MuxOptions, MuxSession, MuxState, Network, Nonce,
    RelayEndpoint, RelayStream, Salt, Security, SignedMessage,
};
use lepic_methods::epicbox::Epicbox;
use lepic_store::{MailClass, WatchRow};
use lepic_transport::transport::BoxFuture;

use super::watch::{MailboxKeys, Unresolved};
use crate::{ContactRelays, RelayMode};

/// The relay of the watch rows, as a row writes it.
pub(crate) const RELAY: &str = "relay.test";

/// The relay of the test sessions, as `domain:port`.
pub(crate) const HOST: &str = "relay.test:80";

/// The group of the contacts' sessions in the tests.
const GROUP: &str = "wallet";

fn secret(byte: u8) -> SecretKey {
    SecretKey::from_array([byte; 32]).unwrap()
}

pub(crate) fn address(byte: u8) -> EpicboxAddress {
    EpicboxAddress::new(
        PublicKey::from_secret_key(&secret(byte)).unwrap(),
        Network::Mainnet,
        Domain::parse(RELAY).unwrap(),
        None,
    )
}

pub(crate) fn identity(byte: u8) -> Identity {
    Identity::new(secret(byte), address(byte)).unwrap()
}

pub(crate) fn endpoint() -> RelayEndpoint {
    RelayEndpoint::new(Domain::parse(RELAY).unwrap(), None, Security::Plain)
}

/// The contacts' session to the test relay, once it attached.
pub(crate) async fn attached(relays: &ContactRelays) -> Arc<MuxSession> {
    let session = relays.epicbox.pushed().get(HOST, GROUP).unwrap();
    let mut state = session.state();
    tokio::time::timeout(
        Duration::from_secs(5),
        state.wait_for(|state| *state == MuxState::Attached),
    )
    .await
    .unwrap()
    .unwrap();
    drop(state);
    session
}

pub(crate) async fn until(condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

/// A mailbox key on the test relay, one per `n`.
pub(crate) fn wide_identity(n: u16) -> Identity {
    let mut bytes = [1; 32];
    bytes[30..].copy_from_slice(&n.to_be_bytes());
    let secret = SecretKey::from_array(bytes).unwrap();
    let address = EpicboxAddress::new(
        PublicKey::from_secret_key(&secret).unwrap(),
        Network::Mainnet,
        Domain::parse(RELAY).unwrap(),
        None,
    );
    Identity::new(secret, address).unwrap()
}

pub(crate) fn sealed(from: u8, to: u8, text: &str) -> SignedMessage {
    SignedMessage::seal(
        text,
        &address(to),
        &secret(from),
        Salt::from([4; 8]),
        Nonce::from([5; 12]),
    )
    .unwrap()
}

/// Sends the domains in `classic` to the 3.0.0 mock and every other one to the mux/1 mock.
pub(crate) struct Routed {
    mux: Arc<dyn Connector>,
    classic: Arc<dyn Connector>,
    pub(crate) classic_domains: Mutex<HashSet<String>>,
}

impl Connector for Routed {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        let classic = self
            .classic_domains
            .lock()
            .unwrap()
            .contains(endpoint.domain().as_str());
        if classic {
            self.classic.connect(endpoint)
        } else {
            self.mux.connect(endpoint)
        }
    }
}

/// Contact relays reading pushed mail, through a connector that reaches `relay` and, for the
/// domains in `classic_domains`, `classic`.
pub(crate) fn relays(
    relay: &MuxMockRelay,
    classic: &MockRelay,
    classic_domains: &[&str],
) -> (ContactRelays, Arc<Routed>) {
    let routed = Arc::new(Routed {
        mux: relay.connector(),
        classic: classic.connector(),
        classic_domains: Mutex::new(
            classic_domains
                .iter()
                .map(|domain| (*domain).to_owned())
                .collect(),
        ),
    });
    let epicbox = Epicbox::new(
        client_settings(endpoint()),
        Network::Mainnet,
        routed.clone(),
    );
    epicbox.pushed().set_contacts(Some(PushedConfig {
        group: GROUP.to_owned(),
        options: MuxOptions {
            waiting_every: None,
            ..MuxOptions::default()
        },
    }));
    let relays = ContactRelays::new(epicbox, RelayMode::Online);
    (relays, routed)
}

/// Mailbox keys by reference.
#[derive(Default)]
pub(crate) struct Table(pub(crate) HashMap<String, Identity>);

impl Table {
    pub(crate) fn with(mut self, key_ref: &str, identity: Identity) -> Self {
        self.0.insert(key_ref.to_owned(), identity);
        self
    }
}

impl MailboxKeys for Table {
    fn identity(&self, row: &WatchRow) -> Result<Identity, Unresolved> {
        self.0.get(&row.key_ref).cloned().ok_or(Unresolved)
    }
}

pub(crate) fn row(key_ref: &str, class: MailClass, expires_at: Option<i64>) -> WatchRow {
    WatchRow {
        key_ref: key_ref.to_owned(),
        relay: RELAY.to_owned(),
        class,
        expires_at: expires_at.map(|second| Timestamp::from_second(second).unwrap()),
    }
}

/// "Now" for the watch passes of the tests.
pub(crate) fn now() -> Timestamp {
    Timestamp::from_second(1_000).unwrap()
}

impl ContactRelays {
    /// These relays with `added` after the relay of the epicbox in the list.
    pub(crate) fn with_added(self, added: Vec<lepic_epicbox::RelayEndpoint>) -> Self {
        let shipped = vec![self.epicbox.settings().endpoint.clone()];
        let list = crate::mailboxes::MailboxList::new(shipped, added, Vec::new()).unwrap();
        self.with_mailboxes(list)
    }
}
