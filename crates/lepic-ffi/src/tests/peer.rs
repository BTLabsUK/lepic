// SPDX-License-Identifier: Apache-2.0
//! `EpicWallet::peer_compat`, `peer_feature_result` and `notice_apply_forwarded` of a wallet
//! with no Epicbox relay configured: they read and write what the wallet knows of an address
//! by its key, relay or not.

use std::sync::Arc;

use jiff::Timestamp;
use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_primitives::params::Network;
use lepic_store::WalletStore as _;

use super::*;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";

const PASSWORD: &str = "password";

/// The name service host bit.
const NAME_SERVICE: u32 = 32;

/// A notice for a slate no wallet here holds.
const WITHDRAWN: &str =
    r#"{"lepic":1,"type":"withdrawn","slate_id":"0436430c-2b02-624c-2032-570501212b00"}"#;

/// The Epicbox address of another wallet, which has a relay.
async fn peer_address() -> String {
    let mut fixture = Fixture::new();
    let relay = MockRelay::new(RelayNetwork::Floonet);
    Arc::get_mut(&mut fixture.runtime.inner).unwrap().relay = Some(relay.connector());
    let config = WalletConfig {
        epicbox_domain: "epicbox.example".to_owned(),
        ..fixture.config()
    };
    let wallet = EpicWallet::create(
        &fixture.runtime,
        config,
        &AppSecretStore::in_memory(),
        None,
        None,
        PASSWORD.to_owned(),
    )
    .await
    .unwrap();
    wallet.epicbox_address().await.unwrap()
}

async fn open(fixture: &Fixture, store: &AppSecretStore) -> EpicWallet {
    EpicWallet::open(
        &fixture.runtime,
        fixture.config(),
        store,
        PASSWORD.to_owned(),
    )
    .await
    .unwrap()
}

/// The wallet database of `fixture`, opened as another program with the data folder and the
/// recovery phrase would.
fn database(fixture: &Fixture) -> lepic_store::SqliteStore {
    let seed = lepic_keychain::Seed::from_mnemonic(PHRASE).unwrap();
    lepic_store::SqliteStore::open(
        &fixture
            .dir
            .path()
            .join(lepic_wallet::ENCRYPTED_DATABASE_FILE),
        lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
        lepic_store::AtRest::Encrypted(&lepic_wallet::store_key(&seed).unwrap()),
    )
    .unwrap()
}

#[tokio::test]
async fn peer_facts_are_read_and_written_by_key_without_a_relay() {
    let peer = peer_address().await;
    let fixture = Fixture::new();
    assert!(fixture.config().epicbox_domain.is_empty());
    let store = AppSecretStore::in_memory();
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &store,
        Some(PHRASE.to_owned()),
        None,
        PASSWORD.to_owned(),
    )
    .await
    .unwrap();

    let facts = wallet.peer_compat(peer.clone()).await.unwrap();
    assert_eq!(
        (facts.last_marked_at_ms, facts.last_unmarked_at_ms),
        (None, None)
    );
    assert_eq!((facts.claimed, facts.works), (0, 0));
    assert!(!facts.lepic && !facts.notices && !facts.fresh);
    wallet
        .peer_feature_result(peer.clone(), NAME_SERVICE, true)
        .await
        .unwrap();
    assert_eq!(wallet.peer_compat(peer.clone()).await.unwrap().works, 0);
    drop(wallet);

    let key = lepic_methods::epicbox::peer_key(Network::Floonet, &peer).unwrap();
    database(&fixture)
        .write(|repos| {
            lepic_wallet::peer_compat::record_claim(
                repos,
                &key,
                Timestamp::from_second(1_700_000_000).unwrap(),
                NAME_SERVICE,
            )
        })
        .unwrap();
    let wallet = open(&fixture, &store).await;
    wallet
        .peer_feature_result(peer.clone(), NAME_SERVICE, true)
        .await
        .unwrap();
    let facts = wallet.peer_compat(peer).await.unwrap();
    assert_eq!(facts.works, NAME_SERVICE);
    assert_eq!(facts.claimed & NAME_SERVICE, NAME_SERVICE);
}

#[tokio::test]
async fn a_forwarded_notice_for_a_slate_not_held_is_not_taken_without_a_relay() {
    let peer = peer_address().await;
    let fixture = Fixture::new();
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &AppSecretStore::in_memory(),
        None,
        None,
        PASSWORD.to_owned(),
    )
    .await
    .unwrap();

    assert!(
        !wallet
            .notice_apply_forwarded(peer, WITHDRAWN.to_owned())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn peer_calls_without_a_relay_refuse_an_address_that_does_not_parse() {
    let fixture = Fixture::new();
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &AppSecretStore::in_memory(),
        None,
        None,
        PASSWORD.to_owned(),
    )
    .await
    .unwrap();

    for bad in ["", "not an address", "nokey@epicbox.example"] {
        assert_eq!(
            kind(wallet.peer_compat(bad.to_owned()).await),
            WalletErrorKind::InvalidArgument,
            "{bad:?}"
        );
        assert_eq!(
            kind(
                wallet
                    .peer_feature_result(bad.to_owned(), NAME_SERVICE, true)
                    .await
            ),
            WalletErrorKind::InvalidArgument,
            "{bad:?}"
        );
        assert_eq!(
            kind(
                wallet
                    .notice_apply_forwarded(bad.to_owned(), WITHDRAWN.to_owned())
                    .await
            ),
            WalletErrorKind::InvalidArgument,
            "{bad:?}"
        );
    }
}
