// SPDX-License-Identifier: Apache-2.0
//! `EpicWallet::sign_with_address_key` and `verify_address_signature`: one wallet's signature
//! verifies against its address key on any device that holds the wallet, and nothing else
//! passes.

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;

use std::sync::Arc;

use super::*;
use crate::api::wallet::verify_address_signature;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";

async fn wallet(fixture: &mut Fixture, mnemonic: Option<&str>) -> EpicWallet {
    let relay = MockRelay::new(RelayNetwork::Floonet);
    Arc::get_mut(&mut fixture.runtime.inner).unwrap().relay = Some(relay.connector());
    let config = WalletConfig {
        epicbox_domain: "epicbox.example".to_owned(),
        ..fixture.config()
    };
    EpicWallet::create(
        &fixture.runtime,
        config,
        &AppSecretStore::in_memory(),
        mnemonic.map(str::to_owned),
        "password".to_owned(),
    )
    .await
    .unwrap()
}

async fn key_of(wallet: &EpicWallet) -> String {
    let address = wallet.epicbox_address().await.unwrap();
    address.split('@').next().unwrap().to_owned()
}

#[tokio::test]
async fn signature_verifies_against_the_same_wallet_on_another_device() {
    let (mut first, mut second) = (Fixture::new(), Fixture::new());
    let here = wallet(&mut first, Some(PHRASE)).await;
    let there = wallet(&mut second, Some(PHRASE)).await;
    let message = b"device link".to_vec();
    let signature = here.sign_with_address_key(message.clone()).await.unwrap();
    assert_eq!(
        there.sign_with_address_key(message.clone()).await.unwrap(),
        signature
    );
    let key = key_of(&there).await;
    assert!(verify_address_signature(
        key.clone(),
        message,
        signature.clone()
    ));
    assert!(verify_address_signature(
        here.epicbox_address().await.unwrap(),
        b"device link".to_vec(),
        signature
    ));
}

#[tokio::test]
async fn signature_fails_for_another_wallet_message_or_key_text() {
    let (mut first, mut second) = (Fixture::new(), Fixture::new());
    let ours = wallet(&mut first, Some(PHRASE)).await;
    let theirs = wallet(&mut second, None).await;
    let message = b"device link".to_vec();
    let signature = theirs.sign_with_address_key(message.clone()).await.unwrap();
    let key = key_of(&ours).await;
    assert!(!verify_address_signature(
        key.clone(),
        message.clone(),
        signature
    ));
    let ours_signed = ours.sign_with_address_key(message.clone()).await.unwrap();
    assert!(!verify_address_signature(
        key.clone(),
        b"device lint".to_vec(),
        ours_signed.clone()
    ));
    assert!(!verify_address_signature(
        "not a key".to_owned(),
        message.clone(),
        ours_signed.clone()
    ));
    assert!(!verify_address_signature(key, message, "zz".to_owned()));
}

#[tokio::test]
async fn signs_without_a_relay_and_refuses_an_oversized_message() {
    let fixture = Fixture::new();
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &AppSecretStore::in_memory(),
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    assert!(
        wallet
            .sign_with_address_key(vec![7; 64 * 1024])
            .await
            .is_ok()
    );
    assert_eq!(
        kind(wallet.sign_with_address_key(vec![7; 64 * 1024 + 1]).await),
        WalletErrorKind::InvalidArgument
    );
}
