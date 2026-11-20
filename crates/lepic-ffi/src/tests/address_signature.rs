// SPDX-License-Identifier: Apache-2.0
//! The listing calls `EpicWallet::epicbox_address_at`, `sign_with_address_key_at` and the pure
//! `verify_address_signature_at`, and the device-link calls `device_link_sign` and
//! `device_link_verify`: one phrase gives the same keys on every device, nothing signs with the
//! payments key, and nothing of another domain, key or wallet passes.

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;

use std::sync::Arc;

use super::*;
use crate::api::types::{ListingDrain, ListingRef};
use crate::api::wallet::verify_address_signature_at;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";

/// A service key, compressed, in hex.
const SERVICE_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const OTHER_SERVICE_KEY: &str =
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

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
        None,
        "password".to_owned(),
    )
    .await
    .unwrap()
}

fn key_of(address: &str) -> String {
    address.split('@').next().unwrap().to_owned()
}

#[tokio::test]
async fn a_listing_address_is_the_same_on_every_device_and_never_the_payments_address() {
    let (mut first, mut second) = (Fixture::new(), Fixture::new());
    let here = wallet(&mut first, Some(PHRASE)).await;
    let there = wallet(&mut second, Some(PHRASE)).await;
    let listing = here
        .epicbox_address_at(SERVICE_KEY.to_owned(), 0)
        .await
        .unwrap();
    assert_eq!(
        there
            .epicbox_address_at(SERVICE_KEY.to_owned(), 0)
            .await
            .unwrap(),
        listing
    );
    assert!(crate::api::wallet::validate_epicbox_address(
        listing.clone(),
        crate::api::types::Chain::Floonet
    ));
    let payments = here.epicbox_address().await.unwrap();
    let others = [
        payments,
        here.epicbox_address_at(SERVICE_KEY.to_owned(), 1)
            .await
            .unwrap(),
        here.epicbox_address_at(OTHER_SERVICE_KEY.to_owned(), 0)
            .await
            .unwrap(),
    ];
    for other in others {
        assert_ne!(key_of(&other), key_of(&listing));
    }
    for bad in [
        "",
        "02",
        &SERVICE_KEY[2..],
        &format!("05{}", &SERVICE_KEY[2..]),
    ] {
        assert_eq!(
            kind(here.epicbox_address_at(bad.to_owned(), 0).await),
            WalletErrorKind::InvalidArgument,
            "{bad}"
        );
    }
}

fn listing_ref(service_key: &str, generation: u32) -> ListingRef {
    ListingRef {
        service_key: service_key.to_owned(),
        generation,
    }
}

#[tokio::test]
async fn several_listings_are_drained_in_one_call_with_a_report_each() {
    let mut fixture = Fixture::new();
    let wallet = wallet(&mut fixture, Some(PHRASE)).await;
    assert!(
        wallet
            .drain_epicbox_listings(Vec::new())
            .await
            .unwrap()
            .is_empty()
    );
    let listings = vec![
        listing_ref(SERVICE_KEY, 0),
        listing_ref(OTHER_SERVICE_KEY, 3),
        listing_ref(SERVICE_KEY, 1),
    ];
    let drains = wallet.drain_epicbox_listings(listings).await.unwrap();
    assert_eq!(drains.len(), 3);
    for drain in &drains {
        assert_eq!(drain.report, Some(Default::default()));
        assert!(drain.error.is_none());
    }
    // The longest list the call takes.
    let sixteen = (0..16).map(|generation| listing_ref(SERVICE_KEY, generation));
    let reports = wallet
        .drain_epicbox_listings(sixteen.collect())
        .await
        .unwrap();
    assert_eq!(reports.len(), 16);
}

fn exactly_one_set(drain: &ListingDrain) -> bool {
    drain.report.is_some() != drain.error.is_some()
}

#[test]
fn one_failing_listing_keeps_its_error_in_place_and_the_others_their_reports() {
    use lepic_wallet::inbox::{InboxError, InboxSummary};
    let taken = InboxSummary {
        received: 2,
        ..InboxSummary::default()
    };
    let failed = InboxError::NetworkMismatch;
    let drains = crate::session::listing_drains(vec![Ok(taken), Err(failed), Ok(taken)]);
    assert_eq!(drains.len(), 3);
    assert!(drains.iter().all(exactly_one_set));
    assert_eq!(drains[0].report.unwrap().received, 2);
    assert!(drains[1].report.is_none() && drains[1].error.is_some());
    assert_eq!(drains[2].report.unwrap().received, 2);
}

#[tokio::test]
async fn more_than_sixteen_listings_or_a_bad_key_are_refused_before_any_relay_is_asked() {
    let mut fixture = Fixture::new();
    let wallet = wallet(&mut fixture, Some(PHRASE)).await;
    let seventeen = (0..17).map(|generation| listing_ref(SERVICE_KEY, generation));
    assert_eq!(
        kind(wallet.drain_epicbox_listings(seventeen.collect()).await),
        WalletErrorKind::InvalidArgument
    );
    // One bad key among good ones refuses the whole call.
    for bad in [
        "",
        "02",
        &SERVICE_KEY[2..],
        &format!("05{}", &SERVICE_KEY[2..]),
    ] {
        let listings = vec![listing_ref(SERVICE_KEY, 0), listing_ref(bad, 0)];
        assert_eq!(
            kind(wallet.drain_epicbox_listings(listings).await),
            WalletErrorKind::InvalidArgument,
            "{bad}"
        );
    }
}

async fn sign(wallet: &EpicWallet, domain: &str) -> Result<String, WalletError> {
    wallet
        .sign_with_address_key_at(
            SERVICE_KEY.to_owned(),
            0,
            domain.to_owned(),
            b"card".to_vec(),
        )
        .await
}

#[tokio::test]
async fn a_listing_signature_verifies_for_its_domain_and_key_only() {
    let (mut first, mut second) = (Fixture::new(), Fixture::new());
    let ours = wallet(&mut first, Some(PHRASE)).await;
    let theirs = wallet(&mut second, None).await;
    let message = b"card".to_vec();
    let signature = sign(&ours, "epic-listing/1").await.unwrap();
    let key = key_of(
        &ours
            .epicbox_address_at(SERVICE_KEY.to_owned(), 0)
            .await
            .unwrap(),
    );
    let verify = |key: &str, domain: &str, message: &[u8], signature: &str| {
        verify_address_signature_at(
            key.to_owned(),
            domain.to_owned(),
            message.to_vec(),
            signature.to_owned(),
        )
    };
    assert!(verify(&key, "epic-listing/1", &message, &signature));
    assert!(!verify(&key, "epic-payreq/1", &message, &signature));
    assert!(!verify(&key, "epic-listing/1", b"cart", &signature));
    assert!(!verify(&key, "epic-listing/1", &message, "zz"));
    let payments = key_of(&ours.epicbox_address().await.unwrap());
    assert!(!verify(&payments, "epic-listing/1", &message, &signature));
    let theirs_signed = sign(&theirs, "epic-listing/1").await.unwrap();
    assert!(!verify(&key, "epic-listing/1", &message, &theirs_signed));
    // LEPIC's own domains are never signed, in any case, and malformed ones are refused.
    for domain in [
        "lepic/addr-proof/1",
        "Lepic-x/1",
        "LEPIC/1",
        "Epic/1",
        "epic",
        "",
    ] {
        assert_eq!(
            kind(sign(&ours, domain).await),
            WalletErrorKind::InvalidArgument,
            "{domain}"
        );
        assert!(!verify(&key, domain, &message, &signature));
    }
}

#[tokio::test]
async fn the_device_link_signature_proves_the_same_phrase() {
    let (mut first, mut second, mut third) = (Fixture::new(), Fixture::new(), Fixture::new());
    let here = wallet(&mut first, Some(PHRASE)).await;
    let there = wallet(&mut second, Some(PHRASE)).await;
    let stranger = wallet(&mut third, None).await;
    let transcript = b"hello transcript".to_vec();
    let signature = here.device_link_sign(transcript.clone()).await.unwrap();
    assert_eq!(signature.len(), 64);
    assert!(
        there
            .device_link_verify(transcript.clone(), signature.clone())
            .await
            .unwrap()
    );
    assert!(
        !stranger
            .device_link_verify(transcript.clone(), signature.clone())
            .await
            .unwrap()
    );
    assert!(
        !there
            .device_link_verify(b"hello transcripT".to_vec(), signature.clone())
            .await
            .unwrap()
    );
    assert!(
        !there
            .device_link_verify(transcript, signature[..63].to_vec())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn signs_without_a_relay_and_refuses_an_oversized_message() {
    let fixture = Fixture::new();
    let wallet = EpicWallet::create(
        &fixture.runtime,
        fixture.config(),
        &AppSecretStore::in_memory(),
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    let sign = |size: usize| {
        wallet.sign_with_address_key_at(
            SERVICE_KEY.to_owned(),
            0,
            "epic-listing/1".to_owned(),
            vec![7; size],
        )
    };
    assert!(sign(64 * 1024).await.is_ok());
    assert_eq!(
        kind(sign(64 * 1024 + 1).await),
        WalletErrorKind::InvalidArgument
    );
    assert!(wallet.device_link_sign(vec![7; 64 * 1024]).await.is_ok());
    assert_eq!(
        kind(wallet.device_link_sign(vec![7; 64 * 1024 + 1]).await),
        WalletErrorKind::InvalidArgument
    );
    // The listing address needs the relay of the configuration.
    assert_eq!(
        kind(wallet.epicbox_address_at(SERVICE_KEY.to_owned(), 0).await),
        WalletErrorKind::Unsupported
    );
}
