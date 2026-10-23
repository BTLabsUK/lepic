//! `EpicWallet::push_signature`: the text it signs, what it refuses, and that it needs a relay.

use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork, PushAction, PushRequest};

use std::sync::Arc;

use super::*;

async fn wallet_on_relay(fixture: &mut Fixture) -> EpicWallet {
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
        None,
        "password".to_owned(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn push_signature_verifies_over_the_contract_text() {
    let mut fixture = Fixture::new();
    let wallet = wallet_on_relay(&mut fixture).await;
    let address = wallet.epicbox_address().await.unwrap();
    let signed = wallet
        .push_signature(
            "register".to_owned(),
            "fcm:AP-a_b.c1".to_owned(),
            1_761_000_000,
        )
        .await
        .unwrap();
    assert_eq!(signed.address, address);
    let parsed = EpicboxAddress::parse(&address, RelayNetwork::Floonet).unwrap();
    let key = address.split('@').next().unwrap();
    let request = |action, token| PushRequest::new(action, token, 1_761_000_000).unwrap();
    let register = request(PushAction::Register, "fcm:AP-a_b.c1");
    assert_eq!(
        register.signed_text(key),
        format!("epic-push-v1\nregister\n{key}\nfcm:AP-a_b.c1\n1761000000")
    );
    assert!(register.verify(&parsed, &signed.signature));
    assert!(!request(PushAction::Unregister, "fcm:AP-a_b.c1").verify(&parsed, &signed.signature));
    assert!(!request(PushAction::Register, "fcm:other").verify(&parsed, &signed.signature));
    let again = wallet
        .push_signature(
            "register".to_owned(),
            "fcm:AP-a_b.c1".to_owned(),
            1_761_000_000,
        )
        .await
        .unwrap();
    assert_eq!(again.signature, signed.signature);
}

#[tokio::test]
async fn push_signature_refuses_a_bad_action_or_token() {
    let mut fixture = Fixture::new();
    let wallet = wallet_on_relay(&mut fixture).await;
    let long = "a".repeat(4097);
    for (action, token) in [
        ("sign", "abc"),
        ("", "abc"),
        ("register", ""),
        ("register", long.as_str()),
        ("register", "a\nb"),
        ("register", "a b"),
        ("register", "a/b"),
    ] {
        assert_eq!(
            kind(
                wallet
                    .push_signature(action.to_owned(), token.to_owned(), 1)
                    .await
            ),
            WalletErrorKind::InvalidArgument,
            "{action} {}",
            token.len()
        );
    }
    assert!(
        wallet
            .push_signature("unregister".to_owned(), "a".repeat(4096), 1)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn push_signature_needs_a_relay() {
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
    assert_eq!(
        kind(
            wallet
                .push_signature("register".to_owned(), "abc".to_owned(), 1)
                .await
        ),
        WalletErrorKind::Unsupported
    );
}
