// SPDX-License-Identifier: Apache-2.0
//! Epic1 links and native sealed text through the binding, between wallets on the mock relay:
//! a link issued, read and paid, the payment taken and answered by the payee, the answer
//! finalized by the payer's collect, printed links retired, and `.epictx` text between native
//! contacts.

use lepic_wallet_contacts::WalletContacts as _;

use super::contact::{EPIC, RELAY, World, pair};
use super::kind;
use crate::api::contact::sealed_file_extension;
use crate::api::epic1::ListenerSocket;
use crate::api::error::WalletErrorKind;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    Chain, CollectTrigger, ContactRelayMode, Epic1LinkKind, HostClassView, SlatePurpose,
};
use crate::api::wallet::EpicWallet;

use ContactRelayMode::Online;

/// A wallet with native slates on, opened again so the setting is in use; `funded` gives it
/// 10 EPIC.
async fn native(world: &mut World, funded: bool) -> EpicWallet {
    let config = world.config(RELAY);
    let store = AppSecretStore::in_memory();
    let wallet = EpicWallet::create(
        &world.runtime,
        config.clone(),
        &store,
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    wallet.set_native_direct(true).unwrap();
    let phrase = wallet.mnemonic("password".to_owned()).await.unwrap();
    drop(wallet);
    let wallet = EpicWallet::open(&world.runtime, config, &store, "password".to_owned())
        .await
        .unwrap();
    if funded {
        world
            .chain
            .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
            .unwrap();
        world.chain.set_height(20);
        wallet.session().scan_to_tip().await;
    }
    wallet
}

async fn collect(wallet: &EpicWallet) -> u32 {
    wallet
        .contacts_collect(CollectTrigger::Pull, Online, None)
        .await
        .unwrap()
        .epic1
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epic1_at_the_listeners_is_off_by_default_and_saved_per_socket() {
    let mut world = World::new();
    let config = world.config(RELAY);
    let store = AppSecretStore::in_memory();
    let wallet = native(&mut world, false).await;
    assert!(!wallet.epic1_at_listener(ListenerSocket::Web));
    assert!(!wallet.epic1_at_listener(ListenerSocket::Onion));
    wallet
        .set_epic1_at_listener(ListenerSocket::Onion, true)
        .unwrap();
    assert!(wallet.epic1_at_listener(ListenerSocket::Onion));
    assert!(!wallet.epic1_at_listener(ListenerSocket::Web));
    // Setting it twice either way is safe.
    wallet
        .set_epic1_at_listener(ListenerSocket::Onion, true)
        .unwrap();
    wallet
        .set_epic1_at_listener(ListenerSocket::Web, false)
        .unwrap();
    assert!(wallet.epic1_at_listener(ListenerSocket::Onion));
    wallet
        .set_epic1_at_listener(ListenerSocket::Onion, false)
        .unwrap();
    assert!(!wallet.epic1_at_listener(ListenerSocket::Onion));
    // Each wallet keeps its own.
    wallet
        .set_epic1_at_listener(ListenerSocket::Web, true)
        .unwrap();
    let other = EpicWallet::create(
        &world.runtime,
        config,
        &store,
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();
    assert!(!other.epic1_at_listener(ListenerSocket::Web));
    assert!(wallet.epic1_at_listener(ListenerSocket::Web));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
async fn a_link_paid_is_answered_by_the_payee_and_finalized_by_the_payers_collect() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.funded().await;

    let address = anna.epic1_address().await.unwrap();
    let link = anna
        .epic1_link_make(
            Some(EPIC),
            Some("coffee".to_owned()),
            Epic1LinkKind::OnScreen,
            Vec::new(),
            Online,
        )
        .await
        .unwrap();
    assert_eq!(link.address, address);
    assert_eq!(link.kind, Epic1LinkKind::OnScreen);
    assert_eq!(link.n, 0);
    let links = anna.epic1_links().await.unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].kind, Epic1LinkKind::OnScreen);
    assert_eq!(links[0].used_at_ms, None);

    let read = ben
        .epic1_link_read(link.link.clone(), Online)
        .await
        .unwrap();
    assert_eq!(read.address, address);
    assert_eq!(read.amount, Some(EPIC));
    assert_eq!(read.message.as_deref(), Some("coffee"));
    assert_eq!(read.hosts.len(), 1);
    assert_eq!(read.hosts[0].host, RELAY);
    assert_eq!(read.hosts[0].class, HostClassView::Public);

    // A relay outside the relay list is not paid before the user confirmed it.
    let elsewhere = anna
        .epic1_link_make(
            Some(EPIC),
            None,
            Epic1LinkKind::Printed,
            vec!["shop.example".to_owned()],
            Online,
        )
        .await
        .unwrap();
    assert_eq!(
        kind(
            ben.epic1_pay(elsewhere.link, None, 1, None, None, false, false, Online)
                .await
        ),
        WalletErrorKind::RelayNotConfirmed
    );
    // The wallet's own relay needs no confirmation.
    let paid = ben
        .epic1_pay(link.link.clone(), None, 1, None, None, false, false, Online)
        .await
        .unwrap();
    assert_eq!(paid.address, address);
    assert_eq!(paid.posted, Some(0));
    assert_eq!(paid.attempts.len(), 1);
    assert_eq!(paid.attempts[0].error, None);
    // The payment is stored under its slate id, so a caller can find it again.
    let book = ben.session().engine_wallet().contact_book();
    let slate_id = lepic_wallet::event::SlateId::parse(&paid.slate_id).unwrap();
    let stored = book.epic1_payment(slate_id).await.unwrap().unwrap();
    assert_eq!(stored.tx_id.0, paid.tx_id);
    assert_eq!(stored.address, address);
    assert_eq!(stored.posted, Some(0));
    assert!(stored.attempts.is_empty());
    let other = lepic_wallet::event::SlateId::from_bytes([4; 16]);
    assert_eq!(book.epic1_payment(other).await.unwrap(), None);

    // The payee takes the payment and posts its answer in the same collect.
    assert_eq!(collect(&anna).await, 1);
    let answers = anna.epic1_answers(Online).await.unwrap();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].slate_id, paid.slate_id);
    assert!(answers[0].posted);
    assert!(
        anna.epic1_links()
            .await
            .unwrap()
            .iter()
            .any(|view| view.used_at_ms.is_some())
    );
    assert_eq!(world.chain.pushed_count(), 0);
    // The payer's collect finalizes.
    collect(&ben).await;
    assert_eq!(world.chain.pushed_count(), 1);

    // The payment is answered once.
    assert_eq!(collect(&anna).await, 0);
    assert_eq!(
        kind(ben.epic1_post_next(paid.slate_id, true, Online).await),
        WalletErrorKind::Epic1Finalized
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_printed_link_is_retired_once_and_bad_requests_are_refused() {
    let mut world = World::new();
    let anna = world.wallet().await;
    let ben = world.funded().await;

    let printed = anna
        .epic1_link_make(None, None, Epic1LinkKind::Printed, Vec::new(), Online)
        .await
        .unwrap();
    assert_eq!(printed.kind, Epic1LinkKind::Printed);
    let links = anna.epic1_links().await.unwrap();
    assert!(
        links
            .iter()
            .any(|view| view.kind == Epic1LinkKind::Printed && view.n == printed.n)
    );

    // A link that asks no amount is paid only with one.
    assert_eq!(
        ben.epic1_link_read(printed.link.clone(), Online)
            .await
            .unwrap()
            .amount,
        None
    );
    assert_eq!(
        kind(
            ben.epic1_pay(
                printed.link.clone(),
                None,
                1,
                None,
                None,
                false,
                true,
                Online
            )
            .await
        ),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(
            ben.epic1_pay(printed.link, Some(0), 1, None, None, false, true, Online)
                .await
        ),
        WalletErrorKind::InvalidArgument
    );

    anna.epic1_link_retire(printed.n).await.unwrap();
    assert!(anna.epic1_links().await.unwrap().is_empty());
    assert_eq!(
        kind(anna.epic1_link_retire(printed.n).await),
        WalletErrorKind::Epic1NotFound
    );

    assert_eq!(
        kind(
            anna.epic1_link_make(Some(0), None, Epic1LinkKind::OnScreen, Vec::new(), Online)
                .await
        ),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(
            anna.epic1_link_make(
                None,
                None,
                Epic1LinkKind::OnScreen,
                vec!["a.example.org".to_owned(); 4],
                Online
            )
            .await
        ),
        WalletErrorKind::Epic1RelayInvalid
    );
    assert_eq!(
        kind(ben.epic1_link_read("not a link".to_owned(), Online).await),
        WalletErrorKind::NotAnEpic1Link
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_contacts_seal_epictx_and_others_epicsealed() {
    let mut world = World::new();
    let anna = native(&mut world, true).await;
    let ben = native(&mut world, false).await;
    let (anna_side, ben_side) = pair(&anna, &ben).await;
    let slate = anna.create_send_slate(EPIC, 1, None, None).await.unwrap();
    let sealed = anna
        .contact_seal_slate(anna_side, slate.tx_id, None)
        .await
        .unwrap();
    assert!(sealed.starts_with("BEGINEPICTX."));
    assert_eq!(sealed_file_extension(sealed.clone()).unwrap(), "epictx");
    let opened = ben.epictx_open(sealed).await.unwrap();
    assert!(opened.native);
    assert_eq!(opened.contact_id, Some(ben_side));
    assert_eq!(opened.purpose, Some(SlatePurpose::Payment));
    let json: serde_json::Value = serde_json::from_str(&opened.slate_json).unwrap();
    assert!(json.is_object());

    // Contacts without native slates keep the sealed text they read today.
    let carl = world.funded().await;
    let dana = world.wallet().await;
    let (carl_side, _) = pair(&carl, &dana).await;
    let slate = carl.create_send_slate(EPIC, 1, None, None).await.unwrap();
    let sealed = carl
        .contact_seal_slate(carl_side, slate.tx_id, None)
        .await
        .unwrap();
    assert!(sealed.starts_with("BEGINEPICSEALED."));
    assert_eq!(sealed_file_extension(sealed.clone()).unwrap(), "epicsealed");
    let opened = dana.epictx_open(sealed).await.unwrap();
    assert!(!opened.native);
    assert!(opened.slate_json.contains(&slate.slate_id));

    assert_eq!(
        kind(dana.epictx_open("not sealed".to_owned()).await),
        WalletErrorKind::InvalidPairingText
    );
}
