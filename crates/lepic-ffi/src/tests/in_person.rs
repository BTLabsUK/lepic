// SPDX-License-Identifier: Apache-2.0
//! In-person invoices and sends through the binding, between wallets on the mock relay: the
//! code, the answer and its check code on both sides, finalizing only the answer picked, the
//! QR parts, and the native-slates switch.

use super::contact::{EPIC, World, pair, raised};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::in_person::{in_person_qr_parts, in_person_qr_read};
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{CollectTrigger, ContactRelayMode, SlateStage};
use crate::api::wallet::EpicWallet;

use ContactRelayMode::{Offline, Online};

/// Creates a wallet in `store` with native slates set as `native_direct` and opens it again,
/// so the setting is in use.
async fn reopened(world: &mut World, native_direct: bool) -> EpicWallet {
    let config = world.config(super::contact::RELAY);
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
    wallet.set_native_direct(native_direct).unwrap();
    drop(wallet);
    EpicWallet::open(&world.runtime, config, &store, "password".to_owned())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_slates_are_off_by_default_and_saved_for_the_next_open() {
    let mut world = World::new();
    let config = world.config(super::contact::RELAY);
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
    assert!(!wallet.native_direct());
    assert!(!wallet.native_direct_in_use());
    wallet.set_native_direct(true).unwrap();
    assert!(wallet.native_direct());
    // The session keeps the value it opened with.
    assert!(!wallet.native_direct_in_use());
    drop(wallet);
    let wallet = EpicWallet::open(
        &world.runtime,
        config.clone(),
        &store,
        "password".to_owned(),
    )
    .await
    .unwrap();
    assert!(wallet.native_direct());
    assert!(wallet.native_direct_in_use());
    // Setting it twice either way is safe.
    wallet.set_native_direct(true).unwrap();
    wallet.set_native_direct(false).unwrap();
    wallet.set_native_direct(false).unwrap();
    assert!(!wallet.native_direct());
    drop(wallet);
    let wallet = EpicWallet::open(&world.runtime, config, &store, "password".to_owned())
        .await
        .unwrap();
    assert!(!wallet.native_direct_in_use());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contact_shows_native_slates_only_with_native_slates_on() {
    let mut world = World::new();
    let anna = reopened(&mut world, true).await;
    let ben = reopened(&mut world, false).await;
    let cara = reopened(&mut world, true).await;
    let dina = reopened(&mut world, true).await;
    // A wallet with native slates off claims none, and shows none.
    pair(&anna, &ben).await;
    let anna_view = anna.contacts().await.unwrap();
    assert_eq!(anna_view.len(), 1);
    assert!(!anna_view[0].native_slates);
    let ben_view = ben.contacts().await.unwrap();
    assert_eq!(ben_view.len(), 1);
    assert!(!ben_view[0].native_slates);
    // Two wallets with it on claim it to each other.
    pair(&cara, &dina).await;
    assert!(cara.contacts().await.unwrap()[0].native_slates);
    assert!(dina.contacts().await.unwrap()[0].native_slates);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
async fn an_invoice_paid_in_person_is_finalized_only_when_its_answer_is_picked() {
    let mut world = World::new();
    let payer = world.funded().await;
    let shop = world.wallet().await;
    shop.session().scan_to_tip().await;
    let code = shop
        .in_person_invoice(2 * EPIC, Some("coffee".to_owned()), None, Online)
        .await
        .unwrap();
    assert!(code.mailbox.is_some());
    assert_eq!(
        kind(shop.in_person_invoice(0, None, None, Online).await),
        WalletErrorKind::InvalidArgument
    );

    let read = payer
        .in_person_read(code.bytes.clone(), 1, None, Online)
        .await
        .unwrap();
    assert_eq!(read.slate_id, code.slate_id);
    assert_eq!(read.stage, SlateStage::I1);
    assert_eq!(read.amount, 2 * EPIC);
    assert_eq!(read.message.as_deref(), Some("coffee"));
    assert!(read.fee.is_some());
    assert!(read.mailbox.is_some());
    assert_eq!(
        kind(
            payer
                .in_person_read(b"not a code".to_vec(), 1, None, Online)
                .await
        ),
        WalletErrorKind::InvalidSlate
    );

    let reply = payer
        .in_person_pay(code.bytes.clone(), 2 * EPIC, 1, None, None, Online)
        .await
        .unwrap();
    assert_eq!(reply.slate_id, code.slate_id);
    assert_eq!(reply.check_code.len(), 4);
    assert!(reply.armored.starts_with("BEGINEPICTX."));
    assert_eq!(
        kind(
            payer
                .in_person_post(reply.slate_id.clone(), false, Online)
                .await
        ),
        WalletErrorKind::RelayNotConfirmed
    );
    assert_eq!(
        kind(
            payer
                .in_person_post(reply.slate_id.clone(), true, Offline)
                .await
        ),
        WalletErrorKind::ContactsOffline
    );
    payer
        .in_person_post(reply.slate_id.clone(), true, Online)
        .await
        .unwrap();
    // Posting again is safe.
    payer
        .in_person_post(reply.slate_id.clone(), true, Online)
        .await
        .unwrap();

    let mut events = shop.session().subscribe();
    let collected = shop
        .contacts_collect(CollectTrigger::Pull, Online, None)
        .await
        .unwrap();
    assert_eq!(collected.in_person, 1);
    let answers: Vec<_> = raised(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            lepic_wallet::Event::InPersonAnswer(answer) => Some(answer),
            _ => None,
        })
        .collect();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].check_code, reply.check_code);
    assert_eq!(answers[0].answer, 1);

    // The check code is reported; nothing is finalized until the app picks the answer.
    let view = shop.in_person_answers(code.slate_id.clone()).await.unwrap();
    assert_eq!(view.answers.len(), 1);
    assert_eq!(view.answers[0].number, 1);
    assert_eq!(view.answers[0].check_code, reply.check_code);
    assert!(!view.answers[0].same_code);
    assert_eq!(view.finalized, None);
    assert_eq!(world.chain.pushed_count(), 0);

    assert_eq!(
        kind(shop.in_person_finalize(code.slate_id.clone(), 2).await),
        WalletErrorKind::InPersonNotFound
    );
    let finalized = shop
        .in_person_finalize(code.slate_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(finalized.slate_id, code.slate_id);
    assert!(finalized.posted);
    assert_eq!(world.chain.pushed_count(), 1);
    let view = shop.in_person_answers(code.slate_id.clone()).await.unwrap();
    assert_eq!(view.finalized, Some(1));
    assert!(view.closed);
    assert_eq!(
        kind(
            shop.in_person_answers("00000000-0000-4000-8000-000000000000".to_owned())
                .await
        ),
        WalletErrorKind::InPersonNotFound
    );
    assert_eq!(
        kind(shop.in_person_answers("not a slate id".to_owned()).await),
        WalletErrorKind::InvalidArgument
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_person_send_takes_its_ttl_from_the_app_and_refuses_a_short_one() {
    let mut world = World::new();
    let sender = world.funded().await;
    for short in [10, 0] {
        assert_eq!(
            kind(
                sender
                    .in_person_send(EPIC / 10, 1, None, None, Some(short), Offline)
                    .await
            ),
            WalletErrorKind::InvalidArgument,
            "ttl {short}"
        );
    }
    let default = sender
        .in_person_send(EPIC / 10, 1, None, None, None, Offline)
        .await
        .unwrap();
    // The one coin is locked by the first send; cancelling it frees the coin.
    sender.cancel_transaction(default.tx_id).await.unwrap();
    let eleven = sender
        .in_person_send(EPIC / 10, 1, None, None, Some(11), Offline)
        .await
        .unwrap();
    // The chain does not move between the calls, so the cutoffs differ by the TTLs.
    assert_eq!(default.ttl_cutoff - eleven.ttl_cutoff, 30 - 11);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_received_in_person_takes_the_answer_shown_back() {
    let mut world = World::new();
    let sender = world.funded().await;
    let receiver = world.wallet().await;
    receiver.session().scan_to_tip().await;
    let code = sender
        .in_person_send(EPIC, 1, Some("change".to_owned()), None, None, Offline)
        .await
        .unwrap();
    assert_eq!(code.mailbox, None);

    let read = receiver
        .in_person_read(code.bytes.clone(), 1, None, Offline)
        .await
        .unwrap();
    assert_eq!(read.stage, SlateStage::S1);
    assert_eq!(read.amount, EPIC);
    assert!(read.mailbox.is_none());
    let reply = receiver
        .in_person_receive(code.bytes.clone(), None, Offline)
        .await
        .unwrap();
    assert_eq!(reply.slate_id, code.slate_id);
    assert!(reply.mailbox.is_none());
    assert_eq!(
        kind(
            receiver
                .in_person_post(reply.slate_id.clone(), true, Online)
                .await
        ),
        WalletErrorKind::InPersonNoMailbox
    );

    // A raw code is not an answer.
    assert_eq!(
        kind(sender.in_person_take(code.bytes.clone()).await),
        WalletErrorKind::InvalidSlate
    );
    let taken = sender
        .in_person_take(reply.armored.clone().into_bytes())
        .await
        .unwrap();
    assert_eq!(taken.slate_id, code.slate_id);
    assert_eq!(taken.answer, 1);
    assert_eq!(taken.check_code, reply.check_code);
    assert!(!taken.duplicate);
    assert_eq!(world.chain.pushed_count(), 0);

    // The same answer scanned again, as QR parts, is the one already taken.
    let parts = in_person_qr_parts(reply.envelope.clone(), 100).unwrap();
    assert!(parts.len() > 1);
    let first = in_person_qr_read(parts[..1].to_vec()).unwrap();
    assert!(!first.complete);
    assert_eq!(first.bytes, None);
    assert_eq!(
        kind(sender.in_person_take_qr(parts[..1].to_vec()).await),
        WalletErrorKind::UrCodeIncomplete
    );
    let whole = in_person_qr_read(parts.clone()).unwrap();
    assert!(whole.complete);
    assert_eq!(whole.bytes.as_deref(), Some(reply.envelope.as_slice()));
    let again = sender.in_person_take_qr(parts).await.unwrap();
    assert!(again.duplicate);
    assert_eq!(again.answer, 1);
    assert_eq!(world.chain.pushed_count(), 0);

    let view = sender
        .in_person_answers(code.slate_id.clone())
        .await
        .unwrap();
    assert_eq!(view.answers.len(), 1);
    assert_eq!(view.finalized, None);
    sender
        .in_person_finalize(code.slate_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(world.chain.pushed_count(), 1);
}

#[test]
fn qr_parts_refuse_what_is_neither_a_code_nor_an_answer() {
    assert_eq!(
        kind(in_person_qr_parts(b"plain text".to_vec(), 200)),
        WalletErrorKind::InvalidSlate
    );
    assert_eq!(
        kind(in_person_qr_parts(Vec::new(), 200)),
        WalletErrorKind::InvalidSlate
    );
}
