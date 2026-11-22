// SPDX-License-Identifier: Apache-2.0
//! In-person invoices and sends through the binding, between wallets on the mock relay: the
//! code, the answer and its check code on both sides, finalizing only the answer picked, and
//! the QR parts.

use super::contact::{EPIC, World, raised};
use super::kind;
use crate::api::error::WalletErrorKind;
use crate::api::in_person::{
    in_person_link_parse, in_person_qr_parts, in_person_qr_read, in_person_request_verify,
};
use crate::api::types::{Chain, ContactRelayMode, InPersonDomainState, SlateStage, SlateWire};

use ContactRelayMode::{Offline, Online};

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
    assert!(reply.armored.starts_with("BEGINEPICTX."));
    assert_eq!(
        kind(payer.in_person_post(reply.slate_id.clone(), Offline).await),
        WalletErrorKind::ContactsOffline
    );
    // The check code comes with the post, not before it.
    let posted = payer
        .in_person_post(reply.slate_id.clone(), Online)
        .await
        .unwrap();
    assert_eq!(posted.check_code.len(), 4);
    assert!(
        posted
            .check_code
            .bytes()
            .all(|digit| digit.is_ascii_digit())
    );
    assert_eq!(posted.format, SlateWire::Native);
    // Posting again is safe, and shows the same code.
    let again = payer
        .in_person_post(reply.slate_id.clone(), Online)
        .await
        .unwrap();
    assert_eq!(again, posted);

    let mut events = shop.session().subscribe();
    shop.delivery_wake(false).await.unwrap();
    let answers: Vec<_> = raised(&mut events)
        .into_iter()
        .filter_map(|event| match event {
            lepic_wallet::Event::InPersonAnswer(answer) => Some(answer),
            _ => None,
        })
        .collect();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].check_code, posted.check_code);
    assert_eq!(answers[0].answer, 1);

    // The check code is reported; nothing is finalized until the app picks the answer.
    let view = shop.in_person_answers(code.slate_id.clone()).await.unwrap();
    assert_eq!(view.answers.len(), 1);
    assert_eq!(view.answers[0].number, 1);
    assert_eq!(view.answers[0].check_code, posted.check_code);
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
                .in_person_post(reply.slate_id.clone(), Online)
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
    assert_eq!(taken.check_code.len(), 4);
    assert!(!taken.duplicate);
    assert_eq!(world.chain.pushed_count(), 0);

    // The same answer scanned again, as QR parts, is the one already taken.
    let parts = in_person_qr_parts(reply.envelope.clone(), 100, None).unwrap();
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
fn qr_parts_take_the_callers_single_code_limit() {
    use lepic_wallet::slate::ur_slate::NATIVE_SLATE_MAGIC;
    let mut code = NATIVE_SLATE_MAGIC.to_vec();
    code.resize(300, 7);
    let default = in_person_qr_parts(code.clone(), 200, None).unwrap();
    assert_eq!(default.len(), 1);
    assert_eq!(
        in_person_qr_parts(code.clone(), 200, Some(360)).unwrap(),
        default
    );
    let split = in_person_qr_parts(code.clone(), 64, Some(64)).unwrap();
    assert_eq!(split.len(), 5 + 10);
    for part in &split {
        assert!(part.len() < default[0].len() / 3);
    }
    let read = in_person_qr_read(split).unwrap();
    assert!(read.complete);
    assert_eq!(read.bytes, Some(code.clone()));
    assert_eq!(
        kind(in_person_qr_parts(code, 200, Some(1025))),
        WalletErrorKind::InvalidArgument
    );
}

#[test]
fn qr_parts_refuse_what_is_neither_a_code_nor_an_answer() {
    assert_eq!(
        kind(in_person_qr_parts(b"plain text".to_vec(), 200, None)),
        WalletErrorKind::InvalidSlate
    );
    assert_eq!(
        kind(in_person_qr_parts(Vec::new(), 200, None)),
        WalletErrorKind::InvalidSlate
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_in_person_link_gives_back_its_code_and_an_unsigned_code_checks_as_unsigned() {
    let mut world = World::new();
    let shop = world.wallet().await;
    shop.session().scan_to_tip().await;
    let code = shop
        .in_person_invoice(2 * EPIC, None, None, Offline)
        .await
        .unwrap();
    let link = lepic_wallet_contacts::invoice_link(&code.bytes);
    assert_eq!(in_person_link_parse(link).unwrap(), code.bytes);
    assert_eq!(
        kind(in_person_link_parse("https://shop.test/pay".to_owned())),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(in_person_link_parse("epiccash://invoice/1/AAAA".to_owned())),
        WalletErrorKind::InvalidSlate
    );
    let check = in_person_request_verify(code.bytes, b"{}".to_vec(), Chain::Floonet).unwrap();
    assert_eq!(check.state, InPersonDomainState::Unsigned);
    assert_eq!((check.domain, check.reason), (None, None));
    assert_eq!(
        kind(in_person_request_verify(
            vec![0; 129 * 1024],
            Vec::new(),
            Chain::Floonet
        )),
        WalletErrorKind::InvalidSlate
    );
}
