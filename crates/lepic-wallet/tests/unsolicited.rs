// SPDX-License-Identifier: Apache-2.0
//! Payments nobody asked for, as a listener receives them: open receipts of one transport are
//! capped in total, and an S1 received before is still answered at the cap.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod support;

use lepic_node::mock::MockFailure;
use lepic_store::{TxId, TxState, WalletStore};
use lepic_transport::file::FILE;
use lepic_transport::transport::TransportId;
use lepic_wallet::inbox::MAX_OPEN_RECEIPTS;
use lepic_wallet::{ReceiveError, ReceiveRequest, Received};
use receive_harness::*;

const VECTOR_SLATE_ID: &str = "0436430c-2b02-624c-2032-570501212b03";

/// The upstream S1 vector under slate id number `n`, so each is a new payment.
fn s1_numbered(n: u32) -> String {
    let s1 = json(&vector("send_file_ttl_s1_v3"));
    assert!(s1.contains(VECTOR_SLATE_ID));
    s1.replace(
        VECTOR_SLATE_ID,
        &format!("00000000-0000-4000-8000-{n:012x}"),
    )
}

fn receiver() -> Receiver {
    let s1 = vector("send_file_ttl_s1_v3");
    let s2 = vector("send_file_ttl_s2_v3");
    Receiver::new(&receiver_mnemonic(&s2), slate_height(&s1))
}

fn unsolicited(
    receiver: &Receiver,
    transport: TransportId,
    n: u32,
) -> Result<Received, ReceiveError> {
    receiver.block_on(receiver.wallet.receive_unsolicited(
        transport,
        &wire(&s1_numbered(n)),
        ReceiveRequest::default(),
    ))
}

/// Fills the open receipts over the file transport to the cap, after one over the stand-in
/// Epicbox transport. Returns the file receipts, oldest first.
fn fill_to_cap(receiver: &Receiver) -> Vec<TxId> {
    unsolicited(receiver, EPICBOX, 10_000).unwrap();
    let cap = u32::try_from(MAX_OPEN_RECEIPTS).unwrap();
    (0..cap)
        .map(|n| unsolicited(receiver, FILE, n).unwrap().tx_id)
        .collect()
}

fn open_receipts(receiver: &Receiver, transport: TransportId) -> Vec<TxId> {
    receiver
        .store()
        .read(|repos| repos.open_receipts(transport.as_str()))
        .unwrap()
        .into_iter()
        .map(|receipt| receipt.id)
        .collect()
}

fn state_of(receiver: &Receiver, tx_id: TxId) -> TxState {
    receiver
        .store()
        .read(|repos| repos.transaction(tx_id))
        .unwrap()
        .unwrap()
        .state
}

#[test]
fn at_the_cap_a_new_payment_is_refused_and_no_open_receipt_is_cancelled() {
    let receiver = receiver();
    let filled = fill_to_cap(&receiver);
    let epicbox = open_receipts(&receiver, EPICBOX);
    let before = receiver.transaction_count();
    assert_eq!(open_receipts(&receiver, FILE).len(), MAX_OPEN_RECEIPTS);

    let refused = unsolicited(&receiver, FILE, 1_000);

    assert!(
        matches!(refused, Err(ReceiveError::OpenReceipts(None))),
        "{refused:?}"
    );
    for tx_id in &filled {
        assert_eq!(state_of(&receiver, *tx_id), TxState::Received);
    }
    assert_eq!(receiver.transaction_count(), before);
    assert_eq!(open_receipts(&receiver, EPICBOX), epicbox);
}

#[test]
fn at_the_cap_a_payment_received_before_gets_its_stored_reply_again() {
    let receiver = receiver();
    let filled = fill_to_cap(&receiver);
    let first = receiver
        .store()
        .read(|repos| {
            let slate_id = repos.transaction(filled[5])?.unwrap().slate_id.unwrap();
            repos.slate(slate_id, lepic_store::SlateStage::Standard2)
        })
        .unwrap()
        .unwrap();

    let again = unsolicited(&receiver, FILE, 5).unwrap();

    assert!(again.repeated);
    assert_eq!(again.tx_id, filled[5]);
    assert_eq!(again.reply.as_bytes(), first.bytes);
    for tx_id in &filled {
        assert_eq!(state_of(&receiver, *tx_id), TxState::Received);
    }
}

#[test]
fn at_the_cap_a_node_that_cannot_be_asked_still_refuses_the_new_payment() {
    let receiver = receiver();
    fill_to_cap(&receiver);
    let before = receiver.transaction_count();
    receiver
        .node
        .fail_next("get_unconfirmed_transactions", MockFailure::Unreachable);

    let refused = unsolicited(&receiver, FILE, 1_000);

    assert!(
        matches!(refused, Err(ReceiveError::OpenReceipts(_))),
        "{refused:?}"
    );
    assert_eq!(receiver.transaction_count(), before);
    assert_eq!(open_receipts(&receiver, FILE).len(), MAX_OPEN_RECEIPTS);
}

#[test]
fn below_the_cap_a_slate_that_is_not_a_payment_is_rejected_as_by_receive() {
    let receiver = receiver();
    let s2 = json(&vector("send_file_ttl_s2_v3"));

    let rejected = receiver.block_on(receiver.wallet.receive_unsolicited(
        FILE,
        &wire(&s2),
        ReceiveRequest::default(),
    ));

    assert!(
        matches!(rejected, Err(ReceiveError::WrongStage { .. })),
        "{rejected:?}"
    );
}
