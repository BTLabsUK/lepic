//! The invoice flow between two LEPIC wallets over the file method: the issuer stores and
//! delivers I1, the payer stores its locked inputs and returns I2, the issuer finalizes, stores
//! I3, drops its private context and posts. Slates that do not fit the step, or whose data does
//! not check, are refused with nothing stored; finalizing again is harmless.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

#[path = "invoice/harness.rs"]
mod invoice_harness;
#[path = "receive/harness.rs"]
mod receive_harness;
mod support;

use invoice_harness::{ACCOUNT, FUNDING, ISSUER_MNEMONIC, PAYER_MNEMONIC, Party};
use lepic_node::mock::{ChainState, MockFailure, MockNode};
use lepic_node::{NodeVersion, Tip};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::hash::Hash;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{
    OutputStatus, ParticipantId, SlateStage, StoredTransaction, TxDirection, TxId, TxState,
};
use lepic_wallet::event::TransactionState;
use lepic_wallet::invoice::{InvoiceError, InvoiceField, PayRequest};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::{Event, WalletError};
use serde_json::Value;
use uuid::Uuid;

const AMOUNT: u64 = 300_000_000;
const TIP: u64 = 4;

fn node() -> MockNode {
    MockNode::from_chain(ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(TIP),
            last_block_pushed: Hash::from_slice(&[0; 32]).unwrap(),
        },
    ))
}

fn request() -> PayRequest {
    PayRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..PayRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

/// A payer holding one coinbase output of `funding` at child 0.
fn payer(node: &MockNode, funding: u64) -> Party {
    let payer = Party::new(PAYER_MNEMONIC, node);
    payer.fund(0, funding);
    payer.set_next_child(1);
    payer
}

/// An issued invoice, the I1 the issuer delivered and the I2 a LEPIC payer answered.
struct Flow {
    node: MockNode,
    issuer: Party,
    payer: Party,
    tx_id: TxId,
    slate_id: Uuid,
    i1: WireSlate,
    i2: WireSlate,
}

fn flow(issuer_message: Option<&str>, request: PayRequest) -> Flow {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    let issued = issuer.issue(AMOUNT, issuer_message).unwrap();
    let i1 = issuer.delivered().unwrap();
    let payer = payer(&node, FUNDING);
    let i2 = payer.pay(&i1, request).unwrap().reply;
    Flow {
        node,
        issuer,
        payer,
        tx_id: issued.tx_id,
        slate_id: Uuid::from_bytes(*issued.slate_id.as_bytes()),
        i1,
        i2,
    }
}

fn transaction(party: &Party, slate_id: Uuid, direction: TxDirection) -> StoredTransaction {
    party
        .read(|repos| repos.transaction_by_slate(slate_id, direction))
        .unwrap()
}

impl Flow {
    fn state(&self) -> TxState {
        transaction(&self.issuer, self.slate_id, TxDirection::Incoming)
            .entry
            .state
    }

    fn has_context(&self) -> bool {
        self.issuer
            .read(|repos| repos.context(self.slate_id, ParticipantId(1)))
            .is_some()
    }

    fn has_i3(&self) -> bool {
        self.issuer
            .read(|repos| repos.slate(self.slate_id, SlateStage::Invoice3))
            .is_some()
    }

    /// Nothing of a finalize was stored: the invoice still waits for its payment.
    fn assert_untouched(&self) {
        assert_eq!(self.state(), TxState::Received);
        assert!(self.has_context());
        assert!(!self.has_i3());
        assert!(self.node.pushed_transactions().is_empty());
    }
}

type Change = Box<dyn FnOnce(&mut Value)>;

/// `wire` with its JSON changed by `change`.
fn tampered(wire: &WireSlate, change: impl FnOnce(&mut Value)) -> WireSlate {
    let mut slate: Value = serde_json::from_str(wire.as_text().unwrap()).unwrap();
    change(&mut slate);
    WireSlate::text(MediaType::JSON, slate.to_string())
}

fn participant<'a>(slate: &'a mut Value, id: &str) -> &'a mut Value {
    slate["participant_data"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|participant| participant["id"] == id)
        .unwrap()
}

fn transaction_events(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
) -> Vec<(TxState, TxState)> {
    let mut changes = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transaction(TransactionState { from, to, .. }) = event {
            changes.push((from, to));
        }
    }
    changes
}

#[test]
fn issuing_stores_the_invoice_and_delivers_the_i1() {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);

    let issued = issuer.issue(AMOUNT, Some("for the bike")).unwrap();

    assert_eq!(issued.amount, Amount::new(AMOUNT));
    let delivered = issuer.delivered().unwrap();
    let text = delivered.as_text().unwrap();
    // The file method writes a new slate without TTL in the V2 shape with a version 2 header.
    assert!(text.starts_with(r#"{"version_info":{"version":2,"orig_version":2,"#));
    let slate_id = Uuid::from_bytes(*issued.slate_id.as_bytes());
    let entry = transaction(&issuer, slate_id, TxDirection::Incoming);
    assert_eq!(entry.id, issued.tx_id);
    assert_eq!(entry.entry.state, TxState::Received);
    assert_eq!(entry.entry.amount_credited, Amount::new(AMOUNT));
    assert_eq!(entry.entry.fee, None);
    let outputs = issuer.read(|repos| repos.outputs_of_transaction(issued.tx_id));
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].status, OutputStatus::Unconfirmed);
    assert_eq!(outputs[0].amount, Amount::new(AMOUNT));
    assert!(
        issuer
            .read(|repos| repos.context(slate_id, ParticipantId(1)))
            .is_some()
    );
    assert!(
        issuer
            .read(|repos| repos.slate(slate_id, SlateStage::Invoice1))
            .is_some()
    );
}

#[test]
fn paying_locks_the_inputs_and_stores_the_i2_reply() {
    let flow = flow(Some("for the bike"), request());

    let entry = transaction(&flow.payer, flow.slate_id, TxDirection::Outgoing);
    assert_eq!(entry.entry.state, TxState::Sent);
    assert_eq!(entry.entry.amount_debited, Amount::new(FUNDING));
    let fee = entry.entry.fee.unwrap();
    let outputs = flow.payer.read(|repos| repos.outputs(ACCOUNT, None));
    let locked: Vec<_> = outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Locked)
        .collect();
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].amount, Amount::new(FUNDING));
    let change: Vec<_> = outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .collect();
    assert_eq!(change.len(), 1);
    assert_eq!(
        change[0].amount.value(),
        FUNDING - AMOUNT - fee.value(),
        "change pays amount and fee"
    );
    let stored = flow
        .payer
        .read(|repos| repos.slate(flow.slate_id, SlateStage::Invoice2))
        .unwrap();
    assert_eq!(stored.bytes, flow.i2.as_bytes());
    // The payer keeps no private context; the issuer signs last.
    assert!(
        flow.payer
            .read(|repos| repos.context(flow.slate_id, ParticipantId(0)))
            .is_none()
    );
}

#[test]
fn finalizing_stores_i3_drops_the_context_and_posts_the_transaction() {
    let flow = flow(Some("for the bike"), request());
    let mut events = flow.issuer.wallet.subscribe();

    let finalized = flow.issuer.finalize(&flow.i2).unwrap();

    assert_eq!(finalized.tx_id, flow.tx_id);
    assert_eq!(finalized.slate.stage(), Stage::I3);
    let issuer = finalized.slate.participant(Role::Receiver).unwrap();
    assert_eq!(issuer.message.as_ref().unwrap().text(), "for the bike");
    finalized.transaction.validate().unwrap();
    assert_eq!(
        flow.node.pushed_transactions(),
        vec![finalized.transaction.clone()]
    );
    assert_eq!(flow.state(), TxState::Posted);
    assert!(!flow.has_context());
    assert!(flow.has_i3());
    assert_eq!(
        transaction_events(&mut events),
        vec![
            (TxState::Received, TxState::Finalized),
            (TxState::Finalized, TxState::Posted),
        ]
    );
}

#[test]
fn finalizing_the_same_i2_again_returns_the_stored_result_without_posting_again() {
    let flow = flow(None, request());
    let first = flow.issuer.finalize(&flow.i2).unwrap();

    let second = flow.issuer.finalize(&flow.i2).unwrap();

    assert_eq!(second, first);
    assert_eq!(flow.node.pushed_transactions().len(), 1);
    assert_eq!(flow.state(), TxState::Posted);
}

#[test]
fn another_payment_of_a_finalized_invoice_is_refused() {
    let flow = flow(None, request());
    flow.issuer.finalize(&flow.i2).unwrap();
    // A second wallet of the same seed pays from a different output.
    let other = payer(&flow.node, FUNDING + 1);
    let other_i2 = other.pay(&flow.i1, request()).unwrap().reply;

    let error = flow.issuer.finalize(&other_i2).unwrap_err();

    assert!(
        matches!(error, InvoiceError::AlreadyFinalized { tx_id, .. } if tx_id == flow.tx_id),
        "{error:?}"
    );
    assert_eq!(flow.node.pushed_transactions().len(), 1);
}

#[test]
fn a_post_the_node_refused_is_retried_by_finalizing_again() {
    let flow = flow(None, request());
    flow.node
        .fail_next("push_transaction", MockFailure::Unreachable);

    let error = flow.issuer.finalize(&flow.i2).unwrap_err();

    assert!(
        matches!(error, InvoiceError::NotPosted { tx_id, .. } if tx_id == flow.tx_id),
        "{error:?}"
    );
    assert_eq!(flow.state(), TxState::Finalized);
    assert!(flow.has_i3());

    flow.issuer.finalize(&flow.i2).unwrap();

    assert_eq!(flow.state(), TxState::Posted);
    assert_eq!(flow.node.pushed_transactions().len(), 1);
}

#[test]
fn a_payers_ttl_does_not_reach_the_issuer_over_the_file_method() {
    let flow = flow(
        None,
        PayRequest {
            ttl_blocks: Some(2),
            ..request()
        },
    );
    // The payer wrote the V3 shape for its TTL under the version 2 header of the I1.
    let i2: Value = serde_json::from_str(flow.i2.as_text().unwrap()).unwrap();
    assert_eq!(i2["ttl_cutoff_height"], "6");
    assert_eq!(i2["version_info"]["version"], 2);
    flow.node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 5));

    let finalized = flow.issuer.finalize(&flow.i2).unwrap();

    assert_eq!(finalized.slate.ttl_cutoff_height(), None);
    assert_eq!(flow.state(), TxState::Posted);
}

#[test]
fn an_invoice_for_another_amount_than_approved_is_refused() {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    issuer.issue(AMOUNT, None).unwrap();
    let i1 = issuer.delivered().unwrap();
    let payer = payer(&node, FUNDING);

    let error = payer
        .pay(
            &i1,
            PayRequest {
                amount: Amount::new(AMOUNT - 1),
                ..request()
            },
        )
        .unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::AmountMismatch { invoiced, approved }
                if invoiced == Amount::new(AMOUNT) && approved == Amount::new(AMOUNT - 1)
        ),
        "{error:?}"
    );
    assert!(payer.read(|repos| repos.transactions(ACCOUNT)).is_empty());
}

#[test]
fn an_invoice_is_paid_once() {
    let flow = flow(None, request());

    let error = flow.payer.pay(&flow.i1, request()).unwrap_err();

    assert!(
        matches!(error, InvoiceError::AlreadyPaid { .. }),
        "{error:?}"
    );
    assert_eq!(
        flow.payer.read(|repos| repos.transactions(ACCOUNT)).len(),
        1
    );
}

#[test]
fn paying_refuses_a_slate_that_is_not_an_invoice() {
    let flow = flow(None, request());
    let other = payer(&flow.node, FUNDING);

    let error = other.pay(&flow.i2, request()).unwrap_err();

    assert!(
        matches!(error, InvoiceError::WrongStage { stage: Stage::I2 }),
        "{error:?}"
    );
    assert!(other.read(|repos| repos.transactions(ACCOUNT)).is_empty());
}

#[test]
fn paying_refuses_an_invoice_past_its_ttl() {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    issuer.issue(AMOUNT, None).unwrap();
    // An I1 in the V3 shape with a version 3 header, which the file method reads with its TTL.
    let i1 = tampered(&issuer.delivered().unwrap(), |slate| {
        slate["version_info"]["version"] = Value::from(3);
        slate["version_info"]["orig_version"] = Value::from(3);
        slate["ttl_cutoff_height"] = Value::from(TIP.to_string());
        slate["payment_proof"] = Value::Null;
    });
    let payer = payer(&node, FUNDING);

    let error = payer.pay(&i1, request()).unwrap_err();

    assert!(
        matches!(error, InvoiceError::Expired { cutoff, tip }
            if cutoff == Height::new(TIP) && tip == Height::new(TIP)),
        "{error:?}"
    );
    assert!(payer.read(|repos| repos.transactions(ACCOUNT)).is_empty());
}

#[test]
fn paying_refuses_an_invoice_whose_message_signature_does_not_verify() {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    issuer.issue(AMOUNT, Some("for the bike")).unwrap();
    let i1 = tampered(&issuer.delivered().unwrap(), |slate| {
        participant(slate, "1")["message"] = Value::from("for the car");
    });
    let payer = payer(&node, FUNDING);

    let error = payer.pay(&i1, request()).unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::MessageSignature {
                role: Role::Receiver,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(payer.read(|repos| repos.transactions(ACCOUNT)).is_empty());
}

#[test]
fn finalizing_refuses_a_payment_that_changed_the_invoice() {
    let flow = flow(None, request());
    let payer_excess = {
        let mut i2: Value = serde_json::from_str(flow.i2.as_text().unwrap()).unwrap();
        participant(&mut i2, "0")["public_blind_excess"].clone()
    };
    let cases: [(InvoiceField, Change); 3] = [
        (
            InvoiceField::Amount,
            Box::new(|slate| slate["amount"] = Value::from((AMOUNT + 1).to_string())),
        ),
        (
            InvoiceField::Offset,
            // The issuer's RNG repeats the byte 1, so its offset is all 01.
            Box::new(|slate| slate["tx"]["offset"] = Value::from("02".repeat(32))),
        ),
        (
            InvoiceField::Issuer,
            Box::new(move |slate| participant(slate, "1")["public_nonce"] = payer_excess),
        ),
    ];
    for (field, change) in cases {
        let error = flow
            .issuer
            .finalize(&tampered(&flow.i2, change))
            .unwrap_err();

        assert!(
            matches!(error, InvoiceError::Mismatch { field: got } if got == field),
            "{field}: {error:?}"
        );
        flow.assert_untouched();
    }
}

#[test]
fn finalizing_refuses_a_payer_signature_over_another_fee() {
    let flow = flow(None, request());
    let raised = tampered(&flow.i2, |slate| {
        let fee = slate["fee"].as_str().unwrap().parse::<u64>().unwrap() + 1_000_000;
        slate["fee"] = Value::from(fee.to_string());
        slate["tx"]["body"]["kernels"][0]["fee"] = Value::from(fee.to_string());
    });

    let error = flow.issuer.finalize(&raised).unwrap_err();

    assert!(
        matches!(error, InvoiceError::PayerSignature(_)),
        "{error:?}"
    );
    flow.assert_untouched();
}

#[test]
fn finalizing_refuses_a_slate_that_answers_no_issued_invoice() {
    let flow = flow(None, request());
    let foreign = tampered(&flow.i2, |slate| {
        slate["id"] = Value::from("0436430c-2b02-624c-2032-570501212bff");
    });

    let unknown = flow.issuer.finalize(&foreign).unwrap_err();
    let early = flow.issuer.finalize(&flow.i1).unwrap_err();

    assert!(
        matches!(unknown, InvoiceError::UnknownSlate { .. }),
        "{unknown:?}"
    );
    assert!(
        matches!(early, InvoiceError::WrongStage { stage: Stage::I1 }),
        "{early:?}"
    );
    flow.assert_untouched();
}

#[test]
fn a_cancelled_invoice_is_not_finalized() {
    let flow = flow(None, request());
    flow.issuer
        .block_on(flow.issuer.wallet.cancel(flow.tx_id))
        .unwrap();
    assert!(!flow.has_context());
    assert!(
        flow.issuer
            .read(|repos| repos.outputs_of_transaction(flow.tx_id))
            .is_empty()
    );

    let error = flow.issuer.finalize(&flow.i2).unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::NotFinalizable {
                state: TxState::Cancelled,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(flow.node.pushed_transactions().is_empty());
}

#[test]
fn a_locked_wallet_issues_nothing() {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    issuer.wallet.lock();

    let error = issuer.issue(AMOUNT, None).unwrap_err();

    assert!(
        matches!(error, InvoiceError::Wallet(WalletError::Locked)),
        "{error:?}"
    );
    assert!(issuer.delivered().is_none());
}
