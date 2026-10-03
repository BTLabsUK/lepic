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
use lepic_crypto::SecretKey;
use lepic_keychain::Identifier;
use lepic_node::mock::{ChainState, MockFailure, MockNode};
use lepic_node::{LocatedKernel, NodeVersion, Tip};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::params::Network;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{EncodeContext, MediaType, WireSlate};
use lepic_slate::error::{DecodeError, ValidationError};
use lepic_slate::model::SlateId;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::role::Role;
use lepic_slate::stage::Stage;
use lepic_store::{
    OutputRecord, OutputStatus, ParticipantId, SlateStage, StoredTransaction, TxDirection, TxId,
    TxState,
};
use lepic_transport::file::FilePolicy;
use lepic_transport::policy::FormatPolicy;
use lepic_wallet::event::TransactionState;
use lepic_wallet::invoice::{
    BuiltI1, I1Plan, I1Randomness, I2Plan, I2Randomness, InvoiceError, InvoiceField, PayRequest,
    build_i1, build_i2, build_i3,
};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::ChangeOutput;
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

fn slate_value(wire: &WireSlate) -> Value {
    serde_json::from_str(wire.as_text().unwrap()).unwrap()
}

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
fn a_restored_wallet_issues_invoices_only_after_its_restore_scan() {
    let node = node();
    let issuer = Party::restored_without_scan(ISSUER_MNEMONIC, &node);

    let error = issuer.issue(AMOUNT, None).unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::Wallet(WalletError::RestoreScanRequired)
        ),
        "{error:?}"
    );
    assert!(issuer.read(|repos| repos.transactions(ACCOUNT)).is_empty());
    assert!(issuer.delivered().is_none());
    issuer
        .block_on(issuer.wallet.scan(
            lepic_wallet::scan::ScanOptions::restore(Network::Floonet),
            &lepic_wallet::scan::ScanCancel::new(),
        ))
        .unwrap();
    issuer.issue(AMOUNT, None).unwrap();
}

#[test]
fn a_restored_wallet_pays_an_invoice_with_change_only_after_its_restore_scan() {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    issuer.issue(AMOUNT, None).unwrap();
    let i1 = issuer.delivered().unwrap();
    let payer = Party::restored_without_scan(PAYER_MNEMONIC, &node);
    payer.fund(0, FUNDING);
    payer.set_next_child(1);

    let error = payer.pay(&i1, request()).unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::Wallet(WalletError::RestoreScanRequired)
        ),
        "{error:?}"
    );
    assert!(payer.read(|repos| repos.transactions(ACCOUNT)).is_empty());
    let funding = payer.read(|repos| repos.outputs(ACCOUNT, None));
    assert!(
        funding
            .iter()
            .all(|output| output.status == OutputStatus::Unspent)
    );
}

#[test]
fn issuing_stores_the_invoice_and_delivers_the_i1() {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);

    let issued = issuer.issue(AMOUNT, Some("for the bike")).unwrap();

    assert_eq!(issued.amount, Amount::new(AMOUNT));
    let delivered = issuer.delivered().unwrap();
    let text = delivered.as_text().unwrap();
    // The file method writes every slate in the V3 shape with a version 3 header (ADR 0015).
    assert!(text.starts_with(r#"{"version_info":{"version":3,"orig_version":3,"#));
    assert!(text.contains(r#""ttl_cutoff_height":null"#));
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
fn a_payers_ttl_reaches_the_issuer_over_the_file_method() {
    let flow = flow(
        None,
        PayRequest {
            ttl_blocks: Some(2),
            ..request()
        },
    );
    // The payer raised the version 2 header of the I1 to 3, so the issuer reads the TTL.
    let i2: Value = serde_json::from_str(flow.i2.as_text().unwrap()).unwrap();
    assert_eq!(i2["ttl_cutoff_height"], "6");
    assert_eq!(i2["version_info"]["version"], 3);
    assert_eq!(i2["version_info"]["orig_version"], 3);
    flow.node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 1));

    let finalized = flow.issuer.finalize(&flow.i2).unwrap();

    assert_eq!(
        finalized.slate.ttl_cutoff_height(),
        Some(Height::new(TIP + 2))
    );
    assert_eq!(flow.state(), TxState::Posted);
}

#[test]
fn a_ttl_under_a_version_two_header_does_not_reach_the_issuer() {
    let flow = flow(
        None,
        PayRequest {
            ttl_blocks: Some(2),
            ..request()
        },
    );
    // A payer that writes the V3 shape under the version 2 header of the I1, as `epic-wallet`'s
    // file method does; the file method then reads the slate without its TTL.
    let i2 = tampered(&flow.i2, |slate| {
        slate["version_info"]["version"] = Value::from(2);
        slate["version_info"]["orig_version"] = Value::from(2);
    });
    flow.node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 5));

    let finalized = flow.issuer.finalize(&i2).unwrap();

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
    let issuer_commit = slate_value(&flow.i1)["tx"]["body"]["outputs"][0]["commit"].clone();
    let is_issuers = move |output: &Value| output["commit"] == issuer_commit;
    // A second payer of the same seed answers the same invoice from another output.
    let other_change = {
        let other = payer(&flow.node, FUNDING + 1);
        let other_i2 = slate_value(&other.pay(&flow.i1, request()).unwrap().reply);
        let outputs = other_i2["tx"]["body"]["outputs"].as_array().unwrap();
        outputs
            .iter()
            .find(|output| !is_issuers(output))
            .unwrap()
            .clone()
    };
    let dropped = is_issuers.clone();
    let replaced = is_issuers;
    let cases: [(InvoiceField, Change); 6] = [
        (
            InvoiceField::Lock,
            Box::new(|slate| {
                slate["lock_height"] = Value::from("5");
                let kernel = &mut slate["tx"]["body"]["kernels"][0];
                kernel["features"] = Value::from("HeightLocked");
                kernel["lock_height"] = Value::from("5");
            }),
        ),
        (
            InvoiceField::Outputs,
            Box::new(move |slate| {
                let outputs = slate["tx"]["body"]["outputs"].as_array_mut().unwrap();
                outputs.retain(|output| !dropped(output));
            }),
        ),
        (
            InvoiceField::Outputs,
            Box::new(move |slate| {
                let outputs = slate["tx"]["body"]["outputs"].as_array_mut().unwrap();
                let issuers = outputs.iter().position(replaced).unwrap();
                outputs[issuers] = other_change;
            }),
        ),
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

#[test]
fn finalizing_refuses_a_payer_message_whose_signature_does_not_verify() {
    let flow = flow(
        None,
        PayRequest {
            message: Some("paid in full".to_owned()),
            ..request()
        },
    );
    let forged = tampered(&flow.i2, |slate| {
        participant(slate, "0")["message"] = Value::from("paid in part");
    });

    let error = flow.issuer.finalize(&forged).unwrap_err();

    assert!(
        matches!(
            error,
            InvoiceError::MessageSignature {
                role: Role::Sender,
                ..
            }
        ),
        "{error:?}"
    );
    flow.assert_untouched();
}

#[test]
fn finalizing_refuses_an_i2_past_its_ttl() {
    let flow = flow(
        None,
        PayRequest {
            ttl_blocks: Some(2),
            ..request()
        },
    );
    flow.node
        .update_chain(|chain| chain.tip.height = Height::new(TIP + 2));

    let error = flow.issuer.finalize(&flow.i2).unwrap_err();

    assert!(
        matches!(error, InvoiceError::Expired { cutoff, tip }
            if cutoff == Height::new(TIP + 2) && tip == Height::new(TIP + 2)),
        "{error:?}"
    );
    flow.assert_untouched();
}

/// The I1 the issuer's wallet built: its RNG repeats the byte 1, so every value it drew is
/// all 01.
fn rebuilt_i1(flow: &Flow) -> BuiltI1 {
    let ones = || SecretKey::from_array([1; 32]).unwrap();
    let built = build_i1(
        &flow.issuer.keychain,
        &I1Plan {
            account: ACCOUNT,
            amount: Amount::new(AMOUNT),
            height: Height::new(TIP),
            key_id: Identifier::new(3, [0, 0, 0, 0]).unwrap(),
            message: None,
        },
        I1Randomness {
            slate_id: SlateId::from_random_bytes([1; 16]),
            offset: ones(),
            nonce: ones(),
            message_nonce: ones(),
        },
    )
    .unwrap();
    let delivered = FilePolicy.decode(&codecs(), &flow.i1).unwrap();
    assert_eq!(delivered.with_origin(None), built.slate);
    built
}

fn codecs() -> CodecRegistry {
    let base_fee = Network::Floonet.params().default_base_fee();
    let mut codecs = CodecRegistry::new();
    codecs
        .register(Box::new(V3JsonCodec::new(base_fee)))
        .unwrap();
    codecs
        .register(Box::new(V2JsonCodec::new(base_fee)))
        .unwrap();
    codecs
}

#[test]
fn a_fee_below_the_minimum_is_refused_even_when_the_payer_signed_it() {
    let flow = flow(None, request());
    let issued = rebuilt_i1(&flow);
    let base_fee = Network::Floonet.params().default_base_fee();
    let minimum = finalized_fee(&flow);
    let fee = Fee::new(minimum.value() - 100_000);
    let funding = flow
        .payer
        .read(|repos| repos.outputs(ACCOUNT, None))
        .into_iter()
        .find(|output| output.amount == Amount::new(FUNDING))
        .unwrap();
    let low = build_i2(
        &flow.payer.keychain,
        &issued.slate,
        &I2Plan {
            fee,
            height: Height::new(TIP),
            ttl_cutoff_height: None,
            inputs: vec![OutputRecord {
                status: OutputStatus::Unspent,
                tx: None,
                ..funding
            }],
            change: vec![ChangeOutput {
                key_id: Identifier::new(3, [0, 0, 9, 0]).unwrap(),
                amount: Amount::new(FUNDING - AMOUNT - fee.value()),
            }],
            message: None,
        },
        &I2Randomness {
            nonce: SecretKey::from_array([2; 32]).unwrap(),
            message_nonce: SecretKey::from_array([2; 32]).unwrap(),
        },
    )
    .unwrap();

    let built = build_i3(base_fee, &issued, &low).unwrap_err();
    assert!(
        matches!(built, InvoiceError::FeeBelowMinimum { fee: got, minimum: needed }
            if got == fee && needed == minimum),
        "{built:?}"
    );

    // Over the wire the legacy decoder refuses the fee before the issuer's own check.
    let wire = FilePolicy
        .encode_reply(
            &codecs(),
            &low,
            &EncodeContext {
                block_header_version: 6,
            },
        )
        .unwrap();
    let error = flow.issuer.finalize(&wire).unwrap_err();
    assert!(
        matches!(
            error,
            InvoiceError::Decode(DecodeError::Validation(
                ValidationError::FeeBelowMinimum { .. }
            ))
        ),
        "{error:?}"
    );
    flow.assert_untouched();
}

/// The fee the payer chose, which selection sets to the minimum for the body.
fn finalized_fee(flow: &Flow) -> Fee {
    transaction(&flow.payer, flow.slate_id, TxDirection::Outgoing)
        .entry
        .fee
        .unwrap()
}

#[test]
fn invoice_error_text_carries_no_amounts() {
    let errors = [
        InvoiceError::AmountMismatch {
            invoiced: Amount::new(123_456_789),
            approved: Amount::new(987_654_321),
        },
        InvoiceError::FeeBelowMinimum {
            fee: Fee::new(123_456_789),
            minimum: Fee::new(987_654_321),
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(
            !text.contains("123456789") && !text.contains("987654321"),
            "{text}"
        );
    }
}

#[test]
fn a_payment_without_change_is_confirmed_by_its_kernel() {
    // One input and the issuer's output: weight 4, at the floonet base fee of 100,000.
    const NO_CHANGE_FEE: u64 = 400_000;
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    let issued = issuer.issue(AMOUNT, None).unwrap();
    let slate_id = Uuid::from_bytes(*issued.slate_id.as_bytes());
    let payer = payer(&node, AMOUNT + NO_CHANGE_FEE);
    let paid = payer.pay(&issuer.delivered().unwrap(), request()).unwrap();
    let finalized = issuer.finalize(&paid.reply).unwrap();
    let payment = transaction(&payer, slate_id, TxDirection::Outgoing);
    assert_eq!(payment.entry.amount_credited, Amount::ZERO);

    let kernel = *finalized.transaction.kernels().first().unwrap();
    let before = payer
        .block_on(payer.wallet.transaction_details(payment.id))
        .unwrap();
    // The payer never receives the I3; its kernel comes from the stored I2.
    assert_eq!(before.kernel_excess, Some(kernel.excess));
    assert_eq!(before.confirmed_height, None);
    node.update_chain(|chain| {
        chain.tip.height = Height::new(TIP + 1);
        chain.kernels.push(LocatedKernel {
            kernel,
            height: Height::new(TIP + 1),
            mmr_index: 1,
        });
    });
    payer.block_on(payer.wallet.refresh()).unwrap();

    assert_eq!(
        transaction(&payer, slate_id, TxDirection::Outgoing)
            .entry
            .state,
        TxState::Confirmed
    );
    let after = payer
        .block_on(payer.wallet.transaction_details(payment.id))
        .unwrap();
    assert_eq!(after.kernel_excess, Some(kernel.excess));
    assert_eq!(after.confirmed_height, Some(Height::new(TIP + 1)));
}

#[test]
fn a_finalized_invoice_the_node_refused_is_posted_by_post() {
    let flow = flow(None, request());
    flow.node
        .fail_next("push_transaction", MockFailure::Unreachable);
    flow.issuer.finalize(&flow.i2).unwrap_err();
    assert_eq!(flow.state(), TxState::Finalized);

    flow.issuer
        .block_on(
            flow.issuer
                .wallet
                .post(flow.tx_id, lepic_node::Propagation::Fluff),
        )
        .unwrap();

    assert_eq!(flow.state(), TxState::Posted);
    assert_eq!(flow.node.pushed_transactions().len(), 1);
}

#[test]
fn a_refused_push_of_an_invoice_whose_kernel_is_on_chain_is_posted() {
    let flow = flow(None, request());
    flow.node
        .fail_next("push_transaction", MockFailure::Unreachable);
    flow.issuer.finalize(&flow.i2).unwrap_err();
    let stored = flow
        .issuer
        .read(|repos| repos.slate(flow.slate_id, SlateStage::Invoice3))
        .unwrap();
    let i3 = lepic_slate::codec::Codec::decode(
        &V3JsonCodec::new(Network::Floonet.params().default_base_fee()),
        &WireSlate::binary(MediaType::JSON, stored.bytes),
    )
    .unwrap();
    flow.node.update_chain(|chain| {
        chain.tip.height = Height::new(TIP + 1);
        chain.kernels.push(LocatedKernel {
            kernel: i3.kernel().unwrap(),
            height: Height::new(TIP + 1),
            mmr_index: 1,
        });
    });
    flow.node.fail_next(
        "push_transaction",
        MockFailure::Rejected(lepic_node::RejectionKind::Internal),
    );

    flow.issuer.finalize(&flow.i2).unwrap();

    assert_eq!(flow.state(), TxState::Posted);
    assert!(flow.node.pushed_transactions().is_empty());
}
