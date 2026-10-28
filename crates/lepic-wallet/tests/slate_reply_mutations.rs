//! Mutations of a valid reply: a sender finalizes the S2 that answers its S1, and an issuer the
//! I2 that answers its I1. Every field a reply could change is changed in turn, and finalizing
//! refuses each one with a typed error and stores nothing: no S3 or I3, no new transaction state,
//! no change to the outputs, the context kept and nothing sent to the node.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "invoice/harness.rs"]
mod invoice_harness;
#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use invoice_harness::{ACCOUNT as PAYER_ACCOUNT, FUNDING, ISSUER_MNEMONIC, PAYER_MNEMONIC, Party};
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{NodeVersion, Propagation, Tip};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::hash::Hash;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{OutputRecord, ParticipantId, SlateStage, TxDirection, TxId, TxState};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::invoice::{InvoiceError, PayRequest};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use receive_harness::Receiver;
use send_support::{ACCOUNT, PEER, Sender, TIP, uuid};
use serde_json::Value;
use support::LOOPBACK;

const AMOUNT: u64 = 100_000_000;
const INVOICE_AMOUNT: u64 = 300_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

type Mutation = (&'static str, Box<dyn Fn(&mut Value)>);

/// `slate` with its JSON changed by `change`.
fn tampered(slate: &WireSlate, change: &dyn Fn(&mut Value)) -> WireSlate {
    let mut value: Value = serde_json::from_str(slate.as_text().unwrap()).unwrap();
    change(&mut value);
    WireSlate::text(MediaType::JSON, value.to_string())
}

fn participant<'a>(slate: &'a mut Value, id: &str) -> &'a mut Value {
    slate["participant_data"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|participant| participant["id"] == id)
        .unwrap()
}

/// A number field in whichever form the shape writes it, moved by `delta`.
fn shift(field: &mut Value, delta: i64) {
    let is_number = field.is_number();
    let current: i64 = match &*field {
        Value::String(text) => text.parse().unwrap(),
        Value::Null => 0,
        other => other.as_i64().unwrap(),
    };
    let moved = u64::try_from(current.saturating_add(delta).max(0)).unwrap();
    *field = if is_number {
        Value::from(moved)
    } else {
        Value::String(moved.to_string())
    };
}

/// `hex` with the digit at `index` replaced by another one.
fn flip(field: &mut Value, index: usize) {
    let hex = field.as_str().unwrap().to_owned();
    let index = index % hex.len();
    let mut digits: Vec<char> = hex.chars().collect();
    digits[index] = if digits[index] == '0' { '1' } else { '0' };
    *field = Value::String(digits.into_iter().collect());
}

#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn mutations() -> Vec<Mutation> {
    let mut cases: Vec<Mutation> = Vec::new();
    for delta in [-1i64, 1, 1_000_000_000] {
        cases.push((
            "amount",
            Box::new(move |slate| shift(&mut slate["amount"], delta)),
        ));
        cases.push((
            "fee",
            Box::new(move |slate| shift(&mut slate["fee"], delta)),
        ));
        cases.push((
            "height",
            Box::new(move |slate| shift(&mut slate["height"], delta)),
        ));
        // A field at zero cannot move down.
        if delta > 0 {
            cases.push((
                "lock_height",
                Box::new(move |slate| shift(&mut slate["lock_height"], delta)),
            ));
            cases.push((
                "ttl_cutoff_height",
                Box::new(move |slate| shift(&mut slate["ttl_cutoff_height"], delta)),
            ));
        }
        cases.push((
            "kernel fee",
            Box::new(move |slate| shift(&mut slate["tx"]["body"]["kernels"][0]["fee"], delta)),
        ));
        if delta > 0 {
            cases.push((
                "kernel lock_height",
                Box::new(move |slate| {
                    shift(&mut slate["tx"]["body"]["kernels"][0]["lock_height"], delta);
                }),
            ));
        }
    }
    cases.push((
        "kernel features",
        Box::new(|slate| {
            slate["tx"]["body"]["kernels"][0]["features"] = Value::from("HeightLocked");
        }),
    ));
    cases.push((
        "kernel removed",
        Box::new(|slate| slate["tx"]["body"]["kernels"] = Value::Array(Vec::new())),
    ));
    cases.push((
        "kernel duplicated",
        Box::new(|slate| {
            let kernel = slate["tx"]["body"]["kernels"][0].clone();
            slate["tx"]["body"]["kernels"]
                .as_array_mut()
                .unwrap()
                .push(kernel);
        }),
    ));
    for index in [0, 7, 63] {
        cases.push((
            "offset",
            Box::new(move |slate| flip(&mut slate["tx"]["offset"], index)),
        ));
    }
    cases.push((
        "input removed",
        Box::new(|slate| slate["tx"]["body"]["inputs"] = Value::Array(Vec::new())),
    ));
    cases.push((
        "input duplicated",
        Box::new(|slate| {
            let input = slate["tx"]["body"]["inputs"][0].clone();
            slate["tx"]["body"]["inputs"]
                .as_array_mut()
                .unwrap()
                .push(input);
        }),
    ));
    cases.push((
        "input replaced by an output commitment",
        Box::new(|slate| {
            let commit = slate["tx"]["body"]["outputs"][0]["commit"].clone();
            slate["tx"]["body"]["inputs"][0]["commit"] = commit;
        }),
    ));
    cases.push((
        "input features",
        Box::new(|slate| slate["tx"]["body"]["inputs"][0]["features"] = Value::from("Plain")),
    ));
    cases.push((
        "output removed",
        Box::new(|slate| {
            slate["tx"]["body"]["outputs"].as_array_mut().unwrap().pop();
        }),
    ));
    cases.push((
        "all outputs removed",
        Box::new(|slate| slate["tx"]["body"]["outputs"] = Value::Array(Vec::new())),
    ));
    cases.push((
        "output duplicated",
        Box::new(|slate| {
            let output = slate["tx"]["body"]["outputs"][1].clone();
            slate["tx"]["body"]["outputs"]
                .as_array_mut()
                .unwrap()
                .push(output);
        }),
    ));
    cases.push((
        "output commitment of another output",
        Box::new(|slate| {
            let commit = slate["tx"]["body"]["outputs"][0]["commit"].clone();
            slate["tx"]["body"]["outputs"][1]["commit"] = commit;
        }),
    ));
    cases.push((
        "output proof of another output",
        Box::new(|slate| {
            let proof = slate["tx"]["body"]["outputs"][0]["proof"].clone();
            slate["tx"]["body"]["outputs"][1]["proof"] = proof;
        }),
    ));
    cases.push((
        "output features",
        Box::new(|slate| slate["tx"]["body"]["outputs"][1]["features"] = Value::from("Coinbase")),
    ));
    cases.push((
        "outputs swapped with inputs",
        Box::new(|slate| {
            let input = slate["tx"]["body"]["inputs"][0]["commit"].clone();
            let output = slate["tx"]["body"]["outputs"][0]["commit"].clone();
            slate["tx"]["body"]["inputs"][0]["commit"] = output;
            slate["tx"]["body"]["outputs"][0]["commit"] = input;
        }),
    ));
    for (name, id) in [("sender", "0"), ("receiver", "1")] {
        for field in ["public_blind_excess", "public_nonce"] {
            for index in [2, 40] {
                let name: &'static str = Box::leak(format!("{name} {field}").into_boxed_str());
                cases.push((
                    name,
                    Box::new(move |slate| flip(&mut participant(slate, id)[field], index)),
                ));
            }
        }
    }
    cases.push((
        "receiver key replaced by the sender's",
        Box::new(|slate| {
            let key = participant(slate, "0")["public_blind_excess"].clone();
            participant(slate, "1")["public_blind_excess"] = key;
        }),
    ));
    cases.push((
        "receiver nonce replaced by the sender's",
        Box::new(|slate| {
            let nonce = participant(slate, "0")["public_nonce"].clone();
            participant(slate, "1")["public_nonce"] = nonce;
        }),
    ));
    for index in [0, 1, 63, 64, 127] {
        cases.push((
            "receiver partial signature",
            Box::new(move |slate| flip(&mut participant(slate, "1")["part_sig"], index)),
        ));
    }
    cases.push((
        "receiver partial signature removed",
        Box::new(|slate| participant(slate, "1")["part_sig"] = Value::Null),
    ));
    cases.push((
        "receiver removed",
        Box::new(|slate| {
            slate["participant_data"].as_array_mut().unwrap().pop();
        }),
    ));
    cases.push((
        "receiver listed twice",
        Box::new(|slate| {
            let entry = slate["participant_data"][1].clone();
            slate["participant_data"]
                .as_array_mut()
                .unwrap()
                .push(entry);
        }),
    ));
    cases.push((
        "participant count",
        Box::new(|slate| slate["num_participants"] = Value::from(3)),
    ));
    cases.push((
        "slate id",
        Box::new(|slate| slate["id"] = Value::from("00000000-0000-4000-8000-000000000001")),
    ));
    cases
}

// ---- S2 against our S1 ----

struct Exchange {
    sender: Sender,
    tx_id: TxId,
    slate_id: lepic_slate::model::SlateId,
    s2: WireSlate,
}

fn exchange() -> Exchange {
    let sender = Sender::new();
    let sent = sender
        .harness
        .block_on(sender.wallet.send(
            SendRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ttl_blocks: Some(1000),
                ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
            },
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let (s1, _) = sender.received().unwrap();
    let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
        .receive(FILE, s1.as_text().unwrap(), None)
        .unwrap()
        .reply;
    Exchange {
        sender,
        tx_id: sent.tx_id,
        slate_id: sent.slate_id,
        s2,
    }
}

/// Everything a finalize could change in the sender's wallet.
#[derive(Debug, PartialEq)]
struct Snapshot {
    state: TxState,
    outputs: Vec<OutputRecord>,
    transactions: usize,
    has_context: bool,
    has_s3: bool,
    pushed: usize,
}

impl Exchange {
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.sender.transactions()[0].entry.state,
            outputs: self.sender.outputs(),
            transactions: self.sender.transactions().len(),
            has_context: self.sender.has_sender_context(uuid(self.slate_id)),
            has_s3: self
                .sender
                .read(|repos| repos.slate(uuid(self.slate_id), SlateStage::Standard3))
                .is_some(),
            pushed: self.sender.harness.node.pushed_transactions().len(),
        }
    }

    /// Finalizing `s2` is refused with a typed error and changes nothing.
    fn assert_refused(&self, name: &str, s2: &WireSlate) {
        let before = self.snapshot();
        let result = self.sender.harness.block_on(self.sender.wallet.finalize(
            LOOPBACK,
            s2,
            Propagation::Stem,
        ));
        assert!(result.is_err(), "{name}: a changed reply was finalized");
        assert_eq!(self.snapshot(), before, "{name}: the refusal changed state");
        assert_eq!(before.state, TxState::Sent);
        assert!(before.has_context && !before.has_s3 && before.pushed == 0);
        let _ = self.tx_id;
    }
}

#[test]
fn a_changed_s2_is_refused_and_stores_nothing() {
    let exchange = exchange();
    for (name, change) in mutations() {
        exchange.assert_refused(name, &tampered(&exchange.s2, change.as_ref()));
    }
}

#[test]
fn the_unchanged_s2_still_finalizes_after_every_refusal() {
    let exchange = exchange();
    for (name, change) in mutations() {
        exchange.assert_refused(name, &tampered(&exchange.s2, change.as_ref()));
    }
    let finalized = exchange
        .sender
        .harness
        .block_on(
            exchange
                .sender
                .wallet
                .finalize(LOOPBACK, &exchange.s2, Propagation::Stem),
        )
        .unwrap();
    assert_eq!(finalized.tx_id, exchange.tx_id);
}

#[test]
fn an_s2_with_any_number_field_moved_or_hex_digit_flipped_is_refused() {
    let exchange = exchange();
    let numbers = ["amount", "fee", "height"];
    let strategy = (
        prop::sample::select(numbers.to_vec()),
        prop_oneof![-5_000i64..=-1, 1i64..5_000],
        0usize..2,
        0usize..64,
    );
    let mut runner = TestRunner::new(Config {
        cases: 64,
        ..Config::default()
    });
    runner
        .run(&strategy, |(field, delta, flip_receiver_nonce, digit)| {
            let change = move |slate: &mut Value| {
                shift(&mut slate[field], delta);
                if flip_receiver_nonce == 1 {
                    flip(&mut participant(slate, "1")["part_sig"], digit);
                }
            };
            let s2 = tampered(&exchange.s2, &change);
            let before = exchange.snapshot();
            let result = exchange
                .sender
                .harness
                .block_on(
                    exchange
                        .sender
                        .wallet
                        .finalize(LOOPBACK, &s2, Propagation::Stem),
                );
            if result.is_ok() {
                return Err(TestCaseError::fail(format!(
                    "{field} {delta} was finalized"
                )));
            }
            prop_assert_eq!(exchange.snapshot(), before);
            Ok(())
        })
        .unwrap();
}

// ---- I2 against our I1 ----

fn node() -> MockNode {
    MockNode::from_chain(ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(4),
            last_block_pushed: Hash::from_slice(&[0; 32]).unwrap(),
        },
    ))
}

struct Flow {
    node: MockNode,
    issuer: Party,
    slate_id: uuid::Uuid,
    i2: WireSlate,
    _payer: Party,
}

fn flow() -> Flow {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    let issued = issuer.issue(INVOICE_AMOUNT, None).unwrap();
    let i1 = issuer.delivered().unwrap();
    let payer = Party::new(PAYER_MNEMONIC, &node);
    payer.fund(0, FUNDING);
    payer.set_next_child(1);
    let i2 = payer
        .pay(
            &i1,
            PayRequest {
                minimum_confirmations: 1,
                strategy: SelectionStrategy::Smallest,
                ..PayRequest::new(PAYER_ACCOUNT, Amount::new(INVOICE_AMOUNT))
            },
        )
        .unwrap()
        .reply;
    Flow {
        node,
        issuer,
        slate_id: uuid::Uuid::from_bytes(*issued.slate_id.as_bytes()),
        i2,
        _payer: payer,
    }
}

#[derive(Debug, PartialEq)]
struct IssuerSnapshot {
    state: TxState,
    has_context: bool,
    has_i3: bool,
    pushed: usize,
}

impl Flow {
    fn snapshot(&self) -> IssuerSnapshot {
        IssuerSnapshot {
            state: self
                .issuer
                .read(|repos| repos.transaction_by_slate(self.slate_id, TxDirection::Incoming))
                .unwrap()
                .entry
                .state,
            has_context: self
                .issuer
                .read(|repos| repos.context(self.slate_id, ParticipantId(1)))
                .is_some(),
            has_i3: self
                .issuer
                .read(|repos| repos.slate(self.slate_id, SlateStage::Invoice3))
                .is_some(),
            pushed: self.node.pushed_transactions().len(),
        }
    }

    fn finalize(&self, wire: &WireSlate) -> Result<lepic_wallet::Finalized, InvoiceError> {
        self.issuer.finalize(wire)
    }

    fn assert_refused(&self, name: &str, i2: &WireSlate) {
        let before = self.snapshot();
        assert!(
            self.finalize(i2).is_err(),
            "{name}: a changed payment was finalized"
        );
        assert_eq!(self.snapshot(), before, "{name}: the refusal changed state");
        assert_eq!(before.state, TxState::Received);
        assert!(before.has_context && !before.has_i3 && before.pushed == 0);
    }
}

/// The mutations that name a participant by role: in an invoice the payer is id 0 and the
/// issuer id 1, so the receiver-side cases above apply with the roles read the other way, and
/// the transaction body differs in which side holds the inputs.
fn invoice_mutations() -> Vec<Mutation> {
    mutations()
        .into_iter()
        .filter(|(name, _)| {
            // Fields the payer owns or that the signatures do not cover: the payer sets the
            // slate height and the expiry (an invoice payment carries the payer's TTL), the
            // input flags are not part of any signature, and in this harness both parties draw
            // the same nonce, so copying one over the other changes nothing.
            !name.starts_with("receiver partial signature")
                && !matches!(
                    *name,
                    "height"
                        | "ttl_cutoff_height"
                        | "input features"
                        | "receiver nonce replaced by the sender's"
                )
        })
        .collect::<Vec<_>>()
        .into_iter()
        .chain([
            (
                "payer partial signature",
                Box::new(|slate: &mut Value| {
                    flip(&mut participant(slate, "0")["part_sig"], 5);
                }) as Box<dyn Fn(&mut Value)>,
            ),
            (
                "payer partial signature removed",
                Box::new(|slate: &mut Value| participant(slate, "0")["part_sig"] = Value::Null),
            ),
            (
                "payer partial signature last digit",
                Box::new(|slate: &mut Value| {
                    flip(&mut participant(slate, "0")["part_sig"], 127);
                }),
            ),
        ])
        .collect()
}

#[test]
fn a_changed_i2_is_refused_and_stores_nothing() {
    let flow = flow();
    for (name, change) in invoice_mutations() {
        flow.assert_refused(name, &tampered(&flow.i2, change.as_ref()));
    }
    // The unchanged payment still goes through afterwards.
    flow.finalize(&flow.i2).unwrap();
    assert_eq!(flow.snapshot().state, TxState::Posted);
}
