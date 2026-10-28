// SPDX-License-Identifier: Apache-2.0
//! An issuer may hand the payer any I1 it likes. Whatever field of a valid I1 is changed, paying
//! it either refuses with a typed error and leaves the payer's wallet as it was, or pays exactly
//! the approved amount plus the fee of an honest payment of the same invoice: the issuer cannot
//! make the payer spend more, pay a fee it set, lock coins it did not select, or pay twice.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "invoice/harness.rs"]
mod harness;
mod support;

use harness::{ACCOUNT, FUNDING, ISSUER_MNEMONIC, PAYER_MNEMONIC, Party};
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{NodeVersion, Tip};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::hash::Hash;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{OutputRecord, OutputStatus, TxDirection};
use lepic_wallet::invoice::PayRequest;
use lepic_wallet::selection::SelectionStrategy;
use serde_json::Value;

const AMOUNT: u64 = 300_000_000;
const TIP: u64 = 4;
/// A second coin the payer holds, which no honest payment of [`AMOUNT`] needs.
const SPARE: u64 = 2_000_000_000;

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

fn tampered(wire: &WireSlate, change: &dyn Fn(&mut Value)) -> WireSlate {
    let mut slate: Value = serde_json::from_str(wire.as_text().unwrap()).unwrap();
    change(&mut slate);
    WireSlate::text(MediaType::JSON, slate.to_string())
}

/// A number field in whichever form the shape writes it, set to `value`.
fn set_number(field: &mut Value, value: u64) {
    *field = match field {
        Value::Number(_) => Value::from(value),
        _ => Value::String(value.to_string()),
    };
}

fn number(field: &Value) -> u64 {
    match field {
        Value::String(text) => text.parse().unwrap(),
        other => other.as_u64().unwrap(),
    }
}

fn flip(field: &mut Value, index: usize) {
    let Some(hex) = field.as_str().map(str::to_owned) else {
        return;
    };
    let index = index % hex.len();
    let mut digits: Vec<char> = hex.chars().collect();
    digits[index] = if digits[index] == '0' { '1' } else { '0' };
    *field = Value::String(digits.into_iter().collect());
}

struct World {
    _node: MockNode,
    payer: Party,
    i1: WireSlate,
}

/// An invoice for [`AMOUNT`] issued to a payer holding the funding coin and a spare one.
fn world() -> World {
    let node = node();
    let issuer = Party::new(ISSUER_MNEMONIC, &node);
    issuer.issue(AMOUNT, None).unwrap();
    let i1 = issuer.delivered().unwrap();
    let payer = Party::new(PAYER_MNEMONIC, &node);
    payer.fund(0, FUNDING);
    payer.fund(1, SPARE);
    payer.set_next_child(2);
    World {
        _node: node,
        payer,
        i1,
    }
}

impl World {
    fn outputs(&self) -> Vec<OutputRecord> {
        self.payer.read(|repos| repos.outputs(ACCOUNT, None))
    }

    fn transactions(&self) -> usize {
        self.payer.read(|repos| repos.transactions(ACCOUNT)).len()
    }

    /// What the payer gave up: the coins it locked minus the change it gets back.
    fn debit(&self) -> u64 {
        let outputs = self.outputs();
        let locked: u64 = outputs
            .iter()
            .filter(|output| output.status == OutputStatus::Locked)
            .map(|output| output.amount.value())
            .sum();
        let change: u64 = outputs
            .iter()
            .filter(|output| output.status == OutputStatus::Unconfirmed)
            .map(|output| output.amount.value())
            .sum();
        locked - change
    }
}

/// The fee and debit of the honest payment of the unchanged I1.
fn honest() -> (u64, u64) {
    let world = world();
    let paid = world.payer.pay(&world.i1, request()).unwrap();
    let reply: Value = serde_json::from_str(paid.reply.as_text().unwrap()).unwrap();
    let fee = number(&reply["fee"]);
    assert_eq!(world.debit(), AMOUNT + fee);
    (fee, world.debit())
}

type Mutation = (&'static str, Box<dyn Fn(&mut Value)>);

fn participant<'a>(slate: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    slate["participant_data"]
        .as_array_mut()?
        .iter_mut()
        .find(|participant| {
            participant["id"] == id || participant["id"].as_u64() == id.parse::<u64>().ok()
        })
}

#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn mutations() -> Vec<Mutation> {
    let cases: Vec<Mutation> = vec![
        (
            "fee set by the issuer",
            Box::new(|s| set_number(&mut s["fee"], 1_000_000_000)),
        ),
        ("fee of one", Box::new(|s| set_number(&mut s["fee"], 1))),
        (
            "fee at u64 max",
            Box::new(|s| set_number(&mut s["fee"], u64::MAX)),
        ),
        (
            "amount at u64 max",
            Box::new(|s| set_number(&mut s["amount"], u64::MAX)),
        ),
        ("amount zero", Box::new(|s| set_number(&mut s["amount"], 0))),
        (
            "amount one more",
            Box::new(|s| set_number(&mut s["amount"], AMOUNT + 1)),
        ),
        (
            "height at u64 max",
            Box::new(|s| set_number(&mut s["height"], u64::MAX)),
        ),
        (
            "lock height far ahead",
            Box::new(|s| set_number(&mut s["lock_height"], 10_000_000)),
        ),
        (
            "lock height at u64 max",
            Box::new(|s| set_number(&mut s["lock_height"], u64::MAX)),
        ),
        (
            "ttl in the past",
            Box::new(|s| s["ttl_cutoff_height"] = Value::from("1")),
        ),
        (
            "ttl at u64 max",
            Box::new(|s| set_number(&mut s["ttl_cutoff_height"], u64::MAX)),
        ),
        (
            "three participants",
            Box::new(|s| s["num_participants"] = Value::from(3)),
        ),
        (
            "one participant",
            Box::new(|s| s["num_participants"] = Value::from(1)),
        ),
        (
            "kernel fee set by the issuer",
            Box::new(|s| set_number(&mut s["tx"]["body"]["kernels"][0]["fee"], 1_000_000_000)),
        ),
        (
            "kernel height locked far ahead",
            Box::new(|s| {
                let kernel = &mut s["tx"]["body"]["kernels"][0];
                kernel["features"] = Value::from("HeightLocked");
                set_number(&mut kernel["lock_height"], 10_000_000);
            }),
        ),
        (
            "kernel coinbase",
            Box::new(|s| s["tx"]["body"]["kernels"][0]["features"] = Value::from("Coinbase")),
        ),
        (
            "two kernels",
            Box::new(|s| {
                let kernel = s["tx"]["body"]["kernels"][0].clone();
                s["tx"]["body"]["kernels"]
                    .as_array_mut()
                    .unwrap()
                    .push(kernel);
            }),
        ),
        (
            "issuer output duplicated",
            Box::new(|s| {
                let output = s["tx"]["body"]["outputs"][0].clone();
                s["tx"]["body"]["outputs"]
                    .as_array_mut()
                    .unwrap()
                    .push(output);
            }),
        ),
        (
            "issuer output coinbase",
            Box::new(|s| s["tx"]["body"]["outputs"][0]["features"] = Value::from("Coinbase")),
        ),
        (
            "issuer output removed",
            Box::new(|s| s["tx"]["body"]["outputs"] = Value::Array(Vec::new())),
        ),
        (
            "issuer output proof damaged",
            Box::new(|s| flip(&mut s["tx"]["body"]["outputs"][0]["proof"], 100)),
        ),
        (
            "input the issuer slipped in",
            Box::new(|s| {
                let commit = s["tx"]["body"]["outputs"][0]["commit"].clone();
                s["tx"]["body"]["inputs"] =
                    serde_json::json!([{ "features": "Plain", "commit": commit }]);
            }),
        ),
        (
            "offset changed",
            Box::new(|s| flip(&mut s["tx"]["offset"], 3)),
        ),
        (
            "issuer excess changed",
            Box::new(|s| {
                if let Some(issuer) = participant(s, "1") {
                    flip(&mut issuer["public_blind_excess"], 9);
                }
            }),
        ),
        (
            "issuer nonce changed",
            Box::new(|s| {
                if let Some(issuer) = participant(s, "1") {
                    flip(&mut issuer["public_nonce"], 9);
                }
            }),
        ),
        (
            "issuer listed twice",
            Box::new(|s| {
                let entry = s["participant_data"][0].clone();
                s["participant_data"].as_array_mut().unwrap().push(entry);
            }),
        ),
        (
            "issuer entry under the payer's id",
            Box::new(|s| {
                if let Some(issuer) = participant(s, "1") {
                    issuer["id"] = match issuer["id"] {
                        Value::String(_) => Value::from("0"),
                        _ => Value::from(0),
                    };
                }
            }),
        ),
        (
            "issuer partial signature already present",
            Box::new(|s| {
                if let Some(issuer) = participant(s, "1") {
                    issuer["part_sig"] = Value::from("00".repeat(64));
                }
            }),
        ),
        (
            "no participants",
            Box::new(|s| s["participant_data"] = Value::Array(Vec::new())),
        ),
        (
            "payment proof naming the issuer as sender",
            Box::new(|s| {
                s["payment_proof"] = serde_json::json!({
                    "receiver_address": "esZ6EqGXXdcwvgmBLmiPHRuW9eLjS68rRb5Ff6DshVJKX1DmUVQZ",
                    "receiver_signature": null,
                    "sender_address": "esZ6EqGXXdcwvgmBLmiPHRuW9eLjS68rRb5Ff6DshVJKX1DmUVQZ",
                });
            }),
        ),
        ("slate id empty", Box::new(|s| s["id"] = Value::from(""))),
    ];
    cases
}

/// Pays `i1`, which differs from the honest invoice by `name`: either it is refused and nothing
/// changed, or it is paid exactly as the honest invoice is. Returns whether it was paid.
fn refused_or_paid_honestly(world: &World, i1: &WireSlate, name: &str, honest: (u64, u64)) -> bool {
    let (honest_fee, honest_debit) = honest;
    let before = world.outputs();
    match world.payer.pay(i1, request()) {
        Err(_) => {
            assert_eq!(
                world.outputs(),
                before,
                "{name}: a refusal changed the outputs"
            );
            assert_eq!(
                world.transactions(),
                0,
                "{name}: a refusal stored a payment"
            );
            false
        }
        Ok(payment) => {
            let reply: Value = serde_json::from_str(payment.reply.as_text().unwrap()).unwrap();
            assert_eq!(
                number(&reply["fee"]),
                honest_fee,
                "{name}: the payer paid a fee the issuer chose"
            );
            assert_eq!(
                world.debit(),
                honest_debit,
                "{name}: the payer gave up more"
            );
            let spare_locked = world.outputs().iter().any(|output| {
                output.amount.value() == SPARE && output.status != OutputStatus::Unspent
            });
            assert!(
                !spare_locked,
                "{name}: a coin the payment does not need was locked"
            );
            true
        }
    }
}

#[test]
fn a_changed_invoice_is_refused_or_paid_for_exactly_the_approved_amount_and_honest_fee() {
    let honest = honest();
    let mut paid = Vec::new();
    for (name, change) in mutations() {
        let world = world();
        let i1 = tampered(&world.i1, change.as_ref());
        if refused_or_paid_honestly(&world, &i1, name, honest) {
            paid.push(name);
        }
    }
    eprintln!("mutations the payer still paid: {paid:?}");
}

/// The number fields of an I1, by JSON pointer.
const NUMBER_FIELDS: [&str; 7] = [
    "/amount",
    "/fee",
    "/height",
    "/lock_height",
    "/ttl_cutoff_height",
    "/tx/body/kernels/0/fee",
    "/tx/body/kernels/0/lock_height",
];

#[test]
fn any_number_an_issuer_writes_into_an_invoice_is_refused_or_paid_honestly() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

    let honest = honest();
    // Seeded, so a failure repeats; the seed is printed with it.
    let seed = [7u8; 32];
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases: 48,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    );
    let value = prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(u64::MAX),
        Just(AMOUNT),
        any::<u64>(),
        0u64..10_000_000,
    ];
    runner
        .run(
            &(0..NUMBER_FIELDS.len(), value, any::<bool>()),
            |(field, value, as_text)| {
                let world = world();
                let pointer = NUMBER_FIELDS[field];
                let i1 = tampered(&world.i1, &|slate| {
                    if let Some(target) = slate.pointer_mut(pointer) {
                        *target = if as_text {
                            Value::String(value.to_string())
                        } else {
                            Value::from(value)
                        };
                    }
                });
                let name = format!("{pointer} = {value} (seed {seed:?})");
                refused_or_paid_honestly(&world, &i1, &name, honest);
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn an_invoice_delivered_twice_is_paid_once() {
    let world = world();
    let first = world.payer.pay(&world.i1, request()).unwrap();
    let outputs = world.outputs();
    let second = world.payer.pay(&world.i1, request());
    // Either refused, or the stored answer again with nothing new locked or signed.
    if let Ok(again) = second {
        assert_eq!(again.tx_id, first.tx_id);
        assert_eq!(again.reply, first.reply);
    }
    assert_eq!(world.outputs(), outputs);
    assert_eq!(world.transactions(), 1);
    assert_eq!(
        world.debit(),
        AMOUNT + {
            let reply: Value = serde_json::from_str(first.reply.as_text().unwrap()).unwrap();
            number(&reply["fee"])
        }
    );
}

#[test]
fn an_invoice_under_another_slate_id_is_a_second_approval_not_a_replay_of_the_first() {
    // The issuer can always ask again under a new id; what matters is that each payment needs
    // its own approval and locks its own coins, never the first payment's.
    let world = world();
    let first = world.payer.pay(&world.i1, request()).unwrap();
    let renamed = tampered(&world.i1, &|s| {
        s["id"] = Value::from("6f3a1c2e-5b7d-4e8f-9a0b-1c2d3e4f5a6b");
    });
    let before = world.outputs();
    if let Ok(second) = world.payer.pay(&renamed, request()) {
        assert_ne!(second.tx_id, first.tx_id);
        let first_inputs: Vec<_> = before
            .iter()
            .filter(|output| output.tx == Some(first.tx_id))
            .map(|output| output.id.commitment)
            .collect();
        for output in world.outputs() {
            if output.tx == Some(second.tx_id) && output.status == OutputStatus::Locked {
                assert!(
                    !first_inputs.contains(&output.id.commitment),
                    "a coin was locked by two payments"
                );
            }
        }
    }
    let payments = world
        .payer
        .read(|repos| repos.transactions(ACCOUNT))
        .into_iter()
        .filter(|stored| stored.entry.direction == TxDirection::Outgoing)
        .count();
    assert!(payments <= 2);
}

/// `wire` with a key holding `depth` nested arrays added at its top level, built as text so the
/// test itself never recurses that deep.
fn nested(wire: &WireSlate, depth: usize) -> WireSlate {
    let text = wire.as_text().unwrap();
    let extra = format!(r#"{{"extra":{}{},"#, "[".repeat(depth), "]".repeat(depth));
    WireSlate::text(MediaType::JSON, text.replacen('{', &extra, 1))
}

#[test]
fn a_deeply_nested_invoice_is_refused_without_exhausting_the_stack() {
    for depth in [64usize, 1_000, 100_000] {
        let world = world();
        let before = world.outputs();
        let i1 = nested(&world.i1, depth);
        // A phone runs the wallet on threads with far less stack than a desktop test thread.
        let result = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(512 * 1024)
                .spawn_scoped(scope, || world.payer.pay(&i1, request()).is_ok())
                .unwrap()
                .join()
        });
        let paid = result.unwrap_or_else(|_| panic!("depth {depth}: paying panicked"));
        // An unknown key may be ignored as upstream ignores it; a refusal stores nothing.
        if !paid {
            assert_eq!(world.outputs(), before, "depth {depth}");
            assert_eq!(world.transactions(), 0, "depth {depth}");
        }
    }
}
