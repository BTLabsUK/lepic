//! Whole transactions: their layouts and hashes, and the outcome of the node's
//! `Transaction::validate(Weighting::AsTransaction)`. Every invalid case breaks exactly one rule
//! and is otherwise a valid transaction, so the rule that fails does not depend on the order in
//! which a validator checks them.

use epic_core::core::hash::Hashed;
use epic_core::core::transaction::{
    self as transaction, KernelFeatures, OutputFeatures, Transaction, Weighting, aggregate,
};
use epic_core::libtx::tx_fee;
use epic_core::ser::{self, ProtocolVersion};
use epic_keychain::BlindingFactor;
use epic_util::secp::Secp256k1;
use serde::Serialize;

use super::AREA;
use super::build::{Coin, OutputSpec, TxSpec, TxSpecJson, signed_kernel};
use super::fixtures::{TransactionJson, ensure, secp, secret, ser_error_name, unexpected};
use crate::{Error, Pins, Rendered, hex, render};

/// The rule a transaction breaks, named after the upstream check that rejects it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Rule {
    SortOrder,
    Duplicate,
    CutThrough,
    RangeProof,
    KernelSignature,
    OutputFeatures,
    KernelFeatures,
    KernelSum,
}

fn broken_rule(error: &transaction::Error) -> Option<Rule> {
    use epic_core::core::committed;
    match error {
        transaction::Error::Serialization(ser::Error::SortError) => Some(Rule::SortOrder),
        transaction::Error::Serialization(ser::Error::DuplicateError) => Some(Rule::Duplicate),
        transaction::Error::CutThrough => Some(Rule::CutThrough),
        transaction::Error::Secp(_) => Some(Rule::RangeProof),
        transaction::Error::IncorrectSignature => Some(Rule::KernelSignature),
        transaction::Error::InvalidOutputFeatures => Some(Rule::OutputFeatures),
        transaction::Error::InvalidKernelFeatures => Some(Rule::KernelFeatures),
        transaction::Error::Committed(committed::Error::KernelSumMismatch) => Some(Rule::KernelSum),
        _ => None,
    }
}

/// How a case departs from the transaction its spec builds, applied after signing.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mutation {
    None,
    /// The offset is replaced by `ALT_OFFSET`; the kernel is unchanged.
    ReplaceOffset,
    /// The kernel signature is replaced by one over the message of the fee plus one.
    SignOtherFee,
    /// The range proofs of the first two outputs are exchanged.
    SwapProofs,
    /// The outputs are put in descending hash order.
    ReverseOutputs,
}

const ALT_OFFSET: [u8; 32] = [0x3f; 32];

struct Case {
    name: &'static str,
    spec: TxSpec,
    mutation: Mutation,
    broken: Option<Rule>,
}

#[derive(Serialize)]
struct CaseInputs {
    spec: TxSpecJson,
    mutation: Mutation,
}

#[derive(Serialize)]
struct AggregateInputs {
    specs: Vec<TxSpecJson>,
}

/// `rule` and `upstream_error` are null for a valid transaction.
#[derive(Serialize)]
struct Validation {
    valid: bool,
    rule: Option<Rule>,
    upstream_error: Option<String>,
}

/// `decode_v2` is the result of the node reading `serialized_v2`, which runs its read-time checks
/// (weight, sort order, cut-through, features) but not proofs, signatures or sums.
#[derive(Serialize)]
struct CaseExpected {
    transaction: TransactionJson,
    fee: String,
    weight: usize,
    serialized_v1: String,
    serialized_v2: String,
    hash: String,
    decode_v2: String,
    validation: Validation,
}

fn fee(inputs: usize, outputs: usize) -> u64 {
    tx_fee(inputs, outputs, 1, None)
}

fn out(value: u64, blind: u8) -> OutputSpec {
    OutputSpec::new(Coin::plain(value, blind))
}

fn spend(inputs: &[u64], outputs: &[u64], fee: u64) -> Result<u64, Error> {
    let total_in = inputs.iter().try_fold(0u64, |sum, v| sum.checked_add(*v));
    let total_out = outputs.iter().try_fold(fee, |sum, v| sum.checked_add(*v));
    total_in
        .zip(total_out)
        .and_then(|(i, o)| i.checked_sub(o))
        .ok_or_else(|| unexpected("case amounts fit in u64"))
}

fn cases() -> Result<Vec<Case>, Error> {
    let fee_1_2 = fee(1, 2);
    let fee_2_2 = fee(2, 2);
    let fee_1_1 = fee(1, 1);
    let change_1_2 = spend(&[2_000_000_000], &[1_500_000_000], fee_1_2)?;
    let change_2_2 = spend(&[700_000_000, 600_000_000], &[1_000_000_000], fee_2_2)?;
    let only_1_1 = spend(&[2_000_000_000], &[], fee_1_1)?;
    let standard = || TxSpec {
        inputs: vec![Coin::plain(2_000_000_000, 0x11)],
        outputs: vec![out(1_500_000_000, 0x21), out(change_1_2, 0x22)],
        features: KernelFeatures::Plain { fee: fee_1_2 },
        offset: [0x31; 32],
        kernel_nonce: [0x32; 32],
    };
    Ok(vec![
        Case {
            name: "tx_valid_plain_1_in_2_out",
            spec: standard(),
            mutation: Mutation::None,
            broken: None,
        },
        Case {
            name: "tx_valid_height_locked_2_in_2_out",
            spec: TxSpec {
                inputs: vec![
                    Coin::plain(700_000_000, 0x12),
                    Coin::plain(600_000_000, 0x13),
                ],
                outputs: vec![out(1_000_000_000, 0x23), out(change_2_2, 0x24)],
                features: KernelFeatures::HeightLocked {
                    fee: fee_2_2,
                    lock_height: 1_000_000,
                },
                offset: [0x33; 32],
                kernel_nonce: [0x34; 32],
            },
            mutation: Mutation::None,
            broken: None,
        },
        Case {
            name: "tx_valid_spends_coinbase_1_in_1_out",
            spec: TxSpec {
                inputs: vec![Coin {
                    features: OutputFeatures::Coinbase,
                    ..Coin::plain(2_000_000_000, 0x14)
                }],
                outputs: vec![out(only_1_1, 0x25)],
                features: KernelFeatures::Plain { fee: fee_1_1 },
                offset: [0x35; 32],
                kernel_nonce: [0x36; 32],
            },
            mutation: Mutation::None,
            broken: None,
        },
        Case {
            name: "tx_invalid_kernel_sum_offset",
            spec: standard(),
            mutation: Mutation::ReplaceOffset,
            broken: Some(Rule::KernelSum),
        },
        Case {
            name: "tx_invalid_kernel_signature",
            spec: standard(),
            mutation: Mutation::SignOtherFee,
            broken: Some(Rule::KernelSignature),
        },
        Case {
            name: "tx_invalid_range_proof",
            spec: standard(),
            mutation: Mutation::SwapProofs,
            broken: Some(Rule::RangeProof),
        },
        Case {
            name: "tx_invalid_unsorted_outputs",
            spec: standard(),
            mutation: Mutation::ReverseOutputs,
            broken: Some(Rule::SortOrder),
        },
        Case {
            name: "tx_invalid_duplicate_outputs",
            spec: TxSpec {
                outputs: vec![
                    out(750_000_000, 0x26),
                    out(750_000_000, 0x26),
                    out(
                        spend(&[2_000_000_000], &[750_000_000, 750_000_000], fee(1, 3))?,
                        0x27,
                    ),
                ],
                features: KernelFeatures::Plain { fee: fee(1, 3) },
                ..standard()
            },
            mutation: Mutation::None,
            broken: Some(Rule::Duplicate),
        },
        Case {
            name: "tx_invalid_cut_through",
            spec: TxSpec {
                inputs: vec![
                    Coin::plain(2_000_000_000, 0x11),
                    Coin::plain(300_000_000, 0x28),
                ],
                outputs: vec![
                    out(300_000_000, 0x28),
                    out(spend(&[2_000_000_000], &[], fee(2, 2))?, 0x29),
                ],
                features: KernelFeatures::Plain { fee: fee(2, 2) },
                ..standard()
            },
            mutation: Mutation::None,
            broken: Some(Rule::CutThrough),
        },
        Case {
            name: "tx_invalid_coinbase_output",
            spec: TxSpec {
                outputs: vec![
                    OutputSpec::new(Coin {
                        features: OutputFeatures::Coinbase,
                        ..Coin::plain(1_500_000_000, 0x2a)
                    }),
                    out(change_1_2, 0x22),
                ],
                ..standard()
            },
            mutation: Mutation::None,
            broken: Some(Rule::OutputFeatures),
        },
        Case {
            name: "tx_invalid_coinbase_kernel",
            spec: TxSpec {
                outputs: vec![
                    out(1_500_000_000, 0x21),
                    out(spend(&[2_000_000_000], &[1_500_000_000], 0)?, 0x22),
                ],
                features: KernelFeatures::Coinbase,
                ..standard()
            },
            mutation: Mutation::None,
            broken: Some(Rule::KernelFeatures),
        },
    ])
}

fn mutate(
    secp: &Secp256k1,
    spec: &TxSpec,
    mut tx: Transaction,
    mutation: Mutation,
) -> Result<Transaction, Error> {
    match mutation {
        Mutation::None => {}
        Mutation::ReplaceOffset => {
            tx.offset = BlindingFactor::from_secret_key(secret(secp, &ALT_OFFSET)?);
        }
        Mutation::SignOtherFee => {
            let other = match spec.features {
                KernelFeatures::Plain { fee } => KernelFeatures::Plain {
                    fee: fee.wrapping_add(1),
                },
                features => features,
            };
            let resigned =
                signed_kernel(secp, other, &spec.excess_blind(secp)?, &spec.kernel_nonce)?;
            for kernel in tx.kernels_mut() {
                kernel.excess_sig = resigned.excess_sig;
            }
        }
        Mutation::SwapProofs => {
            let outputs = tx.outputs_mut();
            let (first, rest) = outputs
                .split_first_mut()
                .ok_or_else(|| unexpected("swapped case has two outputs"))?;
            let second = rest
                .first_mut()
                .ok_or_else(|| unexpected("swapped case has two outputs"))?;
            std::mem::swap(&mut first.proof, &mut second.proof);
        }
        Mutation::ReverseOutputs => tx.outputs_mut().reverse(),
    }
    Ok(tx)
}

fn validation(tx: &Transaction, broken: Option<Rule>) -> Result<Validation, Error> {
    let validation = match tx.validate(Weighting::AsTransaction) {
        Ok(()) => Validation {
            valid: true,
            rule: None,
            upstream_error: None,
        },
        Err(error) => Validation {
            valid: false,
            rule: Some(
                broken_rule(&error).ok_or_else(|| unexpected("upstream error is a known rule"))?,
            ),
            upstream_error: Some(format!("{error:?}")),
        },
    };
    ensure(
        validation.rule == broken,
        "transaction breaks exactly the rule the case names",
    )?;
    Ok(validation)
}

fn decode_v2(bytes: &[u8]) -> String {
    match ser::deserialize::<Transaction>(&mut &bytes[..], ProtocolVersion(2)) {
        Ok(_) => "ok".to_owned(),
        Err(error) => ser_error_name(&error),
    }
}

fn expected(
    secp: &Secp256k1,
    tx: &Transaction,
    broken: Option<Rule>,
) -> Result<CaseExpected, Error> {
    let v1 = ser::ser_vec(tx, ProtocolVersion(1)).map_err(Error::reference("v1 layout"))?;
    let v2 = ser::ser_vec(tx, ProtocolVersion(2)).map_err(Error::reference("v2 layout"))?;
    Ok(CaseExpected {
        transaction: TransactionJson::new(secp, tx),
        fee: tx.fee().to_string(),
        weight: tx.tx_weight(),
        hash: hex(tx.hash()),
        decode_v2: decode_v2(&v2),
        serialized_v1: hex(v1),
        serialized_v2: hex(v2),
        validation: validation(tx, broken)?,
    })
}

fn aggregate_case(pins: &Pins, secp: &Secp256k1) -> Result<Rendered, Error> {
    let first = TxSpec {
        inputs: vec![Coin::plain(900_000_000, 0x15)],
        outputs: vec![out(spend(&[900_000_000], &[], fee(1, 1))?, 0x2b)],
        features: KernelFeatures::Plain { fee: fee(1, 1) },
        offset: [0x37; 32],
        kernel_nonce: [0x38; 32],
    };
    let second = TxSpec {
        inputs: vec![Coin::plain(400_000_000, 0x16)],
        outputs: vec![
            out(100_000_000, 0x2c),
            out(spend(&[400_000_000], &[100_000_000], fee(1, 2))?, 0x2d),
        ],
        features: KernelFeatures::HeightLocked {
            fee: fee(1, 2),
            lock_height: 2_000,
        },
        offset: [0x39; 32],
        kernel_nonce: [0x3a; 32],
    };
    let tx = aggregate(vec![first.build(secp)?, second.build(secp)?])
        .map_err(Error::reference("aggregation"))?;
    let inputs = AggregateInputs {
        specs: vec![TxSpecJson::from(&first), TxSpecJson::from(&second)],
    };
    render(
        AREA,
        "tx_valid_aggregate_two_kernels",
        &pins.node,
        inputs,
        expected(secp, &tx, None)?,
    )
}

pub(super) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    let secp = secp();
    let mut rendered = Vec::new();
    for case in cases()? {
        let tx = mutate(&secp, &case.spec, case.spec.build(&secp)?, case.mutation)?;
        let inputs = CaseInputs {
            spec: TxSpecJson::from(&case.spec),
            mutation: case.mutation,
        };
        rendered.push(render(
            AREA,
            case.name,
            &pins.node,
            inputs,
            expected(&secp, &tx, case.broken)?,
        )?);
    }
    rendered.push(aggregate_case(pins, &secp)?);
    Ok(rendered)
}
