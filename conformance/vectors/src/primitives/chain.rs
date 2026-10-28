// SPDX-License-Identifier: Apache-2.0
//! Weights, fees and the chain parameters a wallet depends on, per network.

use epic_core::consensus;
use epic_core::core::transaction::{
    Input, Output, OutputFeatures, TransactionBody, TxKernel, Weighting,
};
use epic_core::global::{self, ChainTypes};
use epic_core::libtx::tx_fee;
use epic_core::ser::{self, ProtocolVersion};
use epic_util::secp::pedersen::{Commitment, RangeProof};
use serde::Serialize;

use super::AREA;
use super::fixtures::ser_error_name;
use crate::{Error, Pins, Rendered, render};

#[derive(Serialize)]
struct NoInputs {}

#[derive(Serialize)]
struct Cases<T> {
    cases: Vec<T>,
}

const NETWORKS: [(&str, ChainTypes); 2] = [
    ("mainnet", ChainTypes::Mainnet),
    ("floonet", ChainTypes::Floonet),
];

#[derive(Serialize)]
struct NetworkInputs {
    network: &'static str,
}

/// `max_tx_weight` is the block weight a transaction may use: the block limit less one coinbase
/// output and kernel.
#[derive(Serialize)]
struct ChainParams {
    coinbase_maturity: String,
    max_block_weight: usize,
    max_tx_weight: usize,
    block_input_weight: usize,
    block_output_weight: usize,
    block_kernel_weight: usize,
    protocol_version: u32,
    epic_base: String,
    milli_epic: String,
    micro_epic: String,
    default_base_fee: String,
}

fn chain_params() -> ChainParams {
    let coinbase_weight =
        consensus::BLOCK_OUTPUT_WEIGHT.saturating_add(consensus::BLOCK_KERNEL_WEIGHT);
    ChainParams {
        coinbase_maturity: global::coinbase_maturity().to_string(),
        max_block_weight: global::max_block_weight(),
        max_tx_weight: global::max_block_weight().saturating_sub(coinbase_weight),
        block_input_weight: consensus::BLOCK_INPUT_WEIGHT,
        block_output_weight: consensus::BLOCK_OUTPUT_WEIGHT,
        block_kernel_weight: consensus::BLOCK_KERNEL_WEIGHT,
        protocol_version: ProtocolVersion::local().value(),
        epic_base: consensus::EPIC_BASE.to_string(),
        milli_epic: consensus::MILLI_EPIC.to_string(),
        micro_epic: consensus::MICRO_EPIC.to_string(),
        // An empty body has the minimum weight of one, so it pays exactly the base fee.
        default_base_fee: tx_fee(0, 0, 0, None).to_string(),
    }
}

/// `fee` uses the default base fee, `fee_base_1` a base fee of one base unit, which is the
/// weight itself.
#[derive(Serialize)]
struct FeeRow {
    inputs: usize,
    outputs: usize,
    kernels: usize,
    weight: usize,
    weight_as_block: usize,
    fee: String,
    fee_base_1: String,
}

fn fee_grid() -> Vec<FeeRow> {
    let inputs = [0usize, 1, 2, 3, 4, 5, 10, 25, 100];
    let outputs = [0usize, 1, 2, 3, 4, 5, 10, 25];
    let kernels = [0usize, 1, 2];
    let mut rows = Vec::new();
    for &i in &inputs {
        for &o in &outputs {
            for &k in &kernels {
                rows.push(FeeRow {
                    inputs: i,
                    outputs: o,
                    kernels: k,
                    weight: TransactionBody::weight(i, o, k),
                    weight_as_block: TransactionBody::weight_as_block(i, o, k),
                    fee: tx_fee(i, o, k, None).to_string(),
                    fee_base_1: tx_fee(i, o, k, Some(1)).to_string(),
                });
            }
        }
    }
    rows
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Limit {
    WithinLimit,
    TooHeavy,
}

/// `as_transaction` is the weight rule of `Transaction::validate`. `read_counts` is how the node's
/// reader treats a body header announcing these counts: `TooLargeReadErr` before reading any
/// item, or `within_limit`.
#[derive(Serialize)]
struct WeightLimitRow {
    network: &'static str,
    inputs: usize,
    outputs: usize,
    kernels: usize,
    weight_as_block: usize,
    as_transaction: Limit,
    read_counts: String,
}

fn placeholder_body(inputs: usize, outputs: usize, kernels: usize) -> TransactionBody {
    let commit = Commitment::from_vec(vec![0; 33]);
    TransactionBody {
        inputs: vec![Input::new(OutputFeatures::Plain, commit); inputs],
        outputs: vec![
            Output {
                features: OutputFeatures::Plain,
                commit,
                proof: RangeProof::zero(),
            };
            outputs
        ],
        kernels: vec![TxKernel::empty(); kernels],
    }
}

fn read_counts(inputs: usize, outputs: usize, kernels: usize) -> Result<String, Error> {
    let counts = (inputs as u64, outputs as u64, kernels as u64);
    let header = ser::ser_vec(&counts, ProtocolVersion(2)).map_err(Error::reference("counts"))?;
    Ok(
        match ser::deserialize::<TransactionBody>(&mut &header[..], ProtocolVersion(2)) {
            Err(ser::Error::TooLargeReadErr) => "TooLargeReadErr".to_owned(),
            // The header passed; reading then runs out of items.
            Err(ser::Error::CountError | ser::Error::IOErr(..)) | Ok(_) => {
                "within_limit".to_owned()
            }
            Err(other) => ser_error_name(&other),
        },
    )
}

fn weight_limits(network: &'static str) -> Result<Vec<WeightLimitRow>, Error> {
    // Around the transaction limit (block limit less 24) and the block limit, by inputs alone,
    // by outputs alone, and mixed.
    let counts = [
        (1usize, 1usize, 1usize),
        (39_973, 0, 1),
        (39_974, 0, 1),
        (39_997, 0, 1),
        (39_998, 0, 1),
        (0, 1_903, 1),
        (0, 1_904, 1),
        (1, 1_902, 2),
        (2, 1_902, 2),
        (0, 1_904, 2),
        (0, 0, 13_325),
        (0, 0, 13_326),
        (0, 0, 13_333),
        (0, 0, 13_334),
    ];
    counts
        .into_iter()
        .map(|(inputs, outputs, kernels)| {
            let body = placeholder_body(inputs, outputs, kernels);
            let as_transaction = match body.validate_read(Weighting::AsTransaction) {
                Err(epic_core::core::transaction::Error::TooHeavy) => Limit::TooHeavy,
                _ => Limit::WithinLimit,
            };
            Ok(WeightLimitRow {
                network,
                inputs,
                outputs,
                kernels,
                weight_as_block: TransactionBody::weight_as_block(inputs, outputs, kernels),
                as_transaction,
                read_counts: read_counts(inputs, outputs, kernels)?,
            })
        })
        .collect()
}

pub(super) fn generate(pins: &Pins) -> Result<Vec<Rendered>, Error> {
    let mut rendered = Vec::new();
    let mut limits = Vec::new();
    for (name, chain) in NETWORKS {
        global::set_mining_mode(chain);
        rendered.push(render(
            AREA,
            &format!("chain_params_{name}"),
            &pins.node,
            NetworkInputs { network: name },
            chain_params(),
        )?);
        limits.extend(weight_limits(name)?);
    }
    global::set_mining_mode(ChainTypes::Mainnet);
    rendered.push(render(
        AREA,
        "fee_grid",
        &pins.node,
        NoInputs {},
        Cases { cases: fee_grid() },
    )?);
    rendered.push(render(
        AREA,
        "weight_limits",
        &pins.node,
        NoInputs {},
        Cases { cases: limits },
    )?);
    Ok(rendered)
}
