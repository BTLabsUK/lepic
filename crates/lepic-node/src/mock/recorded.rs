// SPDX-License-Identifier: Apache-2.0
//! The chain an upgrade fixture recorded (`testdata/upgrade/*/chain.json`), loaded back into a
//! scripted [`ChainState`].

use jiff::Timestamp;
use lepic_crypto::{Commitment, RangeProof};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::kernel::TxKernel;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::ser::{ProtocolVersion, deserialize};
use lepic_primitives::tx::Transaction;
use serde_json::Value;

use super::{ChainOutput, ChainState};
use crate::api::{LocatedKernel, NodeVersion, Tip};

/// A recorded chain and the transactions its node had been sent and not yet mined.
#[derive(Debug, Clone)]
pub struct RecordedChain {
    pub chain: ChainState,
    pub pushed: Vec<Transaction>,
}

impl RecordedChain {
    /// Reads the `chain.json` an upgrade fixture generator wrote.
    ///
    /// # Errors
    /// A description of the first field that is missing or does not decode.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let root: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
        let version = field(&root, "version")?;
        let tip = field(&root, "tip")?;
        let mut chain = ChainState::new(
            NodeVersion {
                node_version: string(version, "node_version")?.to_owned(),
                block_header_version: u16::try_from(number(version, "block_header_version")?)
                    .map_err(|_| "block_header_version".to_owned())?,
            },
            Tip {
                height: Height::new(number(tip, "height")?),
                last_block_pushed: Hash::from_hex(string(tip, "last_block_pushed")?)
                    .map_err(|error| error.to_string())?,
            },
        );
        for output in array(&root, "outputs")? {
            let features = u8::try_from(number(output, "features")?)
                .ok()
                .and_then(OutputFeatures::from_u8)
                .ok_or("output features")?;
            chain.outputs.push(ChainOutput {
                commitment: Commitment::from_hex(string(output, "commitment")?)
                    .map_err(|error| error.to_string())?,
                features,
                proof: RangeProof::from_hex(string(output, "proof")?)
                    .map_err(|error| error.to_string())?,
                height: Height::new(number(output, "height")?),
                mmr_index: number(output, "mmr_index")?,
                spent: boolean(output, "spent")?,
            });
        }
        for kernel in array(&root, "kernels")? {
            chain.kernels.push(LocatedKernel {
                kernel: deserialize::<TxKernel>(
                    &bytes(string(kernel, "kernel")?)?,
                    ProtocolVersion::V2,
                )
                .map_err(|error| error.to_string())?,
                height: Height::new(number(kernel, "height")?),
                mmr_index: number(kernel, "mmr_index")?,
            });
        }
        for transaction in array(&root, "pool")? {
            chain.pool.push(transaction_of(transaction)?);
        }
        chain.genesis_time = timestamp(root.get("genesis_seconds"))?;
        for entry in array(&root, "header_times")? {
            let pair = entry.as_array().filter(|pair| pair.len() == 2);
            let pair = pair.ok_or("header_times entry")?;
            let height = pair
                .first()
                .and_then(Value::as_u64)
                .ok_or("header_times height")?;
            chain
                .header_times
                .insert(Height::new(height), timestamp(pair.get(1))?);
        }
        chain.ready_for_txs = root.get("ready_for_txs").and_then(Value::as_bool);
        let pushed = array(&root, "pushed")?
            .iter()
            .map(transaction_of)
            .collect::<Result<_, _>>()?;
        Ok(Self { chain, pushed })
    }

    /// The chain one block later, with the pushed transactions in that block: their inputs
    /// spent, their outputs and kernels added.
    #[must_use]
    pub fn mined(&self) -> ChainState {
        let mut chain = self.chain.clone();
        let height = Height::new(chain.tip.height.value().saturating_add(1));
        for transaction in &self.pushed {
            for input in transaction.inputs() {
                for output in &mut chain.outputs {
                    if output.commitment == input.commitment {
                        output.spent = true;
                    }
                }
            }
            for output in transaction.outputs() {
                let mmr_index = u64::try_from(chain.outputs.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                chain.outputs.push(ChainOutput {
                    commitment: output.commitment,
                    features: output.features,
                    proof: output.proof.clone(),
                    height,
                    mmr_index,
                    spent: false,
                });
            }
            for kernel in transaction.kernels() {
                let mmr_index = u64::try_from(chain.kernels.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1);
                chain.kernels.push(LocatedKernel {
                    kernel: *kernel,
                    height,
                    mmr_index,
                });
            }
        }
        chain.tip.height = height;
        chain
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value.get(name).ok_or_else(|| format!("missing {name}"))
}

fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| format!("{name} is not a string"))
}

fn number(value: &Value, name: &str) -> Result<u64, String> {
    field(value, name)?
        .as_u64()
        .ok_or_else(|| format!("{name} is not a number"))
}

fn boolean(value: &Value, name: &str) -> Result<bool, String> {
    field(value, name)?
        .as_bool()
        .ok_or_else(|| format!("{name} is not a boolean"))
}

fn array<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>, String> {
    field(value, name)?
        .as_array()
        .ok_or_else(|| format!("{name} is not a list"))
}

fn timestamp(value: Option<&Value>) -> Result<Timestamp, String> {
    let seconds = value.and_then(Value::as_i64).ok_or("a time in seconds")?;
    Timestamp::from_second(seconds).map_err(|error| error.to_string())
}

fn bytes(hex: &str) -> Result<Vec<u8>, String> {
    let (pairs, rest) = hex.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err("odd hex length".to_owned());
    }
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "bad hex".to_owned())
        })
        .collect()
}

fn transaction_of(value: &Value) -> Result<Transaction, String> {
    let hex = value.as_str().ok_or("a transaction in hex")?;
    Transaction::decode(&bytes(hex)?, ProtocolVersion::V2).map_err(|error| error.to_string())
}
