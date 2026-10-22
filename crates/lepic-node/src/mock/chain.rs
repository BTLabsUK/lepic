//! A scripted chain that a mock node answers from.

use std::collections::BTreeMap;

use jiff::Timestamp;
use lepic_crypto::{Commitment, RangeProof};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::tx::Transaction;
use serde_json::{Value, json};

use super::Answer;
use super::recording::window;
use crate::api::{LocatedKernel, NodeVersion, Tip};
use crate::wire::{WireKernel, WireTransaction};

/// Seconds between the scripted chain's blocks, as the chain's own clock ticks.
pub const BLOCK_INTERVAL_SECONDS: i64 = 60;

/// 2019-03-01T00:00:00Z.
const DEFAULT_GENESIS_SECONDS: i64 = 1_551_398_400;

const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// An output the scripted chain holds, spent or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOutput {
    pub commitment: Commitment,
    pub features: OutputFeatures,
    pub proof: RangeProof,
    pub height: Height,
    pub mmr_index: u64,
    pub spent: bool,
}

/// What a scripted mock node knows. Tests change it between calls through
/// [`super::MockNode::update_chain`].
///
/// Output MMR indices are the outputs' own; `get_pmmr_indices` derives a height range's index
/// range from the outputs in it, which matches the node whenever every block has an output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    pub version: NodeVersion,
    pub tip: Tip,
    pub outputs: Vec<ChainOutput>,
    pub kernels: Vec<LocatedKernel>,
    /// The transaction pool `get_unconfirmed_transactions` lists. A push does not add to it.
    pub pool: Vec<Transaction>,
    /// The time of block 0. Block `n` is dated `n` intervals of [`BLOCK_INTERVAL_SECONDS`] later,
    /// unless `header_times` says otherwise.
    pub genesis_time: Timestamp,
    pub header_times: BTreeMap<Height, Timestamp>,
    /// The answer to `ready_for_txs`; `None` answers as a node before 4.1.0, which does not
    /// know the method.
    pub ready_for_txs: Option<bool>,
}

impl ChainState {
    pub fn new(version: NodeVersion, tip: Tip) -> Self {
        Self {
            version,
            tip,
            outputs: Vec::new(),
            kernels: Vec::new(),
            pool: Vec::new(),
            genesis_time: Timestamp::from_second(DEFAULT_GENESIS_SECONDS)
                .unwrap_or(Timestamp::UNIX_EPOCH),
            header_times: BTreeMap::new(),
            ready_for_txs: None,
        }
    }

    /// The time the scripted chain gives the block at `height`.
    pub fn header_time(&self, height: Height) -> Timestamp {
        self.header_times.get(&height).copied().unwrap_or_else(|| {
            let offset = i64::try_from(height.value())
                .unwrap_or(i64::MAX)
                .saturating_mul(BLOCK_INTERVAL_SECONDS);
            Timestamp::from_second(self.genesis_time.as_second().saturating_add(offset))
                .unwrap_or(self.genesis_time)
        })
    }

    /// The hash the scripted chain gives the block at `height`: the tip's own hash at the tip,
    /// otherwise one derived from the height.
    pub fn header_hash(&self, height: Height) -> Hash {
        if height == self.tip.height {
            return self.tip.last_block_pushed;
        }
        let mut bytes = [0xb1; 32];
        bytes[..8].copy_from_slice(&height.value().to_le_bytes());
        Hash::from_bytes(bytes)
    }

    pub(super) fn answer(&self, method: &str, params: &Value) -> Answer {
        match method {
            "get_version" => Answer::Ok(json!({
                "node_version": self.version.node_version,
                "block_header_version": self.version.block_header_version,
            })),
            "get_tip" => Answer::Ok(json!({
                "height": self.tip.height.value(),
                "last_block_pushed": self.tip.last_block_pushed.to_hex(),
                "prev_block_to_last": ZERO_HASH_HEX,
                "total_difficulty": {},
            })),
            "get_header" => self.answer_header(params),
            "ready_for_txs" => match self.ready_for_txs {
                Some(ready) => Answer::Ok(json!({ "ready_for_txs": ready })),
                None => Answer::Response(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": "Method not found"},
                })),
            },
            "get_kernel" => self.answer_kernel(params),
            "get_outputs" => self.answer_outputs(params),
            "get_unspent_outputs" => self.answer_unspent(params),
            "get_pmmr_indices" => self.answer_pmmr_indices(params),
            "get_unconfirmed_transactions" => Answer::Ok(Value::Array(
                self.pool
                    .iter()
                    .map(|transaction| {
                        json!({
                            "src": "PushApi",
                            "tx_at": "2026-01-01T00:00:00Z",
                            "tx": WireTransaction::from(transaction),
                        })
                    })
                    .collect(),
            )),
            _ => Answer::Violation("method not served by the scripted chain"),
        }
    }

    fn answer_header(&self, params: &Value) -> Answer {
        let Some(height) = params.get(0).and_then(Value::as_u64).map(Height::new) else {
            return Answer::Violation("get_header without a height");
        };
        if height > self.tip.height {
            return Answer::Rejected(json!("NotFound"));
        }
        Answer::Ok(json!({
            "height": height.value(),
            "hash": self.header_hash(height).to_hex(),
            "timestamp": self.header_time(height).to_string(),
        }))
    }

    fn answer_kernel(&self, params: &Value) -> Answer {
        let Some(excess) = params.get(0).and_then(Value::as_str) else {
            return Answer::Violation("get_kernel without an excess");
        };
        let min = params.get(1).and_then(Value::as_u64).map(Height::new);
        let max = params.get(2).and_then(Value::as_u64).map(Height::new);
        // The node reads the header below `min`, and answers a height it has no header for
        // with an internal error, not with `NotFound`.
        let tip = self.tip.height.value();
        if min.is_some_and(|min| min.value() == 0 || min.value() > tip.saturating_add(1)) {
            return Answer::Rejected(json!({"Internal": "header not found"}));
        }
        let found = self.kernels.iter().find(|located| {
            located.kernel.excess.to_hex().eq_ignore_ascii_case(excess)
                && min.is_none_or(|min| located.height >= min)
                && max.is_none_or(|max| located.height <= max)
        });
        match found {
            Some(located) => Answer::Ok(json!({
                "tx_kernel": WireKernel::from(&located.kernel),
                "height": located.height.value(),
                "mmr_index": located.mmr_index,
            })),
            None => Answer::Rejected(json!("NotFound")),
        }
    }

    fn unspent(&self) -> impl Iterator<Item = &ChainOutput> {
        self.outputs.iter().filter(|output| !output.spent)
    }

    fn answer_outputs(&self, params: &Value) -> Answer {
        let Some(requested) = params.get(0).and_then(Value::as_array) else {
            return Answer::Violation("get_outputs without a commitment list");
        };
        let found: Vec<Value> = requested
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|commit| {
                self.unspent()
                    .find(|output| output.commitment.to_hex().eq_ignore_ascii_case(commit))
            })
            .map(|output| printable(output, false))
            .collect();
        Answer::Ok(Value::Array(found))
    }

    fn answer_unspent(&self, params: &Value) -> Answer {
        let start = params.get(0).and_then(Value::as_u64);
        let end = params.get(1).map(Value::as_u64);
        let max = params.get(2).and_then(Value::as_u64);
        let (Some(start), Some(end), Some(max)) = (start, end, max) else {
            return Answer::Violation("get_unspent_outputs with unexpected params");
        };
        let highest = self
            .outputs
            .iter()
            .map(|output| output.mmr_index)
            .max()
            .unwrap_or(0);
        let outputs: BTreeMap<u64, Value> = self
            .unspent()
            .map(|output| (output.mmr_index, printable(output, true)))
            .collect();
        Answer::Ok(window(&outputs, start, end.unwrap_or(highest), max))
    }

    fn answer_pmmr_indices(&self, params: &Value) -> Answer {
        let Some(start) = params.get(0).and_then(Value::as_u64).map(Height::new) else {
            return Answer::Violation("get_pmmr_indices without a start height");
        };
        let end = params
            .get(1)
            .and_then(Value::as_u64)
            .map_or(self.tip.height, Height::new);
        let last_before_start = self
            .outputs
            .iter()
            .filter(|output| output.height < start)
            .map(|output| output.mmr_index)
            .max()
            .unwrap_or(0);
        let last = self
            .outputs
            .iter()
            .filter(|output| output.height <= end)
            .map(|output| output.mmr_index)
            .max()
            .unwrap_or(0);
        Answer::Ok(json!({
            "highest_index": last,
            "last_retrieved_index": last_before_start.saturating_add(1),
            "outputs": [],
        }))
    }
}

fn printable(output: &ChainOutput, include_proof: bool) -> Value {
    json!({
        "output_type": if output.features.is_coinbase() { "Coinbase" } else { "Transaction" },
        "commit": output.commitment.to_hex(),
        "spent": output.spent,
        "proof": include_proof.then(|| output.proof.to_hex()),
        "proof_hash": ZERO_HASH_HEX,
        "block_height": output.height.value(),
        "merkle_proof": null,
        "mmr_index": output.mmr_index,
    })
}
