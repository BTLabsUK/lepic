//! A scripted chain that a mock node answers from.

use std::collections::BTreeMap;

use lepic_crypto::{Commitment, RangeProof};
use lepic_primitives::amount::Height;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::tx::Transaction;
use serde_json::{Value, json};

use super::Answer;
use super::recording::window;
use crate::api::{LocatedKernel, NodeVersion, Tip};
use crate::wire::{WireKernel, WireTransaction};

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
}

impl ChainState {
    pub fn new(version: NodeVersion, tip: Tip) -> Self {
        Self {
            version,
            tip,
            outputs: Vec::new(),
            kernels: Vec::new(),
            pool: Vec::new(),
        }
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
