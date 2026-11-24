// SPDX-License-Identifier: Apache-2.0
//! A scripted chain that a mock node answers from.

use std::collections::BTreeMap;

use jiff::Timestamp;
use lepic_crypto::{Commitment, RangeProof};
use lepic_primitives::amount::{Fee, Height, MILLI_EPIC};
use lepic_primitives::hash::Hash;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::tx::Transaction;
use lepic_primitives::validate::ValidationError;
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
/// A pushed transaction is checked as Epic node 4.1 checks it before it enters the pool, in the
/// node's order: the fee against the default `accept_fee_base`, full validation
/// ([`Transaction::validate`]), the lock height against the next block, then every input
/// unspent on this chain with its features and no output already unspent here. A push changes
/// nothing on the chain; tests spend outputs themselves.
///
/// Two node rules are off until a test asks for them, so tests written before them keep their
/// behaviour:
///
/// - [`ChainState::pool_pushes`]: a transaction the node takes goes into [`ChainState::pool`]
///   and stays there until [`ChainState::mine_block`] puts it in a block. The node refuses the
///   same transaction again ("Duplicate tx") and one that spends an input a pool transaction
///   already spends.
/// - [`ChainState::coinbase_maturity`]: a coinbase output can be spent in a block at least this
///   many blocks after the one that holds it, as the node checks it against the next block.
///
/// Output MMR indices are the outputs' own; `get_pmmr_indices` derives a height range's index
/// range from the outputs in it, which matches the node whenever every block has an output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    pub version: NodeVersion,
    pub tip: Tip,
    pub outputs: Vec<ChainOutput>,
    pub kernels: Vec<LocatedKernel>,
    /// The transaction pool `get_unconfirmed_transactions` lists. A push adds to it only when
    /// [`Self::pool_pushes`] is set.
    pub pool: Vec<Transaction>,
    /// Whether a transaction the node takes enters [`Self::pool`], as with a real node. Off by
    /// default: a push then changes nothing and the test mines by hand.
    pub pool_pushes: bool,
    /// The coinbase maturity the node enforces on a push, in blocks. `None`, the default, does
    /// not check it.
    pub coinbase_maturity: Option<u64>,
    /// The time of block 0. Block `n` is dated `n` intervals of [`BLOCK_INTERVAL_SECONDS`] later,
    /// unless `header_times` says otherwise.
    pub genesis_time: Timestamp,
    pub header_times: BTreeMap<Height, Timestamp>,
    /// Header hashes that replace the derived ones, for a block another one replaced.
    pub header_hashes: BTreeMap<Height, Hash>,
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
            pool_pushes: false,
            coinbase_maturity: None,
            genesis_time: Timestamp::from_second(DEFAULT_GENESIS_SECONDS)
                .unwrap_or(Timestamp::UNIX_EPOCH),
            header_times: BTreeMap::new(),
            header_hashes: BTreeMap::new(),
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

    /// A pool and a maturity rule like a real node's: pushed transactions wait in the pool for
    /// [`Self::mine_block`], and a coinbase output matures after `coinbase_maturity` blocks.
    #[must_use]
    pub fn with_node_rules(mut self, coinbase_maturity: u64) -> Self {
        self.pool_pushes = true;
        self.coinbase_maturity = Some(coinbase_maturity);
        self
    }

    /// Mines the pool into a block one above the tip, which becomes the tip: the inputs of each
    /// transaction are spent and its outputs and kernels added at the new height, then the pool
    /// is empty. A pool transaction whose inputs are no longer unspent is dropped, as the node
    /// drops it when a block makes it invalid. Returns the new tip height.
    pub fn mine_block(&mut self) -> Height {
        let height = Height::new(self.tip.height.value().saturating_add(1));
        for transaction in std::mem::take(&mut self.pool) {
            let spendable = transaction.inputs().iter().all(|input| {
                self.unspent()
                    .any(|output| output.commitment == input.commitment)
            });
            if !spendable {
                continue;
            }
            for input in transaction.inputs() {
                for output in &mut self.outputs {
                    if output.commitment == input.commitment {
                        output.spent = true;
                    }
                }
            }
            for created in transaction.outputs() {
                let mmr_index = self
                    .outputs
                    .iter()
                    .map(|output| output.mmr_index)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                self.outputs.push(ChainOutput {
                    commitment: created.commitment,
                    features: created.features,
                    proof: created.proof.clone(),
                    height,
                    mmr_index,
                    spent: false,
                });
            }
            for kernel in transaction.kernels() {
                let mmr_index = self
                    .kernels
                    .iter()
                    .map(|located| located.mmr_index)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                self.kernels.push(LocatedKernel {
                    kernel: *kernel,
                    height,
                    mmr_index,
                });
            }
        }
        self.tip.height = height;
        self.tip.last_block_pushed = self.header_hash_derived(height);
        height
    }

    /// Mines `count` blocks one after another. Returns the new tip height.
    pub fn mine_blocks(&mut self, count: u64) -> Height {
        for _ in 0..count {
            self.mine_block();
        }
        self.tip.height
    }

    fn header_hash_derived(&self, height: Height) -> Hash {
        let mut bytes = [0xb1; 32];
        bytes[..8].copy_from_slice(&height.value().to_le_bytes());
        Hash::from_bytes(bytes)
    }

    /// The hash the scripted chain gives the block at `height`: the one `header_hashes` gives
    /// it, the tip's own hash at the tip, otherwise one derived from the height.
    pub fn header_hash(&self, height: Height) -> Hash {
        if let Some(hash) = self.header_hashes.get(&height) {
            return *hash;
        }
        if height == self.tip.height {
            return self.tip.last_block_pushed;
        }
        self.header_hash_derived(height)
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

/// The node's default `accept_fee_base`: the pool refuses a fee below this times the fee weight.
const ACCEPT_FEE_BASE: Fee = Fee::new(MILLI_EPIC);

/// Why the node's pool refuses a pushed transaction.
#[derive(Debug)]
pub(super) enum PushRefusal {
    LowFee { threshold: Fee },
    Invalid(ValidationError),
    LockHeight,
    ImmatureCoinbase,
    Duplicate,
    PoolConflict,
    InputNotUnspent,
    OutputExists,
}

impl PushRefusal {
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::LowFee { .. } => "push_transaction with a fee below the pool's minimum",
            Self::Invalid(ValidationError::Structure(_)) => {
                "push_transaction with a transaction that breaks the structure rules"
            }
            Self::Invalid(ValidationError::RangeProof(_)) => {
                "push_transaction with a range proof that does not verify"
            }
            Self::Invalid(ValidationError::KernelSignature { .. }) => {
                "push_transaction with a kernel signature that does not verify"
            }
            Self::Invalid(ValidationError::KernelSum(_)) => {
                "push_transaction with kernel sums that do not balance"
            }
            Self::LockHeight => "push_transaction locked above the next block",
            Self::ImmatureCoinbase => {
                "push_transaction spending a coinbase output before it matured"
            }
            Self::Duplicate => "push_transaction with a transaction already in the pool",
            Self::PoolConflict => {
                "push_transaction spending an output a pool transaction already spends"
            }
            Self::InputNotUnspent => {
                "push_transaction spending an output the chain does not hold unspent"
            }
            Self::OutputExists => "push_transaction creating an output the chain already holds",
        }
    }

    /// The pool error's text, as the node puts it after "Failed to update pool: ".
    pub(super) fn node_text(&self) -> String {
        match self {
            Self::LowFee { threshold } => format!("Low fee transaction: {}", threshold.value()),
            Self::Invalid(error) => format!("Invalid Tx: {error}"),
            Self::LockHeight => {
                "Transaction lock height is greater than current block height".to_owned()
            }
            Self::ImmatureCoinbase => "Immature coinbase".to_owned(),
            Self::Duplicate => "Duplicate tx".to_owned(),
            Self::InputNotUnspent | Self::OutputExists | Self::PoolConflict => {
                "General pool error: failed to validate tx".to_owned()
            }
        }
    }
}

impl ChainState {
    pub(super) fn admit(&self, transaction: &Transaction) -> Result<(), PushRefusal> {
        // The node looks for the same transaction in its pool before anything else.
        if self.pool_pushes && self.pool.contains(transaction) {
            return Err(PushRefusal::Duplicate);
        }
        let threshold = transaction
            .body()
            .counts()
            .tx_fee(ACCEPT_FEE_BASE)
            .unwrap_or(Fee::new(u64::MAX));
        let fee = transaction.fee().unwrap_or(Fee::new(u64::MAX));
        if fee < threshold {
            return Err(PushRefusal::LowFee { threshold });
        }
        transaction.validate().map_err(PushRefusal::Invalid)?;
        let next_block = self.tip.height.value().saturating_add(1);
        if transaction.lock_height().value() > next_block {
            return Err(PushRefusal::LockHeight);
        }
        self.check_maturity(transaction)?;
        let all_unspent = transaction.inputs().iter().all(|input| {
            self.unspent().any(|output| {
                output.commitment == input.commitment && output.features == input.features
            })
        });
        if !all_unspent {
            return Err(PushRefusal::InputNotUnspent);
        }
        let any_exists = transaction.outputs().iter().any(|created| {
            self.unspent()
                .any(|output| output.commitment == created.commitment)
        });
        if any_exists {
            return Err(PushRefusal::OutputExists);
        }
        let pooled_spend = self.pool_pushes
            && transaction.inputs().iter().any(|input| {
                self.pool.iter().any(|pooled| {
                    pooled
                        .inputs()
                        .iter()
                        .any(|spent| spent.commitment == input.commitment)
                })
            });
        if pooled_spend {
            return Err(PushRefusal::PoolConflict);
        }
        Ok(())
    }

    /// The node's check of the next block's height against each coinbase input it holds: the
    /// output is mature once the next block is `coinbase_maturity` above the block that holds it.
    fn check_maturity(&self, transaction: &Transaction) -> Result<(), PushRefusal> {
        let Some(maturity) = self.coinbase_maturity else {
            return Ok(());
        };
        let next_block = self.tip.height.value().saturating_add(1);
        let immature = transaction.inputs().iter().any(|input| {
            input.features.is_coinbase()
                && self.unspent().any(|output| {
                    output.commitment == input.commitment
                        && output.height.value().saturating_add(maturity) > next_block
                })
        });
        if immature {
            return Err(PushRefusal::ImmatureCoinbase);
        }
        Ok(())
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
