//! The node's JSON shapes for the calls LEPIC makes, and their conversion to validated values.
//!
//! Field names and enum spellings follow the node's `api::types` and `core::transaction` serde
//! output in Epic `v4.0.4`. Fields LEPIC does not use are ignored, as upstream ignores them.

use std::collections::BTreeSet;

use lepic_crypto::{Commitment, RangeProof, Signature};
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::tx::Transaction;
use serde::{Deserialize, Serialize};

use crate::api::{
    LocatedKernel, NodeVersion, OutputLocation, PmmrIndices, Tip, UnspentOutput, UnspentOutputs,
};
use crate::error::{FieldProblem, NodeError};

pub(crate) const MAX_NODE_VERSION_LEN: usize = 64;

#[derive(Debug, Deserialize)]
pub(crate) struct WireVersion {
    node_version: String,
    block_header_version: u16,
}

impl WireVersion {
    pub(crate) fn validate(self, method: &'static str) -> Result<NodeVersion, NodeError> {
        if self.node_version.len() > MAX_NODE_VERSION_LEN {
            return Err(NodeError::invalid(
                method,
                "node_version",
                FieldProblem::TooLong {
                    max: MAX_NODE_VERSION_LEN,
                },
            ));
        }
        Ok(NodeVersion {
            node_version: self.node_version,
            block_header_version: self.block_header_version,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireTip {
    height: u64,
    last_block_pushed: String,
}

impl WireTip {
    pub(crate) fn validate(self, method: &'static str) -> Result<Tip, NodeError> {
        let last_block_pushed = Hash::from_hex(&self.last_block_pushed)
            .map_err(|error| NodeError::invalid(method, "last_block_pushed", error.into()))?;
        Ok(Tip {
            height: Height::new(self.height),
            last_block_pushed,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WireOutputFeatures {
    Plain,
    Coinbase,
}

impl From<WireOutputFeatures> for OutputFeatures {
    fn from(features: WireOutputFeatures) -> Self {
        match features {
            WireOutputFeatures::Plain => Self::Plain,
            WireOutputFeatures::Coinbase => Self::Coinbase,
        }
    }
}

impl From<OutputFeatures> for WireOutputFeatures {
    fn from(features: OutputFeatures) -> Self {
        match features {
            OutputFeatures::Plain => Self::Plain,
            OutputFeatures::Coinbase => Self::Coinbase,
        }
    }
}

/// `api::OutputType`, which names plain outputs `Transaction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum WireOutputType {
    Coinbase,
    Transaction,
}

impl From<WireOutputType> for OutputFeatures {
    fn from(output_type: WireOutputType) -> Self {
        match output_type {
            WireOutputType::Coinbase => Self::Coinbase,
            WireOutputType::Transaction => Self::Plain,
        }
    }
}

/// `api::OutputPrintable`.
#[derive(Debug, Deserialize)]
pub(crate) struct WireOutput {
    output_type: WireOutputType,
    commit: String,
    spent: bool,
    proof: Option<String>,
    block_height: Option<u64>,
    mmr_index: u64,
}

impl WireOutput {
    fn commitment(&self, method: &'static str) -> Result<Commitment, NodeError> {
        Commitment::from_hex(&self.commit)
            .map_err(|error| NodeError::invalid(method, "commit", error.into()))
    }

    fn height(&self, method: &'static str) -> Result<Height, NodeError> {
        self.block_height.map(Height::new).ok_or(NodeError::invalid(
            method,
            "block_height",
            FieldProblem::Missing,
        ))
    }
}

/// Validates a `get_outputs` answer against the commitments that were asked for: every output
/// must be one of them, at most once.
pub(crate) fn validate_output_locations(
    method: &'static str,
    outputs: Vec<WireOutput>,
    requested: &BTreeSet<Commitment>,
) -> Result<Vec<OutputLocation>, NodeError> {
    if outputs.len() > requested.len() {
        return Err(NodeError::invalid(method, "outputs", FieldProblem::TooMany));
    }
    let mut seen = BTreeSet::new();
    outputs
        .into_iter()
        .map(|output| {
            let commitment = output.commitment(method)?;
            if !requested.contains(&commitment) {
                return Err(NodeError::invalid(
                    method,
                    "commit",
                    FieldProblem::NotRequested,
                ));
            }
            if !seen.insert(commitment) {
                return Err(NodeError::invalid(
                    method,
                    "commit",
                    FieldProblem::Duplicate,
                ));
            }
            Ok(OutputLocation {
                commitment,
                features: output.output_type.into(),
                height: output.height(method)?,
                mmr_index: output.mmr_index,
            })
        })
        .collect()
}

/// `api::OutputListing`, the answer to `get_unspent_outputs` and `get_pmmr_indices`.
#[derive(Debug, Deserialize)]
pub(crate) struct WireOutputListing {
    highest_index: u64,
    last_retrieved_index: u64,
    outputs: Vec<WireOutput>,
}

impl WireOutputListing {
    /// Every output must lie in the requested index window, at most `max` of them, each with a
    /// single-bulletproof range proof.
    pub(crate) fn validate_unspent(
        self,
        method: &'static str,
        start_index: u64,
        end_index: Option<u64>,
        max: u64,
    ) -> Result<UnspentOutputs, NodeError> {
        let count = u64::try_from(self.outputs.len()).unwrap_or(u64::MAX);
        if count > max {
            return Err(NodeError::invalid(method, "outputs", FieldProblem::TooMany));
        }
        let mut seen = BTreeSet::new();
        let mut outputs = Vec::with_capacity(self.outputs.len());
        for output in self.outputs {
            let in_window = output.mmr_index >= start_index
                && end_index.is_none_or(|end| output.mmr_index <= end);
            if !in_window {
                return Err(NodeError::invalid(
                    method,
                    "mmr_index",
                    FieldProblem::OutOfRange,
                ));
            }
            if !seen.insert(output.mmr_index) {
                return Err(NodeError::invalid(
                    method,
                    "mmr_index",
                    FieldProblem::Duplicate,
                ));
            }
            if output.spent {
                continue;
            }
            let commitment = output.commitment(method)?;
            let proof_hex = output.proof.as_deref().ok_or(NodeError::invalid(
                method,
                "proof",
                FieldProblem::Missing,
            ))?;
            let proof = parse_bulletproof(proof_hex)
                .map_err(|problem| NodeError::invalid(method, "proof", problem))?;
            outputs.push(UnspentOutput {
                commitment,
                features: output.output_type.into(),
                proof,
                height: output.height(method)?,
                mmr_index: output.mmr_index,
            });
        }
        Ok(UnspentOutputs {
            highest_index: self.highest_index,
            last_retrieved_index: self.last_retrieved_index,
            outputs,
        })
    }

    // The node fills an output listing for this call, with the first index of the range in
    // `last_retrieved_index` and the last in `highest_index`.
    pub(crate) fn into_pmmr_indices(self) -> PmmrIndices {
        PmmrIndices {
            first_index: self.last_retrieved_index,
            last_index: self.highest_index,
        }
    }
}

fn parse_bulletproof(hex: &str) -> Result<RangeProof, FieldProblem> {
    let expected_digits = RangeProof::BULLETPROOF_LEN.saturating_mul(2);
    if hex.len() != expected_digits {
        return Err(FieldProblem::Crypto(
            lepic_crypto::CryptoError::WrongLength {
                item: lepic_crypto::Item::RangeProof,
                expected: RangeProof::BULLETPROOF_LEN,
                actual: hex.len().div_ceil(2),
            },
        ));
    }
    RangeProof::from_hex(hex).map_err(FieldProblem::from)
}

/// `core::KernelFeatures` as serde writes it: `"Coinbase"`, `{"Plain":{"fee":n}}` or
/// `{"HeightLocked":{"fee":n,"lock_height":n}}`, with plain JSON numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WireKernelFeatures {
    Plain { fee: u64 },
    Coinbase,
    HeightLocked { fee: u64, lock_height: u64 },
}

impl From<WireKernelFeatures> for KernelFeatures {
    fn from(features: WireKernelFeatures) -> Self {
        match features {
            WireKernelFeatures::Plain { fee } => Self::Plain { fee: Fee::new(fee) },
            WireKernelFeatures::Coinbase => Self::Coinbase,
            WireKernelFeatures::HeightLocked { fee, lock_height } => Self::HeightLocked {
                fee: Fee::new(fee),
                lock_height: Height::new(lock_height),
            },
        }
    }
}

impl From<KernelFeatures> for WireKernelFeatures {
    fn from(features: KernelFeatures) -> Self {
        match features {
            KernelFeatures::Plain { fee } => Self::Plain { fee: fee.value() },
            KernelFeatures::Coinbase => Self::Coinbase,
            KernelFeatures::HeightLocked { fee, lock_height } => Self::HeightLocked {
                fee: fee.value(),
                lock_height: lock_height.value(),
            },
        }
    }
}

/// `core::TxKernel`; the signature is in compact form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireKernel {
    features: WireKernelFeatures,
    excess: String,
    excess_sig: String,
}

impl WireKernel {
    fn validate(self, method: &'static str) -> Result<TxKernel, NodeError> {
        let excess = Commitment::from_hex(&self.excess)
            .map_err(|error| NodeError::invalid(method, "excess", error.into()))?;
        let excess_sig = Signature::from_compact_hex(&self.excess_sig)
            .map_err(|error| NodeError::invalid(method, "excess_sig", error.into()))?;
        Ok(TxKernel::new(self.features.into(), excess, excess_sig))
    }
}

impl From<&TxKernel> for WireKernel {
    fn from(kernel: &TxKernel) -> Self {
        Self {
            features: kernel.features.into(),
            excess: kernel.excess.to_hex(),
            excess_sig: kernel.excess_sig.to_compact_hex(),
        }
    }
}

/// `api::LocatedTxKernel`.
#[derive(Debug, Deserialize)]
pub(crate) struct WireLocatedKernel {
    tx_kernel: WireKernel,
    height: u64,
    mmr_index: u64,
}

impl WireLocatedKernel {
    /// The kernel must be the one asked for, inside the requested height range.
    pub(crate) fn validate(
        self,
        method: &'static str,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> Result<LocatedKernel, NodeError> {
        let kernel = self.tx_kernel.validate(method)?;
        if kernel.excess != *excess {
            return Err(NodeError::invalid(
                method,
                "excess",
                FieldProblem::NotRequested,
            ));
        }
        let height = Height::new(self.height);
        let in_range = min_height.is_none_or(|min| height >= min)
            && max_height.is_none_or(|max| height <= max);
        if !in_range {
            return Err(NodeError::invalid(
                method,
                "height",
                FieldProblem::OutOfRange,
            ));
        }
        Ok(LocatedKernel {
            kernel,
            height,
            mmr_index: self.mmr_index,
        })
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "mock", derive(Deserialize))]
struct WireInput {
    features: WireOutputFeatures,
    commit: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "mock", derive(Deserialize))]
struct WireTxOutput {
    features: WireOutputFeatures,
    commit: String,
    proof: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "mock", derive(Deserialize))]
struct WireBody {
    inputs: Vec<WireInput>,
    outputs: Vec<WireTxOutput>,
    kernels: Vec<WireKernel>,
}

/// `core::Transaction` as the node's `push_transaction` reads it.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "mock", derive(Deserialize))]
pub(crate) struct WireTransaction {
    offset: String,
    body: WireBody,
}

impl From<&Transaction> for WireTransaction {
    fn from(transaction: &Transaction) -> Self {
        Self {
            offset: transaction.offset().to_hex(),
            body: WireBody {
                inputs: transaction
                    .inputs()
                    .iter()
                    .map(|input| WireInput {
                        features: input.features.into(),
                        commit: input.commitment.to_hex(),
                    })
                    .collect(),
                outputs: transaction
                    .outputs()
                    .iter()
                    .map(|output| WireTxOutput {
                        features: output.features.into(),
                        commit: output.commitment.to_hex(),
                        proof: output.proof.to_hex(),
                    })
                    .collect(),
                kernels: transaction.kernels().iter().map(WireKernel::from).collect(),
            },
        }
    }
}

#[cfg(feature = "mock")]
impl WireTransaction {
    /// The transaction a mock node received, checked as strictly as the node reads one.
    pub(crate) fn into_transaction(self) -> Option<Transaction> {
        use lepic_primitives::crypto_ser::BlindingFactor;
        use lepic_primitives::input::Input;
        use lepic_primitives::output::Output;
        use lepic_primitives::tx::TransactionBody;

        let offset = BlindingFactor::from_hex(&self.offset).ok()?;
        let inputs = self
            .body
            .inputs
            .into_iter()
            .map(|input| {
                let commitment = Commitment::from_hex(&input.commit).ok()?;
                Some(Input::new(input.features.into(), commitment))
            })
            .collect::<Option<Vec<_>>>()?;
        let outputs = self
            .body
            .outputs
            .into_iter()
            .map(|output| {
                let commitment = Commitment::from_hex(&output.commit).ok()?;
                let proof = RangeProof::from_hex(&output.proof).ok()?;
                Some(Output::new(output.features.into(), commitment, proof))
            })
            .collect::<Option<Vec<_>>>()?;
        let kernels = self
            .body
            .kernels
            .into_iter()
            .map(|kernel| kernel.validate("push_transaction").ok())
            .collect::<Option<Vec<_>>>()?;
        let transaction = Transaction::new(
            offset,
            TransactionBody::from_parts(inputs, outputs, kernels),
        );
        transaction.verify_read().ok()?;
        Some(transaction)
    }
}
