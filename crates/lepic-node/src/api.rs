//! The node port the wallet engine depends on, and the validated values it returns.

use std::future::Future;

use lepic_crypto::{Commitment, RangeProof};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::kernel::TxKernel;
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::tx::Transaction;

use crate::error::NodeError;

/// The foreign API calls the wallet makes, as listed in `docs/compat/node-api.md`.
///
/// Every value returned has been checked: hex fields decode to valid curve values and hashes,
/// and outputs and kernels are the ones that were asked for. Heights and indices are only as
/// trustworthy as the node; use them to bound the next request, not as facts.
pub trait NodeApi: Send + Sync {
    fn get_version(&self) -> impl Future<Output = Result<NodeVersion, NodeError>> + Send;

    fn get_tip(&self) -> impl Future<Output = Result<Tip, NodeError>> + Send;

    /// `Ok(None)` when the node knows no kernel with this excess in the height range.
    fn get_kernel(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> impl Future<Output = Result<Option<LocatedKernel>, NodeError>> + Send;

    /// The commitments the node holds as unspent outputs. A commitment missing from the result
    /// is not in the node's UTXO set. Large lists are split into concurrent requests.
    fn get_outputs(
        &self,
        commitments: &[Commitment],
    ) -> impl Future<Output = Result<Vec<OutputLocation>, NodeError>> + Send;

    /// One page of the UTXO set by output MMR index, with range proofs. Spent entries are
    /// dropped.
    fn get_unspent_outputs(
        &self,
        start_index: u64,
        end_index: Option<u64>,
        max: u64,
    ) -> impl Future<Output = Result<UnspentOutputs, NodeError>> + Send;

    /// The output MMR index range covering a block height range.
    fn get_pmmr_indices(
        &self,
        start_height: Height,
        end_height: Option<Height>,
    ) -> impl Future<Output = Result<PmmrIndices, NodeError>> + Send;

    /// Not retried: a repeated post of a transaction the node already accepted is answered with
    /// an error, which would hide the first success.
    fn push_transaction(
        &self,
        transaction: &Transaction,
        propagation: Propagation,
    ) -> impl Future<Output = Result<(), NodeError>> + Send;

    /// The transactions in the node's transaction pool, waiting to be mined. A transaction
    /// still in the Dandelion stem phase is not listed. Fails with
    /// [`FieldProblem::TooMany`](crate::FieldProblem::TooMany) when the pool lists more than
    /// [`MAX_POOL_KERNELS`] kernels.
    fn get_unconfirmed_transactions(
        &self,
    ) -> impl Future<Output = Result<Vec<PoolTransaction>, NodeError>> + Send;
}

/// The most kernels a pool listing may carry: one per transaction in a node pool of the
/// default maximum size. A larger listing is refused rather than validated.
pub const MAX_POOL_KERNELS: usize = 50_000;

/// A transaction in the node's pool. Only its kernels are read: they identify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTransaction {
    pub kernels: Vec<TxKernel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeVersion {
    pub node_version: String,
    pub block_header_version: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tip {
    pub height: Height,
    pub last_block_pushed: Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocatedKernel {
    pub kernel: TxKernel,
    pub height: Height,
    pub mmr_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputLocation {
    pub commitment: Commitment,
    pub features: OutputFeatures,
    pub height: Height,
    pub mmr_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnspentOutput {
    pub commitment: Commitment,
    pub features: OutputFeatures,
    pub proof: RangeProof,
    pub height: Height,
    pub mmr_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnspentOutputs {
    pub highest_index: u64,
    pub last_retrieved_index: u64,
    pub outputs: Vec<UnspentOutput>,
}

/// First and last output MMR index of a height range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmmrIndices {
    pub first_index: u64,
    pub last_index: u64,
}

/// How the node relays a pushed transaction: Dandelion stem phase first, or broadcast at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propagation {
    Stem,
    Fluff,
}
