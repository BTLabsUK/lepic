//! The upstream in-process test chain: an `AutomatedTesting` chain in a scratch directory, grown
//! with upstream's own block helper, plus a fork builder for reorganisation scenarios.

use std::path::Path;
use std::sync::Arc;

use epic_chain::store::DifficultyIter;
use epic_chain::types::NoopAdapter;
use epic_chain::{Chain, Options};
use epic_core::consensus;
use epic_core::core::block::feijoada::{Deterministic, Feijoada, PoWType, next_block_bottles};
use epic_core::core::foundation::load_foundation_output;
use epic_core::core::hash::Hashed;
use epic_core::core::{Block, BlockHeader, Output, Transaction, TxKernel};
use epic_core::global::{self, ChainTypes};
use epic_core::pow;
use epic_wallet_impls::test_framework;

use super::Failure;

/// A directory under the system temporary directory, removed on drop.
pub(crate) struct ScratchDir(tempfile::TempDir);

impl ScratchDir {
    pub(crate) fn new(label: &str) -> Result<ScratchDir, Failure> {
        tempfile::Builder::new()
            .prefix(&format!("lepic-vectors-{label}-"))
            .tempdir()
            .map(ScratchDir)
            .map_err(Failure::Io)
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }
}

/// Upstream reads chain parameters from process-wide settings. Every engine case runs under these,
/// with `crate::chain_type_guard` held.
pub(crate) fn use_test_chain_settings(scratch: &Path) {
    global::set_mining_mode(ChainTypes::AutomatedTesting);
    // A path that does not exist makes upstream use its embedded floonet foundation outputs.
    global::set_foundation_path(
        scratch
            .join("no-foundation-file.json")
            .to_string_lossy()
            .into_owned(),
    );
}

pub(crate) struct TestChain {
    chain: Arc<Chain>,
}

impl TestChain {
    pub(crate) fn new(dir: &Path) -> Result<TestChain, Failure> {
        let genesis = pow::mine_genesis_block().map_err(Failure::upstream)?;
        let chain = Chain::init(
            dir.join(".epic").to_string_lossy().into_owned(),
            Arc::new(NoopAdapter {}),
            genesis,
            pow::verify_size,
            false,
        )
        .map_err(Failure::upstream)?;
        Ok(TestChain {
            chain: Arc::new(chain),
        })
    }

    pub(crate) fn chain(&self) -> &Arc<Chain> {
        &self.chain
    }

    pub(crate) fn head(&self) -> Result<BlockHeader, Failure> {
        self.chain.head_header().map_err(Failure::upstream)
    }

    pub(crate) fn header_at(&self, height: u64) -> Result<BlockHeader, Failure> {
        self.chain
            .get_header_by_height(height)
            .map_err(Failure::upstream)
    }

    /// Appends a block on the current head with upstream's `add_block_with_reward`.
    pub(crate) fn mine(&self, txs: &[&Transaction], output: Output, kernel: TxKernel) {
        test_framework::add_block_with_reward(&self.chain, txs.to_vec(), output, kernel);
    }

    /// A second chain in `dir` holding this chain's blocks up to `height`, as a node that has not
    /// synced past it holds them.
    pub(crate) fn prefix(&self, dir: &Path, height: u64) -> Result<TestChain, Failure> {
        let copy = TestChain::new(dir)?;
        for at in 1..=height {
            let hash = self.header_at(at)?.hash();
            let block = self.chain.get_block(&hash).map_err(Failure::upstream)?;
            copy.chain
                .process_block(block, Options::SKIP_POW)
                .map_err(Failure::upstream)?;
        }
        if copy.head()?.hash() != self.header_at(height)?.hash() {
            return Err(Failure::Story("the chain prefix did not reach its height"));
        }
        Ok(copy)
    }

    /// Appends a fork block on `prev`, which need not be the head. Mirrors `add_block_with_reward`
    /// step for step, except that difficulty and timestamp follow `prev` instead of the head, and
    /// the placeholder proof is offset by `FORK_PROOF_OFFSET`. Returns the new header, which is
    /// not on the main chain until its branch is the longest.
    pub(crate) fn mine_fork_block(
        &self,
        prev: &BlockHeader,
        txs: &[&Transaction],
        output: Output,
        kernel: TxKernel,
    ) -> Result<BlockHeader, Failure> {
        let height = prev.height.checked_add(1).ok_or(Failure::Overflow)?;
        let next_header_info = consensus::next_difficulty(
            1,
            (&prev.pow.proof).into(),
            DifficultyIter::from(prev.hash(), self.chain.store()),
        );
        let txs: Vec<Transaction> = txs.iter().map(|tx| (*tx).clone()).collect();
        let mut block = if consensus::is_foundation_height(height) {
            let foundation = load_foundation_output(height);
            Block::from_coinbases(
                prev,
                txs,
                (output, kernel),
                (foundation.output, foundation.kernel),
                next_header_info.clone().difficulty,
            )
        } else {
            Block::from_reward(
                prev,
                txs,
                output,
                kernel,
                next_header_info.clone().difficulty,
            )
        }
        .map_err(Failure::upstream)?;

        // Upstream spaces blocks by a fixed interval; it is read back from the first block so this
        // builder cannot drift from the helper that built the rest of the chain.
        let spacing = self
            .header_at(1)?
            .timestamp
            .signed_duration_since(self.header_at(0)?.timestamp);
        block.header.version = consensus::header_version(height);
        block.header.timestamp = prev
            .timestamp
            .checked_add_signed(spacing)
            .ok_or(Failure::Overflow)?;
        block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

        let seed_hash = self
            .chain
            .header_pmmr()
            .read()
            .get_header_hash_by_height(pow::randomx::rx_current_seed_height(height))
            .map_err(Failure::upstream)?;
        let mut seed = [0u8; 32];
        let seed_bytes = seed_hash.as_bytes().get(..32).ok_or(Failure::Overflow)?;
        seed.copy_from_slice(seed_bytes);
        block.header.pow.seed = seed;

        self.chain
            .set_txhashset_roots(&mut block)
            .map_err(Failure::upstream)?;
        pow::pow_size(
            &mut block.header,
            next_header_info.difficulty,
            global::proofsize(),
            global::min_edge_bits(),
        )
        .map_err(Failure::upstream)?;

        let emitted_policy = global::get_emitted_policy(height);
        let policy = global::get_policies(emitted_policy)
            .ok_or(Failure::Story("no emission policy at this height"))?;
        let algo = Deterministic::choose_algo(&policy, &prev.bottles);
        block.header.bottles = next_block_bottles(algo, &prev.bottles);
        let proof_seed = prev
            .height
            .checked_add(FORK_PROOF_OFFSET)
            .ok_or(Failure::Overflow)?;
        block.header.pow.proof = pow_proof(&algo, proof_seed);
        block.header.policy = emitted_policy;

        let header = block.header.clone();
        self.chain
            .process_block(block, Options::SKIP_POW)
            .map_err(Failure::upstream)?;
        self.chain.validate(false).map_err(Failure::upstream)?;
        Ok(header)
    }
}

/// A header hash covers the proof but not the block body, and upstream's placeholder proof depends
/// only on the height. A fork block at the same height would hash like the block it replaces, so
/// fork blocks take the placeholder of a height this far above. Test chains here stay far shorter.
const FORK_PROOF_OFFSET: u64 = 0x80;

/// The placeholder proof upstream's test helper puts in each header; `SKIP_POW` never checks it.
fn pow_proof(algo: &PoWType, seed: u64) -> pow::Proof {
    let byte = seed.to_le_bytes().first().copied().unwrap_or_default();
    match algo {
        PoWType::Cuckaroo => pow::Proof::CuckooProof {
            edge_bits: 29,
            nonces: vec![seed; 3],
        },
        PoWType::RandomX => pow::Proof::RandomXProof { hash: [byte; 32] },
        PoWType::Cuckatoo => pow::Proof::CuckooProof {
            edge_bits: 31,
            nonces: vec![seed; 3],
        },
        PoWType::ProgPow => pow::Proof::ProgPowProof { mix: [byte; 32] },
    }
}
