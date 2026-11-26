// SPDX-License-Identifier: Apache-2.0
//! The coinbase a mining node asks the wallet for, as `epic-wallet`'s foreign `build_coinbase`
//! builds it: an output and a kernel for the block reward plus the block's fees, from the
//! wallet's keychain, so a restore from the phrase finds the output again.
//!
//! The output is stored as an unconfirmed coinbase with no transaction, a candidate. A
//! refresh that finds it on chain records the incoming transaction then. A node passes its key
//! back on the next template and gets a candidate with the same key; the earlier one stays,
//! as a block can still be found on the older template. A node is never refused for their
//! number: it would retry for as long as it took and get no new job meanwhile.
//!
//! A candidate built for height `h` can only be in block `h`, so a refresh checks candidates by
//! block rather than asking the node for each output, which the node logs as a miss for every
//! template that did not become a block ([`Wallet::check_candidates`]). It reads the header at
//! each height with candidates, at or below the tip, and reads that block's outputs only when it
//! has not checked these candidates against a block with that hash yet. Three things delete
//! candidates: no match in their block once the tip is more than [`REORG_WINDOW`] blocks above
//! it, a height of 0 or more than [`STALE_AFTER`] blocks above the tip, and [`MAX_CANDIDATES`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use jiff::Timestamp;
use lepic_crypto::aggsig::{create_secnonce, sign_single, verify_single_from_commit};
use lepic_crypto::{Commitment, CryptoError, PublicKey};
use lepic_keychain::proof::create_output;
use lepic_keychain::{Identifier, ProofBuilder, ProofError, SwitchCommitment};
use lepic_node::{NodeApi, OutputLocation};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::kernel::{KernelFeatures, TxKernel};
use lepic_primitives::output::{Output, OutputFeatures};
use lepic_store::{
    AccountIndex, CommitmentBytes, KeyId, OutputRecord, OutputStatus, Repositories, StoreError,
    TransactionEntry, TxDirection, TxId, TxState, WalletStore,
};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use crate::account::{self, DEFAULT_ACCOUNT_LABEL};
use crate::chain;
use crate::error::WalletError;
use crate::other_wallet;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::RefreshError;
use crate::scan::DEFAULT_PAGE_SIZE;
use crate::state::{self, StateChange};
use crate::wallet::Wallet;

/// Blocks above the tip past which a candidate is deleted unchecked: a height no tip has come
/// near.
pub const STALE_AFTER: u64 = 50;

/// Blocks below the tip within which a block may still be replaced, so its candidates stay and
/// its header is read again on each refresh. Once the tip is more than this above a height,
/// candidates its block did not hold are deleted. The deepest reorganisation seen on mainnet
/// was five blocks.
pub const REORG_WINDOW: u64 = 10;

/// Candidates a wallet keeps. Past it the one built longest ago goes (ADR 0048).
pub const MAX_CANDIDATES: usize = 4096;

/// What the node sends: the fees of the block's transactions, the block's height, and the key
/// of the candidate it built the last template with, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinbaseRequest {
    pub fees: Fee,
    pub height: Height,
    pub key_id: Option<Identifier>,
}

/// The coinbase output and kernel for the block, and the key that blinds the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coinbase {
    pub output: Output,
    pub kernel: TxKernel,
    pub key_id: Identifier,
}

#[derive(Debug, Error)]
pub enum CoinbaseError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("coinbase output could not be built")]
    Output(#[source] ProofError),
    #[error("coinbase kernel could not be signed")]
    Signing(#[source] CryptoError),
    #[error("block height {0} leaves no room for the coinbase lock height")]
    Height(Height),
}

impl From<StoreError> for CoinbaseError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Builds the coinbase for the block `request` describes on the default account and stores
    /// its output as a candidate: unconfirmed, with no transaction, and locked until the
    /// network's coinbase maturity has passed above the block.
    ///
    /// The output takes the key the node passed back when that key blinds only candidates of
    /// this wallet and would not make one again for another height; any other key, or none,
    /// takes the account's next output key. Candidates already stored stay. The kernel is
    /// checked against its excess before it is returned.
    ///
    /// Fails with [`WalletError::Locked`] inside [`CoinbaseError::Wallet`] when the wallet is
    /// locked, and with [`WalletError::RestoreScanRequired`] on a database rebuilt from the
    /// seed before a scan from genesis completed. Nothing is stored on failure.
    #[instrument(
        name = "build_coinbase",
        skip_all,
        fields(wallet = %self.config().name, height = %request.height)
    )]
    pub async fn build_coinbase(
        &self,
        request: CoinbaseRequest,
    ) -> Result<Coinbase, CoinbaseError> {
        let session = self.session()?;
        let params = self.config().network.params();
        self.blocking(move |ports, _| {
            Ok(session.store.write(|repos| {
                let account = account::account_by_label(repos, DEFAULT_ACCOUNT_LABEL)?;
                let value = params.coinbase_value(request.fees, request.height);
                let key_id = match request.key_id {
                    Some(key_id)
                        if key_reusable(&*repos, account.index, key_id, value, request.height)? =>
                    {
                        key_id
                    }
                    _ => account::next_output_key(repos, account.index)?,
                };
                let coinbase = build(&session.keychain, value, key_id, &mut **ports.rng.lock())?;
                repos.put_output(&OutputRecord {
                    id: coinbase.output.identifier(),
                    key_id: KeyId(key_id.to_bytes()),
                    account: account.index,
                    amount: value,
                    status: OutputStatus::Unconfirmed,
                    height: request.height,
                    lock_height: params
                        .coinbase_lock_height(request.height)
                        .map_err(|_| CoinbaseError::Height(request.height))?,
                    mmr_index: None,
                    tx: None,
                })?;
                repos.touch_output(coinbase.output.commitment.as_bytes())?;
                delete_over_cap(repos)?;
                debug!(amount = %value, "coinbase built");
                Ok::<_, CoinbaseError>(coinbase)
            }))
        })
        .await?
    }
}

/// The blocks a refresh checked candidates against, kept while the wallet is unlocked: a height,
/// the hash of its block, and the candidates that block was read for and did not hold. Locking
/// or closing the wallet drops them, and the next refresh reads each block again.
#[derive(Default)]
pub(crate) struct CheckedBlocks {
    blocks: Mutex<BTreeMap<Height, CheckedBlock>>,
}

/// One block a refresh read for candidates, and those it did not hold. One it held is not kept:
/// should a reorganisation orphan it and the chain come back to this block, it is read again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckedBlock {
    hash: Hash,
    candidates: BTreeSet<Commitment>,
}

impl CheckedBlocks {
    /// Whether the block with `hash` at `height` was read for every one of `candidates` and held
    /// none of them.
    fn settled(&self, height: Height, hash: Hash, candidates: &BTreeSet<Commitment>) -> bool {
        self.lock().get(&height).is_some_and(|checked| {
            checked.hash == hash && candidates.is_subset(&checked.candidates)
        })
    }

    /// Takes the blocks a refresh checked, once it stored what it found. Heights it did not
    /// check have no candidates left, or none it could read, and are forgotten.
    pub(crate) fn replace(&self, blocks: BTreeMap<Height, CheckedBlock>) {
        *self.lock() = blocks;
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<Height, CheckedBlock>> {
        self.blocks.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What [`Wallet::check_candidates`] found.
#[derive(Debug, Default)]
pub(crate) struct CandidateCheck {
    /// The candidates a block holds, where it holds them.
    pub(crate) found: Vec<OutputLocation>,
    /// Candidates their block did not hold, at heights more than [`REORG_WINDOW`] below the
    /// tip: [`delete_stale`] deletes them.
    pub(crate) expired: BTreeSet<Commitment>,
    /// What to remember in [`CheckedBlocks`] once the refresh stored what it found.
    pub(crate) checked: BTreeMap<Height, CheckedBlock>,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Checks `candidates`, by the height they were built for, against the blocks at those
    /// heights, up to `tip`. Asks the node for no output by commitment: it reads the header at
    /// each height, and the block's outputs only when [`CheckedBlocks`] has not seen these
    /// candidates against that block hash. A height above the tip or at 0 is not asked about.
    /// A block replaced while it was read is not remembered and expires nothing, so the next
    /// refresh reads it again.
    ///
    /// Fails with [`RefreshError::Node`] or [`RefreshError::Implausible`]; nothing is
    /// remembered then.
    pub(crate) async fn check_candidates(
        &self,
        checked: &CheckedBlocks,
        candidates: &BTreeMap<Height, BTreeSet<Commitment>>,
        tip: Height,
    ) -> Result<CandidateCheck, RefreshError> {
        let node = &self.ports().node;
        let mut check = CandidateCheck::default();
        if tip < Height::new(1) {
            return Ok(check);
        }
        for (height, commitments) in candidates.range(Height::new(1)..=tip) {
            let Some(header) = node.get_header(*height).await? else {
                debug!(height = %height, "no header at a candidate's height");
                continue;
            };
            let unmatched = if checked.settled(*height, header.hash, commitments) {
                commitments.clone()
            } else {
                let Some(outputs) = block_coinbase(node, *height, tip).await? else {
                    continue;
                };
                let found: Vec<_> = outputs
                    .into_iter()
                    .filter(|output| {
                        output.height == *height && commitments.contains(&output.commitment)
                    })
                    .collect();
                let after = node.get_header(*height).await?;
                if after.map(|after| after.hash) != Some(header.hash) {
                    debug!(height = %height, "block replaced while it was read");
                    continue;
                }
                let mut unmatched = commitments.clone();
                for output in found {
                    unmatched.remove(&output.commitment);
                    debug!(height = %output.height, "coinbase candidate found in its block");
                    check.found.push(output);
                }
                unmatched
            };
            if height.value().saturating_add(REORG_WINDOW) < tip.value() {
                check.expired.extend(unmatched.iter().copied());
            }
            check.checked.insert(
                *height,
                CheckedBlock {
                    hash: header.hash,
                    candidates: unmatched,
                },
            );
        }
        Ok(check)
    }
}

/// The coinbase outputs of the block at `height`, from its range of the output MMR, or `None`
/// when the node's pages did not cover the range. A coinbase cannot be spent before it matures,
/// so the block's unspent outputs hold its reward.
async fn block_coinbase(
    node: &impl NodeApi,
    height: Height,
    tip: Height,
) -> Result<Option<Vec<OutputLocation>>, RefreshError> {
    let indices = node.get_pmmr_indices(height, Some(height)).await?;
    chain::check_output_index(indices.last_index, tip)?;
    let mut outputs = Vec::new();
    let mut next = indices.first_index;
    // A node returns full pages, and spent outputs only widen a page, so a node that pages
    // past this takes the range one output at a time.
    let most_pages = (indices.last_index.saturating_sub(indices.first_index) / DEFAULT_PAGE_SIZE)
        .saturating_add(2);
    let mut pages = 0u64;
    while next <= indices.last_index {
        pages = pages.saturating_add(1);
        if pages > most_pages {
            debug!(height = %height, "block outputs took more pages than the range holds");
            return Ok(None);
        }
        let page = node
            .get_unspent_outputs(next, Some(indices.last_index), DEFAULT_PAGE_SIZE.get())
            .await?;
        for output in &page.outputs {
            chain::check_output_height(output.height, tip)?;
        }
        outputs.extend(
            page.outputs
                .into_iter()
                .filter(|output| output.features == OutputFeatures::Coinbase)
                .map(|output| OutputLocation {
                    commitment: output.commitment,
                    features: output.features,
                    height: output.height,
                    mmr_index: output.mmr_index,
                }),
        );
        if page.highest_index <= page.last_retrieved_index {
            break;
        }
        match page.last_retrieved_index.checked_add(1) {
            Some(after) if after > next => next = after,
            _ => {
                debug!(height = %height, "block outputs not paged forward");
                return Ok(None);
            }
        }
    }
    Ok(Some(outputs))
}

/// The coinbase output for `value` at `key_id`, and the kernel signed by its excess over the
/// coinbase feature message, as upstream `reward::output` builds them.
pub fn build(
    keychain: &lepic_keychain::Keychain,
    value: Amount,
    key_id: Identifier,
    rng: &mut (impl rand_core::CryptoRng + ?Sized),
) -> Result<Coinbase, CoinbaseError> {
    let switch = SwitchCommitment::Regular;
    let amount = value.value();
    let builder = ProofBuilder::new(keychain).map_err(CoinbaseError::Output)?;
    let plain = create_output(keychain, &builder, amount, &key_id, switch)
        .map_err(CoinbaseError::Output)?;
    let output = Output::new(OutputFeatures::Coinbase, plain.commitment, plain.proof);
    let over_value = Commitment::commit_value(amount).map_err(CoinbaseError::Signing)?;
    let excess =
        Commitment::sum(&[output.commitment], &[over_value]).map_err(CoinbaseError::Signing)?;
    let key = keychain
        .derive_key(amount, &key_id, switch)
        .map_err(WalletError::from)?;
    let public = PublicKey::from_secret_key(&key).map_err(CoinbaseError::Signing)?;
    let nonce = create_secnonce(rng).map_err(CoinbaseError::Signing)?;
    let features = KernelFeatures::Coinbase;
    let message = features.signature_message();
    let signature =
        sign_single(&message, &key, &nonce, Some(&public)).map_err(CoinbaseError::Signing)?;
    verify_single_from_commit(&signature, &message, &excess).map_err(CoinbaseError::Signing)?;
    Ok(Coinbase {
        output,
        kernel: TxKernel::new(features, excess, signature),
        key_id,
    })
}

/// An output a coinbase built and no block has confirmed yet.
pub(crate) fn is_candidate(output: &OutputRecord) -> bool {
    output.status == OutputStatus::Unconfirmed
        && output.tx.is_none()
        && output.id.features == OutputFeatures::Coinbase
}

/// Says whether `key_id` may be used again for `value` at `height`: some output has it, and every
/// one is a candidate of `account` built for this height or for another value. A key that blinds
/// anything else, or nothing this wallet stored, is not reused. The same key and value make the
/// same commitment, and a candidate is checked in the block of its one height: built again for
/// the next height, as a node asks right after it found a block, it would leave the found block
/// unchecked.
fn key_reusable(
    repos: &dyn Repositories,
    account: AccountIndex,
    key_id: Identifier,
    value: Amount,
    height: Height,
) -> Result<bool, StoreError> {
    let key = KeyId(key_id.to_bytes());
    let mut found = false;
    for accounts in repos.accounts()? {
        for output in repos.outputs(accounts.index, None)? {
            if output.key_id != key {
                continue;
            }
            if output.account != account
                || !is_candidate(&output)
                || (output.amount == value && output.height != height)
            {
                return Ok(false);
            }
            found = true;
        }
    }
    Ok(found)
}

/// Deletes the candidates past [`MAX_CANDIDATES`], least recently touched first.
fn delete_over_cap(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    let mut candidates = repos.outputs_by_touch(OutputStatus::Unconfirmed)?;
    candidates.retain(is_candidate);
    let over = candidates.len().saturating_sub(MAX_CANDIDATES);
    for output in candidates.iter().take(over) {
        repos.delete_output(output.commitment())?;
    }
    Ok(())
}

/// Records the incoming transaction of a candidate a block confirmed at `height`, links the
/// output to it, unspent until `lock_height`, and returns the change for the new entry.
pub(crate) fn confirm(
    repos: &mut dyn Repositories,
    output: &mut OutputRecord,
    height: Height,
    lock_height: Height,
    now: Timestamp,
) -> Result<StateChange, StoreError> {
    let tx_id = repos.insert_transaction(&TransactionEntry {
        account: output.account,
        direction: TxDirection::Incoming,
        state: TxState::Confirmed,
        slate_id: None,
        transport: None,
        amount_credited: output.amount,
        amount_debited: Amount::ZERO,
        fee: None,
        created_at: now,
        updated_at: now,
    })?;
    repos.set_confirmed_height(tx_id, height)?;
    output.tx = Some(tx_id);
    output.status = OutputStatus::Unspent;
    output.height = height;
    output.lock_height = lock_height;
    debug!(height = %height, "coinbase confirmed");
    Ok(StateChange {
        tx_id,
        from: TxState::Confirmed,
        to: TxState::Confirmed,
    })
}

/// An output a block reward confirmed that a reorganisation orphaned: unconfirmed again, still
/// linked to its expired entry ([`orphan`]). It can come back only in a block at its own height,
/// so a refresh checks that block like a candidate's for
/// [`crate::refresh::CONFIRMATION_RECHECK_BLOCKS`], as long as it looks again at a confirmed
/// payment.
pub(crate) fn is_orphaned(output: &OutputRecord) -> bool {
    output.status == OutputStatus::Unconfirmed
        && output.tx.is_some()
        && output.id.features == OutputFeatures::Coinbase
}

/// The kernel excess of a block reward confirmed at `confirmed`: an incoming entry with no slate
/// whose output, made at that height, is a coinbase. The reward's kernel commits to the output
/// less its value ([`build`]), so it needs no key. Kernels stay on chain once their block is in
/// it, so a kernel lookup tells a reward the chain holds from one a reorganisation took, spent or
/// not. `None` for any other entry.
pub(crate) fn reward_kernel(
    entry: &TransactionEntry,
    outputs: &[OutputRecord],
    confirmed: Height,
) -> Option<Commitment> {
    if entry.direction != TxDirection::Incoming || entry.slate_id.is_some() {
        return None;
    }
    let output = outputs.iter().find(|output| {
        output.id.features == OutputFeatures::Coinbase && output.height >= confirmed
    })?;
    let value = Commitment::commit_value(output.amount.value()).ok()?;
    Commitment::sum(&[output.id.commitment], &[value]).ok()
}

/// A confirmed block reward a scan looks up by kernel: its id, kernel excess and confirmation
/// height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RewardCheck {
    pub(crate) tx_id: TxId,
    pub(crate) excess: Commitment,
    pub(crate) confirmed: Height,
}

/// The confirmed block rewards whose coinbase output is stored as spent though nothing here spent
/// it: a send relinks the outputs it spends, and another wallet's spend lists them
/// ([`other_wallet`]). A refresh that missed the output after a reorganisation took its block
/// marked it spent this way before rewards were looked up by kernel; a scan finds those at any
/// depth.
pub(crate) fn rewards_to_check(repos: &dyn Repositories) -> Result<Vec<RewardCheck>, StoreError> {
    let spent_elsewhere: BTreeSet<CommitmentBytes> = repos
        .other_wallet_spends()?
        .into_iter()
        .flat_map(|(_, spend)| spend.spent)
        .collect();
    let mut checks = Vec::new();
    for (tx_id, confirmed) in repos.confirmed_from(Height::ZERO)? {
        let Some(entry) = repos.transaction(tx_id)? else {
            continue;
        };
        if entry.state != TxState::Confirmed {
            continue;
        }
        let outputs = repos.outputs_of_transaction(tx_id)?;
        let unexplained = outputs.iter().any(|output| {
            output.id.features == OutputFeatures::Coinbase
                && output.status == OutputStatus::Spent
                && !spent_elsewhere.contains(output.commitment())
        });
        if !unexplained {
            continue;
        }
        if let Some(excess) = reward_kernel(&entry, &outputs, confirmed) {
            checks.push(RewardCheck {
                tx_id,
                excess,
                confirmed,
            });
        }
    }
    Ok(checks)
}

/// Expires the confirmed block reward `tx_id` whose kernel the chain no longer holds: a
/// reorganisation replaced its block. Its coinbase output becomes unconfirmed again
/// ([`is_orphaned`]), out of every balance, still linked to it with its height, and any record
/// of another wallet spending it is undone. Its confirmation height is cleared. Returns the
/// change, or `None` when it is not confirmed.
pub(crate) fn orphan(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    now: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    let Some(confirmed) = repos.confirmed_height(tx_id)? else {
        return Ok(None);
    };
    if repos.transaction(tx_id)?.map(|entry| entry.state) != Some(TxState::Confirmed) {
        return Ok(None);
    }
    for mut output in repos.outputs_of_transaction(tx_id)? {
        if output.id.features != OutputFeatures::Coinbase || output.height < confirmed {
            continue;
        }
        if output.status == OutputStatus::Spent {
            other_wallet::revived(repos, &output)?;
        }
        output.status = OutputStatus::Unconfirmed;
        output.mmr_index = None;
        repos.put_output(&output)?;
    }
    let change = state::orphan_reward(repos, tx_id, now)?;
    repos.clear_confirmed_height(tx_id)?;
    warn!(tx_id = %tx_id, height = %confirmed, "block reward no longer on chain");
    Ok(change)
}

/// Confirms again the orphaned block reward `output` belongs to, which the chain holds after
/// all at `height`: its entry goes back from `expired` to `confirmed`, and the output is unspent
/// until `lock_height`. Returns the change, or `None` when the entry was confirmed already.
pub(crate) fn confirm_again(
    repos: &mut dyn Repositories,
    output: &mut OutputRecord,
    height: Height,
    lock_height: Height,
    now: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    let Some(tx_id) = output.tx else {
        return Ok(None);
    };
    let change = state::confirm_released(repos, tx_id, now)?;
    repos.set_confirmed_height(tx_id, height)?;
    output.status = OutputStatus::Unspent;
    output.height = height;
    output.lock_height = lock_height;
    info!(tx_id = %tx_id, height = %height, "block reward back on chain");
    Ok(change)
}

/// Deletes the candidates no block confirmed that were built for height 0, for a height more
/// than [`STALE_AFTER`] above `tip`, or that are in `expired`, and returns how many.
pub(crate) fn delete_stale(
    repos: &mut dyn Repositories,
    tip: Height,
    expired: &BTreeSet<Commitment>,
) -> Result<u64, StoreError> {
    let highest = tip.value().saturating_add(STALE_AFTER);
    let stale = |output: &OutputRecord| {
        let height = output.height.value();
        height == 0 || height > highest || expired.contains(&output.id.commitment)
    };
    let mut deleted = 0u64;
    for account in repos.accounts()? {
        for output in repos.outputs(account.index, Some(OutputStatus::Unconfirmed))? {
            if is_candidate(&output) && stale(&output) {
                repos.delete_output(output.commitment())?;
                deleted = deleted.saturating_add(1);
            }
        }
    }
    if deleted > 0 {
        debug!(deleted, "stale coinbase candidates deleted");
    }
    Ok(deleted)
}
