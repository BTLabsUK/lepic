// SPDX-License-Identifier: Apache-2.0
//! Watching a transaction that ended unconfirmed although its kernel may still be mined: a
//! cancelled or expired payment, or a send an earlier version released. Ending it keeps what
//! recognises it on chain: its kernel and the outputs it would have created.
//!
//! For [`RELEASED_WATCH_BLOCKS`] after a send ended (a day of blocks for a receive), each
//! refresh looks the kernel up; a kernel found confirms the transaction and stores its outputs
//! as unspent again. After that window, each refresh asks the node for those outputs, with no
//! end, so a transaction mined later still confirms and its outputs still return.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    AccountIndex, KeyId, OutputRecord, OutputStatus, Record, Recovery, Repositories, SlateStage,
    StoreError, TransactionEntry, TxDirection, TxId, TxState, TxWatch, WalletStore,
    WatchPhase as StoredPhase, WatchedOutput,
};
use tracing::{debug, info, warn};

use crate::chain;
use crate::codecs;
use crate::error::WalletError;
use crate::lifecycle::Session;
use crate::other_wallet;
use crate::ports::{SecretVault, StoreOpener};
use crate::recover::end_for_mined_payment;
use crate::refresh::{RefreshError, balance_height, stored_slate, ttl_cutoff, unless_refused};
use crate::self_send::SELF;
use crate::state::{StateChange, confirm_released};
use crate::wallet::Wallet;
use lepic_primitives::error_chain::ErrorChain;

/// Blocks after a release during which a refresh still looks for the send's kernel: a week of
/// blocks. After it, a refresh looks for the send's change outputs instead; a send with no
/// change is no longer looked for, and only a scan finds what it spent.
pub const RELEASED_WATCH_BLOCKS: u64 = 10_080;

/// Blocks after an incoming payment ended unconfirmed (cancelled, expired or superseded)
/// during which a refresh looks for its kernel: a day of blocks. After it, a refresh asks the
/// node for the payment's own output instead, with no end: nothing stops the sender from
/// posting a signed payment later, and the output is what the payment gives this wallet. A
/// payment its sender's TTL ended with nothing posted is not watched at all
/// ([`lapsed_receipt`]).
pub const ENDED_RECEIVE_WATCH_BLOCKS: u64 = 1_440;

/// What a release keeps to recognise the send if the chain mines it after all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleasedSend {
    excess: Commitment,
    /// The height the slate was created at, below which the kernel cannot be.
    min_height: Height,
    /// The tip the release was decided at.
    released_at: Height,
    change: Vec<ReleasedChange>,
}

/// A change output the release deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReleasedChange {
    commitment: Commitment,
    key_id: KeyId,
    amount: Amount,
}

impl ReleasedSend {
    /// The last height a refresh looks the kernel up to, `window` blocks after the release.
    fn watched_until(&self, window: u64) -> Height {
        // A height that overflows is never reached, so the send stays watched.
        self.released_at
            .checked_add_blocks(window)
            .unwrap_or(Height::new(u64::MAX))
    }

    /// The send as its watch record holds it. A commitment that no longer parses is a
    /// damaged record.
    fn from_watch(watch: &TxWatch) -> Result<Self, StoreError> {
        let commitment = |bytes: &[u8]| {
            Commitment::from_bytes(bytes).map_err(|_| StoreError::Corrupt {
                record: Record::TransactionRecord,
                field: "watched commitment",
            })
        };
        Ok(Self {
            excess: commitment(&watch.excess)?,
            min_height: watch.min_height,
            released_at: watch.ended_at,
            change: watch
                .outputs
                .iter()
                .map(|output| {
                    Ok(ReleasedChange {
                        commitment: commitment(&output.commitment)?,
                        key_id: output.key_id,
                        amount: output.amount,
                    })
                })
                .collect::<Result<_, StoreError>>()?,
        })
    }

    fn to_watch(&self, phase: StoredPhase) -> TxWatch {
        TxWatch {
            phase,
            excess: *self.excess.as_bytes(),
            min_height: self.min_height,
            ended_at: self.released_at,
            outputs: self
                .change
                .iter()
                .map(|change| WatchedOutput {
                    commitment: *change.commitment.as_bytes(),
                    key_id: change.key_id,
                    amount: change.amount,
                })
                .collect(),
        }
    }

    /// The change output as a refresh stores it once the kernel is found at `height`, as the
    /// send stored it before it was mined.
    fn change_record(
        &self,
        change: &ReleasedChange,
        account: AccountIndex,
        tx_id: TxId,
        height: Height,
    ) -> OutputRecord {
        OutputRecord {
            id: OutputIdentifier::new(OutputFeatures::Plain, change.commitment),
            key_id: change.key_id,
            account,
            amount: change.amount,
            status: OutputStatus::Unspent,
            height,
            lock_height: Height::ZERO,
            mmr_index: None,
            tx: Some(tx_id),
        }
    }
}

/// Keeps what recognises a transaction that ends unconfirmed although its kernel may still be
/// mined, before its unconfirmed outputs are deleted: its kernel `excess`, the height
/// `min_height` below which the kernel cannot be, and those outputs. A refresh up to
/// [`RELEASED_WATCH_BLOCKS`] after `ended_at` then confirms it if the kernel is found. Run it in
/// the store transaction that ends it.
pub(crate) fn record_watch(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    excess: Commitment,
    min_height: Height,
    ended_at: Height,
) -> Result<(), StoreError> {
    let change = repos
        .outputs_of_transaction(tx_id)?
        .into_iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .map(|output| ReleasedChange {
            commitment: output.id.commitment,
            key_id: output.key_id,
            amount: output.amount,
        })
        .collect();
    let released = ReleasedSend {
        excess,
        min_height,
        released_at: ended_at,
        change,
    };
    repos.put_tx_watch(tx_id, &released.to_watch(StoredPhase::Kernel))
}

/// Whether the incoming payment `tx_id` ended at its sender's TTL with nothing posted: a
/// payment someone else sent this wallet, never pushed by this wallet and not an invoice it
/// finalized, whose slate's TTL cutoff is at or below `at`. Such a payment keeps no watch once
/// its kernel is known absent: the sender's wallet stops at the same TTL, an update scan still
/// finds an output mined later, and a watch per payment would let a sender who picks a TTL a
/// block away grow the watched set without end.
pub(crate) fn lapsed_receipt(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    entry: &TransactionEntry,
    at: Height,
) -> Result<bool, StoreError> {
    let Some(slate_id) = entry.slate_id else {
        return Ok(false);
    };
    if entry.direction != TxDirection::Incoming
        || entry.transport.as_deref() == Some(SELF.as_str())
        || repos.node_post(tx_id)?.is_some()
        || repos.slate(slate_id, SlateStage::Invoice3)?.is_some()
    {
        return Ok(false);
    }
    Ok(ttl_cutoff(repos, codecs, tx_id, slate_id)?.is_some_and(|cutoff| cutoff <= at))
}

/// How a refresh looks for a watched transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchPhase {
    /// By its kernel, up to `window` blocks after it ended.
    Kernel { window: u64 },
    /// By its outputs, with no end.
    Outputs,
}

impl WatchPhase {
    fn stored(self) -> StoredPhase {
        match self {
            Self::Kernel { .. } => StoredPhase::Kernel,
            Self::Outputs => StoredPhase::Outputs,
        }
    }
}

/// The kernel window of a watched transaction: a day of blocks for an incoming payment, a
/// week for a send.
const fn kernel_window(direction: TxDirection) -> u64 {
    match direction {
        TxDirection::Incoming => ENDED_RECEIVE_WATCH_BLOCKS,
        TxDirection::Outgoing => RELEASED_WATCH_BLOCKS,
    }
}

/// A cancelled or expired transaction still watched for.
#[derive(Debug, Clone)]
struct Watched {
    tx_id: TxId,
    account: AccountIndex,
    send: ReleasedSend,
    phase: WatchPhase,
}

/// The cancelled or expired transactions still watched for, with the account each belongs to
/// and how each is looked for.
fn released_sends(repos: &dyn Repositories) -> Result<Vec<Watched>, StoreError> {
    let mut released = Vec::new();
    for (tx_id, watch) in repos.tx_watches()? {
        let Some(entry) = repos.transaction(tx_id)? else {
            continue;
        };
        if !matches!(entry.state, TxState::Cancelled | TxState::Expired) {
            continue;
        }
        let phase = match watch.phase {
            StoredPhase::Kernel => WatchPhase::Kernel {
                window: kernel_window(entry.direction),
            },
            StoredPhase::Outputs => WatchPhase::Outputs,
        };
        released.push(Watched {
            tx_id,
            account: entry.account,
            send: ReleasedSend::from_watch(&watch)?,
            phase,
        });
    }
    Ok(released)
}

/// What confirming a watched transaction as mined changed.
#[derive(Debug, Default)]
pub(crate) struct MinedRelease {
    /// The changes to the transaction, and to the pair of a recovery it ended.
    pub(crate) changes: Vec<StateChange>,
    /// The open recovery of the transaction, ended failed as the transaction was mined first.
    pub(crate) recovery: Option<Recovery>,
}

/// Confirms a watched transaction found mined at `height`, by its kernel or its output, and
/// stores the outputs it dropped as unspent from there, or takes over those a scan already
/// stored. An open recovery of it ends failed in the same write. A transaction no longer
/// cancelled or expired, or no longer watched in `phase`, is left as it is.
#[allow(clippy::too_many_arguments)] // The watched send and where the chain mined it.
fn confirm_mined_release(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    account: AccountIndex,
    released: &ReleasedSend,
    phase: StoredPhase,
    height: Height,
    now: Timestamp,
) -> Result<MinedRelease, WalletError> {
    let still_ended = repos
        .transaction(tx_id)?
        .is_some_and(|entry| matches!(entry.state, TxState::Cancelled | TxState::Expired));
    let still_watched = repos
        .tx_watch(tx_id)?
        .is_some_and(|watch| watch.phase == phase);
    if !still_ended || !still_watched {
        return Ok(MinedRelease::default());
    }
    // The inputs first: an entry of another wallet's spend they leave may hold the change a
    // scan credited to it, and becomes the entry the change is then taken from.
    claim_inputs(repos, codecs, tx_id)?;
    for change in &released.change {
        match repos.output(change.commitment.as_bytes())? {
            None => repos.put_output(&released.change_record(change, account, tx_id, height))?,
            Some(restored) => adopt_restored_change(repos, tx_id, &restored)?,
        }
    }
    let mut changes: Vec<StateChange> = confirm_released(repos, tx_id, now)?.into_iter().collect();
    repos.set_confirmed_height(tx_id, height)?;
    repos.delete_tx_watch(tx_id)?;
    let recovery = match end_for_mined_payment(repos, codecs, tx_id, height, now)? {
        Some((recovery, pair)) => {
            changes.extend(pair);
            Some(recovery)
        }
        None => None,
    };
    Ok(MinedRelease { changes, recovery })
}

/// Confirms the cancelled or expired transaction whose watched output `commitment` a scan
/// found on chain at `height`, before the scan stores it, so the output is stored as that
/// transaction's and not as a receive of its own: only that transaction creates it. Run it
/// for an output the store does not hold; afterwards the store holds it when it was watched.
pub(crate) fn confirm_found_output(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    commitment: &Commitment,
    height: Height,
    now: Timestamp,
) -> Result<MinedRelease, WalletError> {
    for watched in released_sends(repos)? {
        let watches_it = watched
            .send
            .change
            .iter()
            .any(|change| change.commitment == *commitment);
        if !watches_it {
            continue;
        }
        debug!(tx_id = %watched.tx_id, height = %height, "ended transaction found by a scan");
        return confirm_mined_release(
            repos,
            codecs,
            watched.tx_id,
            watched.account,
            &watched.send,
            watched.phase.stored(),
            height,
            now,
        );
    }
    Ok(MinedRelease::default())
}

/// Records the inputs of `tx_id`, a send the chain mined after it ended here, as spent by it:
/// out of any entry of another wallet's spend, which a refresh that found them gone before it
/// saw the send mined took them for, and away from a later send of this wallet that locked
/// them again and can now never be mined.
fn claim_inputs(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<(), StoreError> {
    let Some(entry) = repos.transaction(tx_id)? else {
        return Ok(());
    };
    let Some(slate_id) = entry.slate_id else {
        return Ok(());
    };
    // The incoming entry of a send to the wallet itself shares the slate; the outgoing one
    // spent the inputs.
    let spender = entry.direction == TxDirection::Outgoing;
    let stages = [
        SlateStage::Standard3,
        SlateStage::Standard1,
        SlateStage::Invoice2,
    ];
    let mut slate = None;
    for stage in stages {
        slate = stored_slate(repos, codecs, tx_id, slate_id, stage)?;
        if slate.is_some() {
            break;
        }
    }
    let Some(slate) = slate else {
        return Ok(());
    };
    for input in slate.inputs() {
        if let Some(output) = repos.output(input.commitment.as_bytes())? {
            other_wallet::revived(repos, &output)?;
            if spender {
                repos.put_output(&OutputRecord {
                    status: OutputStatus::Spent,
                    tx: Some(tx_id),
                    ..output
                })?;
            }
        }
    }
    Ok(())
}

/// Links a change output a scan stored before the late confirmation to the send that created
/// it, and drops the entry the scan restored it under, so the history counts the change once,
/// in the send. An output linked to any other transaction is left alone.
fn adopt_restored_change(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    output: &OutputRecord,
) -> Result<(), StoreError> {
    let restored = match output.tx {
        Some(linked) if linked == tx_id => return Ok(()),
        Some(linked) => {
            let Some(entry) = repos.transaction(linked)? else {
                return Ok(());
            };
            // An entry imported from an old wallet's history is kept with its record.
            let restore_entry = entry.direction == TxDirection::Incoming
                && entry.slate_id.is_none()
                && entry.amount_debited == Amount::ZERO
                && entry.amount_credited == output.amount
                && repos.imported_transaction(linked)?.is_none();
            if !restore_entry {
                return Ok(());
            }
            Some(linked)
        }
        None => None,
    };
    repos.put_output(&OutputRecord {
        tx: Some(tx_id),
        ..output.clone()
    })?;
    if let Some(restored) = restored
        && repos.outputs_of_transaction(restored)?.is_empty()
    {
        debug!(tx_id = %tx_id, "restored entry merged into the released send");
        crate::scan::delete_found_entry(repos, restored)?;
    }
    Ok(())
}

/// Records the tip a send was finalized at. Run it in the store transaction that finalizes.
pub(crate) fn record_finalized(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    tip: Height,
) -> Result<(), StoreError> {
    let mut marks = repos.tx_marks(tx_id)?;
    marks.finalized_at = Some(tip);
    repos.put_tx_marks(tx_id, &marks)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Looks for every cancelled or expired transaction still watched. One in its kernel window
    /// has its kernel looked up, to the highest confirmed tip but not past the window; one past
    /// it has its outputs asked for, all in one request. A kernel or output found confirms the
    /// transaction at that height and stores its outputs as unspent. One whose kernel window
    /// ended unseen is then looked for by its outputs, or, with none, no longer watched.
    /// Returns the state changes stored.
    pub(crate) async fn watch_released(
        &self,
        session: &Arc<Session<S::Store>>,
        tip: Height,
        now: Timestamp,
    ) -> Result<Vec<StateChange>, RefreshError> {
        let (height, released) = {
            let session = Arc::clone(session);
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    Ok::<_, StoreError>((balance_height(repos)?.min(tip), released_sends(repos)?))
                }))
            })
            .await??
        };
        if released.is_empty() {
            return Ok(Vec::new());
        }
        let mut mined = Vec::new();
        let mut kernel_ended = Vec::new();
        let mut late = Vec::new();
        for watched in released {
            let window = match watched.phase {
                WatchPhase::Kernel { window } => window,
                WatchPhase::Outputs => {
                    late.push(watched);
                    continue;
                }
            };
            let send = &watched.send;
            let until = send.watched_until(window).min(height);
            if until < send.min_height {
                continue;
            }
            let floor = chain::kernel_floor(send.min_height, until);
            let answer = self
                .ports()
                .node
                .get_kernel(&send.excess, Some(floor), Some(until))
                .await;
            let Some(kernel) = unless_refused(watched.tx_id, answer)? else {
                continue;
            };
            match kernel {
                Some(kernel) => {
                    chain::check_kernel_height(kernel.height, floor, until)?;
                    debug!(tx_id = %watched.tx_id, height = %kernel.height, "released send found on chain");
                    mined.push((watched, kernel.height));
                }
                None if height >= send.watched_until(window) => kernel_ended.push(watched),
                None => {}
            }
        }
        mined.extend(self.find_late(session, late, height).await?);
        let session = Arc::clone(session);
        let (changes, recoveries) = self
            .blocking(move |_, config| {
                let codecs = codecs::legacy(config.network.params().default_base_fee());
                Ok(session.store.write(|repos| {
                    for watched in &kernel_ended {
                        end_kernel_watch(repos, &codecs, watched, height)?;
                    }
                    let mut changes = Vec::new();
                    let mut recoveries = Vec::new();
                    for (watched, at) in &mined {
                        let confirmed = confirm_mined_release(
                            repos,
                            &codecs,
                            watched.tx_id,
                            watched.account,
                            &watched.send,
                            watched.phase.stored(),
                            *at,
                            now,
                        )?;
                        changes.extend(confirmed.changes);
                        recoveries.extend(confirmed.recovery);
                    }
                    Ok::<_, WalletError>((changes, recoveries))
                }))
            })
            .await??;
        for recovery in &recoveries {
            info!(tx_id = %recovery.tx_id, "recovery failed: the payment was mined first");
            self.emit_recovery(recovery);
        }
        Ok(changes)
    }

    /// The transactions watched by their outputs that are mined, with the height each was
    /// mined at: one of whose outputs the store already holds, as a scan stores it, or the
    /// node holds unspent at or below `height`. The node is asked once, for the outputs of
    /// all the others together; a failed request finds nothing this time.
    ///
    /// The set grows by one entry per payment that ended unconfirmed after this wallet signed
    /// it, except a received payment its sender's TTL ended with nothing posted
    /// ([`lapsed_receipt`]), which a sender can make end a block after it arrives. The rest
    /// leave the inbox's bound on open receipts no sooner than the expiry window or their own
    /// TTL, and each entry adds one commitment to that one request.
    async fn find_late(
        &self,
        session: &Arc<Session<S::Store>>,
        late: Vec<Watched>,
        height: Height,
    ) -> Result<Vec<(Watched, Height)>, RefreshError> {
        if late.is_empty() {
            return Ok(Vec::new());
        }
        let commitments: Vec<Commitment> = late
            .iter()
            .flat_map(|watched| watched.send.change.iter().map(|change| change.commitment))
            .collect();
        let stored = {
            let session = Arc::clone(session);
            let commitments = commitments.clone();
            self.blocking(move |_, _| {
                Ok(session.store.read(|repos| {
                    let mut stored = BTreeMap::new();
                    for commitment in &commitments {
                        // Only a scan stores one of these again, and only from the chain.
                        if let Some(output) = repos.output(commitment.as_bytes())?
                            && output.status != OutputStatus::Unconfirmed
                        {
                            stored.insert(*commitment, output.height);
                        }
                    }
                    Ok::<_, StoreError>(stored)
                }))
            })
            .await??
        };
        let asked: BTreeSet<Commitment> = commitments
            .into_iter()
            .filter(|commitment| !stored.contains_key(commitment))
            .collect();
        let mut found = stored;
        if !asked.is_empty() {
            let request: Vec<Commitment> = asked.iter().copied().collect();
            match self.ports().node.get_outputs(&request).await {
                Ok(locations) => {
                    for location in locations {
                        // A node that reports an output above the confirmed tip is not
                        // believed yet.
                        if location.height <= height && asked.contains(&location.commitment) {
                            found.insert(location.commitment, location.height);
                        }
                    }
                }
                // The rest of the refresh goes on; a later refresh asks again.
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "outputs of ended transactions not looked up");
                }
            }
        }
        Ok(late
            .into_iter()
            .filter_map(|watched| {
                let at = watched
                    .send
                    .change
                    .iter()
                    .filter_map(|change| found.get(&change.commitment).copied())
                    .min()?;
                debug!(tx_id = %watched.tx_id, height = %at, "ended transaction found by its output");
                Some((watched, at))
            })
            .collect())
    }
}

/// Ends the kernel window of `watched`, which passed unseen: a transaction with outputs is
/// looked for by them from now on; one with none, or a payment its sender's TTL ended with
/// nothing posted ([`lapsed_receipt`]), is no longer watched.
fn end_kernel_watch(
    repos: &mut dyn Repositories,
    codecs: &CodecRegistry,
    watched: &Watched,
    height: Height,
) -> Result<(), StoreError> {
    let Some(mut watch) = repos
        .tx_watch(watched.tx_id)?
        .filter(|watch| watch.phase == StoredPhase::Kernel)
    else {
        return Ok(());
    };
    let lapsed = match repos.transaction(watched.tx_id)? {
        Some(entry) => lapsed_receipt(repos, codecs, watched.tx_id, &entry, height)?,
        None => false,
    };
    if watched.send.change.is_empty() || lapsed {
        debug!(tx_id = %watched.tx_id, height = %height, "released send no longer watched");
        repos.delete_tx_watch(watched.tx_id)?;
    } else {
        debug!(tx_id = %watched.tx_id, height = %height, "ended transaction now watched by its outputs");
        watch.phase = StoredPhase::Outputs;
        repos.put_tx_watch(watched.tx_id, &watch)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lepic_keychain::Identifier;

    use super::*;

    fn released() -> ReleasedSend {
        let key_id = Identifier::new(3, [0, 0, 7, 0]).unwrap();
        ReleasedSend {
            excess: Commitment::commit_value(5).unwrap(),
            min_height: Height::new(4),
            released_at: Height::new(1_444),
            change: vec![ReleasedChange {
                commitment: Commitment::commit_value(9).unwrap(),
                key_id: KeyId(key_id.to_bytes()),
                amount: Amount::new(899_200_000),
            }],
        }
    }

    #[test]
    fn a_released_send_round_trips_through_its_watch_record() {
        let send = released();
        let watch = send.to_watch(StoredPhase::Outputs);

        assert_eq!(watch.phase, StoredPhase::Outputs);
        assert_eq!(ReleasedSend::from_watch(&watch).unwrap(), send);
    }

    #[test]
    fn a_watch_record_with_a_commitment_off_the_curve_is_corrupt() {
        let mut watch = released().to_watch(StoredPhase::Kernel);
        watch.outputs[0].commitment = [0xff; 33];

        assert!(matches!(
            ReleasedSend::from_watch(&watch),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn the_kernel_watch_ends_a_week_after_a_send_and_a_day_after_a_receive() {
        assert_eq!(
            released().watched_until(kernel_window(TxDirection::Outgoing)),
            Height::new(1_444 + 10_080)
        );
        assert_eq!(
            released().watched_until(kernel_window(TxDirection::Incoming)),
            Height::new(1_444 + 1_440)
        );
    }
}
