//! Releasing a send the network never took: a finalized or posted send whose kernel a refresh
//! did not find on chain [`RELEASE_AFTER_BLOCKS`] or more after it was finalized. Releasing it
//! cancels it as [`Wallet::cancel`] does, so its inputs can be spent again.
//!
//! Whether the node refused the post, never answered it, or took it and then dropped it, a
//! kernel still missing a day of blocks later means the transaction is not on its way to the
//! chain through that node. Another node may still hold it, so the release is the owner's
//! decision, never automatic.
//!
//! A release keeps what recognises the send on chain: its kernel and its change. For
//! [`RELEASED_WATCH_BLOCKS`] after the release, each refresh looks the kernel up; a kernel
//! found confirms the send and stores its change as unspent again. After that window, each
//! refresh asks the node for the change itself, with no end, so a send mined later still
//! confirms and its change still returns.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_keychain::Identifier;
use lepic_node::NodeApi;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    AccountIndex, KeyId, OutputRecord, OutputStatus, Repositories, StoreError, StoredTransaction,
    TxDirection, TxId, TxState, WalletStore,
};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use crate::cancel::{cancel_partner, drop_holdings, pool_holds, self_send_partner};
use crate::chain;
use crate::error::WalletError;
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{RefreshError, balance_height, final_kernel, legacy_codecs, unless_refused};
use crate::state::{StateChange, apply_transition, confirm_released, state_name};
use crate::wallet::Wallet;

/// Blocks after finalizing that a send's kernel must still be missing before it may be
/// released: a day of blocks, the wait the Epic Cash app applies.
pub const RELEASE_AFTER_BLOCKS: u64 = 1_440;

/// Blocks after a release during which a refresh still looks for the send's kernel: a week of
/// blocks. After it, a refresh looks for the send's change outputs instead; a send with no
/// change is no longer looked for, and only a scan finds what it spent.
pub const RELEASED_WATCH_BLOCKS: u64 = 10_080;

/// Blocks after an incoming payment ended unconfirmed (cancelled, expired or superseded)
/// during which a refresh looks for its kernel: a day of blocks. After it, a refresh asks the
/// node for the payment's own output instead, with no end: nothing stops the sender from
/// posting a signed payment later, and the output is what the payment gives this wallet.
pub const ENDED_RECEIVE_WATCH_BLOCKS: u64 = 1_440;

const FINALIZED_HEIGHT_PREFIX: &str = "release.finalized_height.";
const KERNEL_ABSENT_PREFIX: &str = "release.kernel_absent.";
const RELEASED_PREFIX: &str = "release.released.";
/// A watched transaction whose kernel window ended unseen and that is now looked for by its
/// outputs. The record is the one kept under [`RELEASED_PREFIX`], moved.
const LATE_PREFIX: &str = "release.late.";

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

    fn encode(&self) -> String {
        let mut fields = vec![
            self.excess.to_hex(),
            self.min_height.value().to_string(),
            self.released_at.value().to_string(),
        ];
        fields.extend(self.change.iter().map(|change| {
            let key_id: String = change
                .key_id
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!(
                "{}:{key_id}:{}",
                change.commitment.to_hex(),
                change.amount.value()
            )
        }));
        fields.join(" ")
    }

    fn decode(text: &str) -> Option<Self> {
        let mut fields = text.split(' ');
        let excess = Commitment::from_hex(fields.next()?).ok()?;
        let min_height = Height::new(fields.next()?.parse().ok()?);
        let released_at = Height::new(fields.next()?.parse().ok()?);
        let change = fields
            .map(|field| {
                let mut parts = field.split(':');
                let change = ReleasedChange {
                    commitment: Commitment::from_hex(parts.next()?).ok()?,
                    key_id: KeyId(Identifier::from_hex(parts.next()?).ok()?.to_bytes()),
                    amount: Amount::new(parts.next()?.parse().ok()?),
                };
                parts.next().is_none().then_some(change)
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            excess,
            min_height,
            released_at,
            change,
        })
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
    repos.put_setting(&key(RELEASED_PREFIX, tx_id), &released.encode())
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
    fn prefix(self) -> &'static str {
        match self {
            Self::Kernel { .. } => RELEASED_PREFIX,
            Self::Outputs => LATE_PREFIX,
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
/// and how each is looked for. A record that does not parse is skipped: the transaction then
/// keeps its state, as it did before ended transactions were watched.
fn released_sends(repos: &dyn Repositories) -> Result<Vec<Watched>, StoreError> {
    let mut released = Vec::new();
    for account in repos.accounts()? {
        for stored in repos.transactions(account.index)? {
            let entry = &stored.entry;
            if !matches!(entry.state, TxState::Cancelled | TxState::Expired) {
                continue;
            }
            let phases = [
                WatchPhase::Kernel {
                    window: kernel_window(entry.direction),
                },
                WatchPhase::Outputs,
            ];
            for phase in phases {
                let Some(text) = repos.setting(&key(phase.prefix(), stored.id))? else {
                    continue;
                };
                match ReleasedSend::decode(&text) {
                    Some(send) => released.push(Watched {
                        tx_id: stored.id,
                        account: entry.account,
                        send,
                        phase,
                    }),
                    None => warn!(tx_id = %stored.id, "released send unreadable"),
                }
            }
        }
    }
    Ok(released)
}

/// Confirms a watched transaction found mined at `height`, by its kernel or its output, and
/// stores the outputs it dropped as unspent from there, or takes over those a scan already
/// stored. A transaction no longer cancelled or expired, or no longer watched in `phase`, is
/// left as it is.
fn confirm_mined_release(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    account: AccountIndex,
    released: &ReleasedSend,
    phase: WatchPhase,
    height: Height,
    now: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    let record = key(phase.prefix(), tx_id);
    let still_ended = repos
        .transaction(tx_id)?
        .is_some_and(|entry| matches!(entry.state, TxState::Cancelled | TxState::Expired));
    if !still_ended || repos.setting(&record)?.is_none() {
        return Ok(None);
    }
    for change in &released.change {
        match repos.output(change.commitment.as_bytes())? {
            None => repos.put_output(&released.change_record(change, account, tx_id, height))?,
            Some(restored) => adopt_restored_change(repos, tx_id, &restored)?,
        }
    }
    let change = confirm_released(repos, tx_id, now)?;
    repos.set_confirmed_height(tx_id, height)?;
    repos.delete_setting(&record)?;
    Ok(change)
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

/// Why a transaction cannot be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ReleaseRefusal {
    /// Only an outgoing transaction in state `finalized` or `posted` is released.
    #[error("transaction is not a finalized or posted send, it is {}", state_name(*state))]
    NotPendingSend { state: TxState },
    /// The final slate is not stored or no longer decodes, so the kernel cannot be looked up.
    #[error("the kernel of the transaction is not known")]
    KernelUnknown,
    /// No refresh has yet looked the kernel up at or above `from` and missed it.
    #[error("the kernel was not yet looked up at or above height {from}")]
    TooEarly { from: Height },
}

/// What decides whether one finalized or posted send may be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReleaseCheck {
    pub(crate) excess: Commitment,
    /// The height the slate was created at, below which the kernel cannot be.
    pub(crate) min_height: Height,
    /// The height from which a missing kernel makes the send releasable.
    pub(crate) from: Height,
    /// The height at which a refresh last looked the kernel up and missed it.
    pub(crate) absent_at: Option<Height>,
}

impl ReleaseCheck {
    pub(crate) fn releasable(&self) -> bool {
        self.absent_at.is_some_and(|absent| absent >= self.from)
    }

    /// Whether a refresh at `height` should look the kernel up for the release.
    pub(crate) fn due_at(&self, height: Height) -> bool {
        height >= self.from && !self.releasable()
    }
}

/// The release check of `stored`, or why it has none: it is not an outgoing finalized or posted
/// transaction, or its kernel is not known.
pub(crate) fn release_check(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    stored: &StoredTransaction,
) -> Result<Result<ReleaseCheck, ReleaseRefusal>, StoreError> {
    let entry = &stored.entry;
    let pending_send = entry.direction == TxDirection::Outgoing
        && matches!(entry.state, TxState::Finalized | TxState::Posted);
    let Some(slate_id) = entry.slate_id.filter(|_| pending_send) else {
        return Ok(Err(ReleaseRefusal::NotPendingSend { state: entry.state }));
    };
    let Some((excess, min_height)) = final_kernel(repos, codecs, stored.id, slate_id)? else {
        return Ok(Err(ReleaseRefusal::KernelUnknown));
    };
    // Sends finalized before the height was stored count from the slate's creation, which is
    // never later than finalizing.
    let finalized = stored_height(repos, FINALIZED_HEIGHT_PREFIX, stored.id)?.unwrap_or(min_height);
    Ok(Ok(ReleaseCheck {
        excess,
        min_height,
        // A height that overflows is never reached, so the send is never releasable.
        from: finalized
            .checked_add_blocks(RELEASE_AFTER_BLOCKS)
            .unwrap_or(Height::new(u64::MAX)),
        absent_at: stored_height(repos, KERNEL_ABSENT_PREFIX, stored.id)?,
    }))
}

/// Records the tip a send was finalized at. Run it in the store transaction that finalizes.
pub(crate) fn record_finalized(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    tip: Height,
) -> Result<(), StoreError> {
    repos.put_setting(
        &key(FINALIZED_HEIGHT_PREFIX, tx_id),
        &tip.value().to_string(),
    )
}

/// Records that a lookup of the send's kernel up to `height` did not find it.
pub(crate) fn record_kernel_absent(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    height: Height,
) -> Result<(), StoreError> {
    repos.put_setting(
        &key(KERNEL_ABSENT_PREFIX, tx_id),
        &height.value().to_string(),
    )
}

fn key(prefix: &str, tx_id: TxId) -> String {
    format!("{prefix}{tx_id}")
}

/// A stored height that does not parse counts as not stored: the send then waits for the next
/// lookup, which is the safe side.
fn stored_height(
    repos: &dyn Repositories,
    prefix: &str,
    tx_id: TxId,
) -> Result<Option<Height>, StoreError> {
    Ok(match repos.setting(&key(prefix, tx_id))? {
        Some(text) => {
            let height = text.parse().ok().map(Height::new);
            if height.is_none() {
                warn!(tx_id = %tx_id, "release height unreadable");
            }
            height
        }
        None => None,
    })
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Releases a finalized or posted send that the network never took, so its inputs can be
    /// spent again: the transaction is cancelled as [`Wallet::cancel`] cancels it, with its
    /// inputs unlocked, its change output dropped, its state `cancelled` and an
    /// [`crate::Event::Transaction`].
    ///
    /// The send must be releasable, as [`crate::details::TransactionDetails::releasable`]
    /// reports. At the call the node is asked once more: neither its transaction pool nor its
    /// chain may hold the kernel, and its tip must be plausible. The pool is asked first, so a
    /// transaction mined between the two lookups is found on chain.
    ///
    /// If another node still holds the transaction and mines it later, the inputs are spent by
    /// it after all, and a new send that spends them fails. A refresh up to
    /// [`RELEASED_WATCH_BLOCKS`] after the release then confirms the send and stores its change
    /// again ([`Wallet::refresh`]).
    ///
    /// Fails with [`WalletError::Locked`], [`WalletError::UnknownTransaction`],
    /// [`WalletError::NotReleasable`] with the reason, [`WalletError::OnChain`] when the chain
    /// holds the kernel, [`WalletError::InPool`] when the node's pool holds it,
    /// [`WalletError::Node`] or [`WalletError::Implausible`] when the node cannot be asked, and
    /// [`WalletError::ChangedDuringCancel`] when another operation moved the transaction on
    /// meanwhile. Nothing is changed by a failed release.
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn release(&self, tx_id: TxId) -> Result<(), WalletError> {
        let session = self.session()?;
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        let (observed, check) = {
            let session = Arc::clone(&session);
            self.blocking(move |_, _| {
                session
                    .store
                    .read(|repos| releasable(repos, &codecs, tx_id))
            })
            .await?
        };
        let node = &self.ports().node;
        // The pool is asked first, then the tip and the chain up to it, so a transaction that
        // leaves the pool for a block between the lookups is found by the chain lookup.
        let pooled = pool_holds(node, &check.excess)
            .await
            .map_err(WalletError::Node)?;
        if pooled {
            debug!("kernel found in the node pool");
            return Err(WalletError::InPool(tx_id));
        }
        let tip = node.get_tip().await.map_err(WalletError::Node)?.height;
        self.check_plausible_tip(&session, tip).await?;
        let kernel = node
            .get_kernel(&check.excess, Some(check.min_height), Some(tip))
            .await
            .map_err(WalletError::Node)?;
        if let Some(kernel) = kernel {
            debug!(height = %kernel.height, "kernel found on chain");
            return Err(WalletError::OnChain(tx_id));
        }
        let changes = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let entry = repos
                        .transaction(tx_id)?
                        .ok_or(WalletError::UnknownTransaction(tx_id))?;
                    if entry.state != observed {
                        return Err(WalletError::ChangedDuringCancel(tx_id));
                    }
                    let partner = self_send_partner(repos, &entry)?;
                    record_watch(repos, tx_id, check.excess, check.min_height, tip)?;
                    drop_holdings(repos, tx_id, &entry)?;
                    let mut changes: Vec<StateChange> =
                        apply_transition(repos, tx_id, TxState::Cancelled, now)?
                            .into_iter()
                            .collect();
                    if let Some(partner) = partner {
                        let watch = Some((check.excess, check.min_height, tip));
                        changes.extend(cancel_partner(repos, &partner, watch, now)?);
                    }
                    Ok::<_, WalletError>(changes)
                })
            })
            .await?;
        if !changes.is_empty() {
            info!(height = %tip, "transaction released");
        }
        for change in changes {
            self.emit(change.into());
        }
        Ok(())
    }

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
        let changes = self
            .blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    for watched in &kernel_ended {
                        end_kernel_watch(repos, watched, height)?;
                    }
                    let mut changes = Vec::new();
                    for (watched, at) in &mined {
                        changes.extend(confirm_mined_release(
                            repos,
                            watched.tx_id,
                            watched.account,
                            &watched.send,
                            watched.phase,
                            *at,
                            now,
                        )?);
                    }
                    Ok::<_, WalletError>(changes)
                }))
            })
            .await??;
        Ok(changes)
    }

    /// The transactions watched by their outputs that are mined, with the height each was
    /// mined at: one of whose outputs the store already holds, as a scan stores it, or the
    /// node holds unspent at or below `height`. The node is asked once, for the outputs of
    /// all the others together.
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
                        if let Some(output) = repos.output(commitment.as_bytes())? {
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
            for location in self.ports().node.get_outputs(&request).await? {
                // A node that reports an output above the confirmed tip is not believed yet.
                if location.height <= height && asked.contains(&location.commitment) {
                    found.insert(location.commitment, location.height);
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
/// looked for by them from now on, one with none is no longer watched.
fn end_kernel_watch(
    repos: &mut dyn Repositories,
    watched: &Watched,
    height: Height,
) -> Result<(), StoreError> {
    let record = key(RELEASED_PREFIX, watched.tx_id);
    let Some(text) = repos.setting(&record)? else {
        return Ok(());
    };
    repos.delete_setting(&record)?;
    if watched.send.change.is_empty() {
        debug!(tx_id = %watched.tx_id, height = %height, "released send no longer watched");
    } else {
        debug!(tx_id = %watched.tx_id, height = %height, "ended transaction now watched by its outputs");
        repos.put_setting(&key(LATE_PREFIX, watched.tx_id), &text)?;
    }
    Ok(())
}

/// The state and release check of a send that may be released now.
fn releasable(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
) -> Result<(TxState, ReleaseCheck), WalletError> {
    let entry = repos
        .transaction(tx_id)?
        .ok_or(WalletError::UnknownTransaction(tx_id))?;
    let state = entry.state;
    let refused = |reason| WalletError::NotReleasable { tx_id, reason };
    let check =
        release_check(repos, codecs, &StoredTransaction { id: tx_id, entry })?.map_err(refused)?;
    if !check.releasable() {
        return Err(refused(ReleaseRefusal::TooEarly { from: check.from }));
    }
    Ok((state, check))
}

#[cfg(test)]
mod tests {
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
    fn a_released_send_record_round_trips() {
        let send = released();

        assert_eq!(ReleasedSend::decode(&send.encode()), Some(send));
    }

    #[test]
    fn a_released_send_with_no_change_round_trips() {
        let send = ReleasedSend {
            change: Vec::new(),
            ..released()
        };

        assert_eq!(ReleasedSend::decode(&send.encode()), Some(send));
    }

    #[test]
    fn rejects_a_damaged_released_send_record() {
        let text = released().encode();
        let cut = text.rsplit_once(':').unwrap().0;

        assert_eq!(ReleasedSend::decode(cut), None);
        assert_eq!(ReleasedSend::decode(&format!("{text}:1")), None);
        assert_eq!(ReleasedSend::decode(""), None);
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
