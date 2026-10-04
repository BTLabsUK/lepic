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
//! found confirms the send and stores its change as unspent again.

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

use crate::cancel::{drop_holdings, pool_holds};
use crate::chain;
use crate::error::WalletError;
use crate::lifecycle::Session;
use crate::ports::{SecretVault, StoreOpener};
use crate::refresh::{RefreshError, balance_height, final_kernel, legacy_codecs};
use crate::state::{StateChange, apply_transition, confirm_released, state_name};
use crate::wallet::Wallet;

/// Blocks after finalizing that a send's kernel must still be missing before it may be
/// released: a day of blocks, the wait the Flutter app applies.
pub const RELEASE_AFTER_BLOCKS: u64 = 1_440;

/// Blocks after a release during which a refresh still looks for the send's kernel: a week of
/// blocks. A kernel mined later is not looked for; a scan still finds the change it created.
pub const RELEASED_WATCH_BLOCKS: u64 = 10_080;

const FINALIZED_HEIGHT_PREFIX: &str = "release.finalized_height.";
const KERNEL_ABSENT_PREFIX: &str = "release.kernel_absent.";
const RELEASED_PREFIX: &str = "release.released.";

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
    /// The last height a refresh looks the kernel up to.
    fn watched_until(&self) -> Height {
        // A height that overflows is never reached, so the send stays watched.
        self.released_at
            .checked_add_blocks(RELEASED_WATCH_BLOCKS)
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

/// Keeps what recognises a released send, before its change is deleted. Run it in the store
/// transaction that releases it.
fn record_released(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    check: &ReleaseCheck,
    released_at: Height,
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
        excess: check.excess,
        min_height: check.min_height,
        released_at,
        change,
    };
    repos.put_setting(&key(RELEASED_PREFIX, tx_id), &released.encode())
}

/// The released sends still watched for, with the account each belongs to. A record that does
/// not parse is skipped: the send then keeps its state, as it did before releases were watched.
fn released_sends(
    repos: &dyn Repositories,
) -> Result<Vec<(TxId, AccountIndex, ReleasedSend)>, StoreError> {
    let mut released = Vec::new();
    for account in repos.accounts()? {
        for stored in repos.transactions(account.index)? {
            let entry = &stored.entry;
            if entry.direction != TxDirection::Outgoing || entry.state != TxState::Cancelled {
                continue;
            }
            let Some(text) = repos.setting(&key(RELEASED_PREFIX, stored.id))? else {
                continue;
            };
            match ReleasedSend::decode(&text) {
                Some(send) => released.push((stored.id, entry.account, send)),
                None => warn!(tx_id = %stored.id, "released send unreadable"),
            }
        }
    }
    Ok(released)
}

/// Confirms a released send whose kernel was found at `height` and stores its change as
/// unspent from there, unless a scan already stored it. A send no longer cancelled, or no
/// longer watched, is left as it is.
fn confirm_mined_release(
    repos: &mut dyn Repositories,
    tx_id: TxId,
    account: AccountIndex,
    released: &ReleasedSend,
    height: Height,
    now: Timestamp,
) -> Result<Option<StateChange>, WalletError> {
    let record = key(RELEASED_PREFIX, tx_id);
    let still_cancelled = repos
        .transaction(tx_id)?
        .is_some_and(|entry| entry.state == TxState::Cancelled);
    if !still_cancelled || repos.setting(&record)?.is_none() {
        return Ok(None);
    }
    for change in &released.change {
        if repos.output(change.commitment.as_bytes())?.is_none() {
            repos.put_output(&released.change_record(change, account, tx_id, height))?;
        }
    }
    let change = confirm_released(repos, tx_id, now)?;
    repos.set_confirmed_height(tx_id, height)?;
    repos.delete_setting(&record)?;
    Ok(change)
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
    /// reports. At the call the node is asked once more: its tip must be plausible, and neither
    /// its chain nor its transaction pool may hold the kernel.
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
        let pooled = pool_holds(node, &check.excess)
            .await
            .map_err(WalletError::Node)?;
        if pooled {
            debug!("kernel found in the node pool");
            return Err(WalletError::InPool(tx_id));
        }
        let change = self
            .blocking(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let entry = repos
                        .transaction(tx_id)?
                        .ok_or(WalletError::UnknownTransaction(tx_id))?;
                    if entry.state != observed {
                        return Err(WalletError::ChangedDuringCancel(tx_id));
                    }
                    record_released(repos, tx_id, &check, tip)?;
                    drop_holdings(repos, tx_id, &entry)?;
                    apply_transition(repos, tx_id, TxState::Cancelled, now)
                })
            })
            .await?;
        if let Some(change) = change {
            info!(height = %tip, "transaction released");
            self.emit(change.into());
        }
        Ok(())
    }

    /// Looks up the kernel of every released send still watched, up to the highest confirmed
    /// tip but not past its watch. A kernel found confirms the send at the kernel's height and
    /// stores its change as unspent; a send whose watch ended unseen is no longer watched.
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
        let mut unwatched = Vec::new();
        for (tx_id, account, send) in released {
            let until = send.watched_until().min(height);
            if until < send.min_height {
                continue;
            }
            let kernel = self
                .ports()
                .node
                .get_kernel(&send.excess, Some(send.min_height), Some(until))
                .await?;
            match kernel {
                Some(kernel) => {
                    chain::check_kernel_height(kernel.height, send.min_height, until)?;
                    debug!(tx_id = %tx_id, height = %kernel.height, "released send found on chain");
                    mined.push((tx_id, account, send, kernel.height));
                }
                None if height >= send.watched_until() => unwatched.push(tx_id),
                None => {}
            }
        }
        let session = Arc::clone(session);
        let changes = self
            .blocking(move |_, _| {
                Ok(session.store.write(|repos| {
                    for &tx_id in &unwatched {
                        debug!(tx_id = %tx_id, height = %height, "released send no longer watched");
                        repos.delete_setting(&key(RELEASED_PREFIX, tx_id))?;
                    }
                    let mut changes = Vec::new();
                    for (tx_id, account, send, at) in &mined {
                        changes.extend(confirm_mined_release(
                            repos, *tx_id, *account, send, *at, now,
                        )?);
                    }
                    Ok::<_, WalletError>(changes)
                }))
            })
            .await??;
        Ok(changes)
    }
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
    fn the_watch_ends_a_week_of_blocks_after_the_release() {
        assert_eq!(
            released().watched_until(),
            Height::new(1_444 + RELEASED_WATCH_BLOCKS)
        );
    }
}
