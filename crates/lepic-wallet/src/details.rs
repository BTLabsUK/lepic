// SPDX-License-Identifier: Apache-2.0
//! What the wallet knows about one stored transaction beyond its log entry.

use std::num::NonZeroUsize;

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_node::NodeApi;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::registry::CodecRegistry;
use lepic_slate::role::Role;
use lepic_store::{
    AccountIndex, ChainCheck, ImportedKind, OutboxStatus, Recovery, RecoveryState, Repositories,
    SlateStage, StoreError, StoredTransaction, TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::transport::Destination;
use tracing::instrument;
use uuid::Uuid;

use crate::account::AccountError;
use crate::codecs;
use crate::epicbox_invoice::display_message;
use crate::error::WalletError;
use crate::invoice::earliest_cutoff;
use crate::legacy_history::{self, TxOrigin};
use crate::notices::{
    cancelled_report, payer_declined_report, posted_report, receiver_declined_report,
};
use crate::ports::{SecretVault, StoreOpener};
use crate::post_retry::refused_every_time;
use crate::receive::verify_message;
use crate::recover::recovery_selection;
use crate::refresh::{last_confirmed, minimum_confirmations};
use crate::scan::{ScanFound, found_output, scan_found};
use crate::selection::{SelectionRequest, SelectionStrategy};
use crate::send_limit::effective_cutoff;
use crate::slate_cache::{SlateCache, Stages};
use crate::wallet::Wallet;

/// How long the host shows a sender's report that it posted a payment this wallet received,
/// while the payment still waits for its sender. A posted transaction is mined within minutes;
/// a report older than this says nothing the chain has not answered by then.
pub const POSTED_REPORT_WINDOW: jiff::SignedDuration = jiff::SignedDuration::from_hours(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    pub transaction: StoredTransaction,
    /// The excess of the final kernel, read from the final slate stored with the transaction, or
    /// for an invoice payer from the stored I2. `None` when neither is stored: before this
    /// wallet finalizes, for a payment taken by receive, and for an output restored by a scan.
    pub kernel_excess: Option<Commitment>,
    /// The height of the output or kernel that confirmed the transaction, or of the restored
    /// output. `None` while it is unconfirmed, and for one confirmed before heights were stored.
    /// Refresh moves it when a reorganisation mines the confirming output at another height. A
    /// transaction confirmed by its kernel keeps the height of its first confirmation: refresh
    /// stops looking up the kernel once it is confirmed, so a reorganisation is not followed.
    pub confirmed_height: Option<Height>,
    /// The other party's address on the transport that carried the slate: where a send or an
    /// invoice was delivered, or where a slate taken from the Epicbox inbox came from. `None`
    /// for a file exchange, a slate the host passed in, a restored output, and a transaction
    /// stored before addresses were.
    pub counterparty: Option<Destination>,
    /// For a payment received at a listing address ([`Wallet::drain_epicbox_at`]), that
    /// listing. `None` for every other transaction.
    pub receive_listing: Option<crate::namespace::Listing>,
    /// For a payment received at an epic1 address, the address index it came to. `None` for
    /// every other transaction.
    pub epic1_index: Option<u32>,
    /// The height from which the slate may no longer be completed, as its stored stages carry
    /// it. `None` when the slate sets none or no stage is stored.
    pub ttl_cutoff_height: Option<Height>,
    /// For a finalized or posted transaction this wallet posts, the height from which
    /// [`Wallet::post`] no longer posts it: the earlier of its slate's and the wallet's own
    /// cutoff for a send, of its I3's and I1's for an invoice it issued. `None` in any other
    /// state and when no cutoff applies.
    pub post_cutoff_height: Option<Height>,
    /// When this wallet saw the transaction confirmed. `None` unless it is confirmed.
    pub confirmed_at: Option<Timestamp>,
    /// The participants' messages whose signatures verify, in the order the parties joined,
    /// read from the latest stored stage of the slate. Empty for a restored output.
    pub messages: Vec<SlateMessage>,
    /// Whether the transaction is a payment or an invoice, from the stages stored with it.
    pub flow: TxFlow,
    /// Made here, imported from an old wallet's history, or an output a scan found.
    pub origin: TxOrigin,
    /// For an imported transaction, what only the old wallet knew. `None` for any other.
    pub imported: Option<ImportedDetails>,
    /// For an entry a scan stored for an output it found with no record, which scan it was and
    /// how it is dated. `None` for any other, and for one stored before this was recorded.
    pub found: Option<ScanFound>,
    /// A send waiting for its answer whose slate no delivery attempt got to the other party
    /// yet: every attempt failed, or none finished, as when the process ended before the
    /// first. Nothing answers it until it is resent. Also `true` while the first attempt
    /// still runs; `false` once an attempt delivered it, and for any other transaction.
    pub undelivered: bool,
    /// The outputs the transaction created for this wallet, change included, that the wallet
    /// stores, spent or not. For a transaction made here, read from the slate stage this
    /// wallet built, in its order, without the outputs of the stage it answered; for an output
    /// a scan found, its commitment, which a restore finds again. Both stay the same once the
    /// outputs are spent. Otherwise, as for an imported entry, the outputs the store links to
    /// it by commitment, which leave it once a transaction spends them. Empty when none is
    /// stored, as for a cancelled send whose change was dropped.
    pub output_commits: Vec<Commitment>,
    /// The outputs of this wallet the transaction spent: for one made here, the inputs this
    /// wallet added to the slate stage it built, as the store holds them; for a spend by
    /// another wallet, the outputs it spent. Empty for any other.
    pub spent_commits: Vec<Commitment>,
    /// For a spend by another wallet ([`TxOrigin::OtherWallet`], outgoing), whether it rests on
    /// the node's answers alone: no completed scan has covered its blocks yet. Show it as
    /// unverified. `false` for every other transaction.
    pub unverified: bool,
    /// For a payment received over Epicbox that still waits for its sender, when the sender
    /// reported that it posted the transaction, while that report is younger than
    /// [`POSTED_REPORT_WINDOW`]. Advisory: the sender says so, and only a refresh that finds
    /// the kernel confirms the payment. `None` for any other transaction.
    pub sender_reported_posted_at: Option<Timestamp>,
    /// For a received payment this wallet answered, when its sender reported that it cancelled
    /// the payment, as long as the payment is not confirmed: while it waits for its sender, and
    /// after it ended here. Advisory: nothing was released on the report, and a payment the
    /// chain still confirms clears it. Set before this version also, for the payment of an
    /// invoice, when its issuer cancelled the invoice on the relay (Epicbox 3.1.0); a relay's
    /// report sets nothing now. `None` for any other transaction.
    pub sender_reported_cancelled_at: Option<Timestamp>,
    /// For a send this wallet made, when its receiver declined it unanswered, as a wallet set to
    /// refuse payments nobody asked for does (ADR 0045). A send declined now is erased, so this
    /// is set only on a send recorded as declined by an older version, or one a decline could
    /// not erase (a send to the wallet itself, or one an open recovery holds). Show the send as
    /// declined by the receiver. `None` for any other transaction.
    pub receiver_declined_at: Option<Timestamp>,
    /// For a send over stock Epicbox that still waits for its answer, when a refresh marked it
    /// unanswered, a day after it was made. Such a receiver cannot say that it refused the
    /// payment, as one at its open receipt caps does, or that it is offline. Show the send as
    /// not answered; an answer that comes later still finalizes it. `None` for any other
    /// transaction.
    pub unanswered_at: Option<Timestamp>,
    /// For an invoice this wallet issued, when its payer declined it (ADR 0016). The invoice
    /// stays `received` and unpaid: a decline never cancels it, so show it as declined and let
    /// the issuer cancel it. `None` for any other transaction, and for a decline recorded
    /// without a time by an older version.
    pub payer_declined_at: Option<Timestamp>,
    /// Whether [`crate::Wallet::relay_cancel`] can ask the relay to cancel the transaction: it
    /// was filed on an Epicbox 3.1.0 relay under a relay transaction id, and is neither posted
    /// nor ended. The relay may still refuse. `false` for a transaction restored from a backup,
    /// which keeps no relay ids.
    pub relay_cancellable: bool,
    /// Whether the transaction is a block reward this wallet received: an incoming entry with
    /// no slate whose output is a coinbase output, whether a mining node had this wallet build
    /// it or a scan found it. Its output is locked until its `lock_height`.
    pub coinbase: bool,
    /// Why the wallet ended the transaction `expired`, where its records can say
    /// ([`ExpiredReason`]). `None` for a transaction in any other state, and for an expired one
    /// with neither a stored slate nor a known kernel.
    pub expired_reason: Option<ExpiredReason>,
    /// Why the wallet ended the transaction `cancelled`, where it can say
    /// ([`cancelled_reason`]). `None` for a transaction in any other state, and for one the
    /// user or its counterparty cancelled.
    pub cancelled_reason: Option<CancelledReason>,
    /// The latest recovery of this payment ([`Wallet::recover`]), in any state. `None` for a
    /// transaction never recovered.
    pub recovery: Option<RecoveryDetails>,
    /// For an entry of the self-send pair of an open recovery, the payment it recovers. The
    /// wallet neither posts nor cancels the entry until the recovery ends. `None` for any
    /// other transaction.
    pub recovery_of: Option<TxId>,
    /// Whether [`Wallet::recover`] takes the transaction by what the store holds: an outgoing
    /// payment that is finalized, posted, cancelled or expired, with no open recovery, whose
    /// final kernel and inputs are stored, each input held for it, and whose inputs pay the
    /// recovery's fee. The node may still refuse it.
    pub recoverable: bool,
    /// Whether a reorganisation replaced a block this open transaction depends on
    /// ([`ChainReplaced`]). `None` for an ended transaction, and for an open one the wallet saw
    /// no replaced block for.
    pub chain_replaced: Option<ChainReplaced>,
}

/// How a reorganisation touched an open transaction (ADR 0071). The wallet waits in each case;
/// nothing is needed from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainReplaced {
    /// A send whose inputs a reorganisation took: their maker is off chain. The send goes
    /// through once the maker is mined again, and ends `expired`
    /// ([`ExpiredReason::InputsReorged`]) if the maker is not back within 60 blocks.
    InputsReplaced,
    /// A transaction that was confirmed until a reorganisation replaced its block. It is open
    /// again and confirms when a block of the new chain includes it.
    Reopened,
    /// An incoming transaction, open while this session saw a block replaced within the last
    /// 60 blocks: a payment reported mined may take a few blocks more.
    Recent,
}

/// A recovery of a payment as the payment's details show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDetails {
    /// The outgoing entry of the recovery's self-send pair.
    pub sent_tx: TxId,
    /// The incoming entry of the recovery's self-send pair.
    pub received_tx: TxId,
    pub state: RecoveryState,
    /// The blocks from the one holding the recovery's kernel up to the last confirmed height,
    /// counting both. 0 until the chain holds the kernel.
    pub confirmations: u64,
    /// The confirmations at which the recovery ends its payment: the wallet's minimum
    /// confirmations.
    pub needed: u64,
    /// The recovery's fee, from its sent entry.
    pub fee: Option<Fee>,
    /// Why the last push of the recovery failed, or why the recovery failed. `None` once the
    /// chain holds its kernel.
    pub error: Option<String>,
}

/// Why the wallet ended a transaction `cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelledReason {
    /// A send whose inputs a recovery spent back to this wallet: the recovery reached the
    /// account's spend confirmations, so the send can never be mined.
    Recovered,
}

/// Why `transaction` ended `cancelled`: [`CancelledReason::Recovered`] when a recovery of it
/// reached its confirmations. A recovery that ended any other way leaves no reason.
pub fn cancelled_reason(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
) -> Result<Option<CancelledReason>, StoreError> {
    if transaction.entry.state != TxState::Cancelled {
        return Ok(None);
    }
    Ok(repos
        .recovery(transaction.id)?
        .filter(|recovery| recovery.state == RecoveryState::Done)
        .map(|_| CancelledReason::Recovered))
}

/// Why the wallet ended a transaction `expired`, from its stored records only.
///
/// The wallet that started the transaction (the sender of a payment, the issuer of an invoice)
/// holds the other side's answer when it stored the answer's slate (S2 or S3, I2 or I3), knows
/// the final kernel, recorded the tip it finalized at, or recorded a push to the node. Without
/// any of these the transaction ends [`ExpiredReason::NoAnswer`]. Every other expiry, including
/// each one of a wallet that answered (a receive, a paid invoice), ends
/// [`ExpiredReason::NotMined`], unless [`ExpiredReason::RejectedByNode`] applies, which wins.
/// [`ExpiredReason::InputsReorged`] wins over all of them. A block reward only expires
/// [`ExpiredReason::Orphaned`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpiredReason {
    /// A send this wallet finalized whose every push the node's pool refused, until its
    /// cutoff passed. Its inputs are spendable again. Its kernel stays watched: if another
    /// node mines it after all, it becomes `confirmed`.
    RejectedByNode,
    /// A payment or invoice this wallet started whose answer never reached it before its
    /// cutoff. No kernel of it can be mined.
    NoAnswer,
    /// A transaction that was answered but not mined before its cutoff. Its kernel may still
    /// be mined.
    NotMined,
    /// A block reward whose block a reorganisation replaced after it was confirmed. Its output
    /// is unconfirmed again and counts in no balance. It becomes `confirmed` again if the
    /// chain returns to that block.
    Orphaned,
    /// A send whose inputs a reorganisation took, still gone 60 blocks after the wallet first
    /// saw them gone (ADR 0071). Its coins went back to the transactions that made them: each is
    /// unconfirmed until its maker is mined again, and a block reward's is orphaned.
    InputsReorged,
}

/// Why `transaction` expired, as [`expired_reason`], or [`ExpiredReason::Orphaned`] for a block
/// reward: only [`crate::coinbase::orphan`] expires one.
fn expiry(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
    stages: Option<&Stages>,
    kernel_excess: Option<&Commitment>,
    coinbase: bool,
) -> Result<Option<ExpiredReason>, StoreError> {
    if coinbase && transaction.entry.state == TxState::Expired {
        return Ok(Some(ExpiredReason::Orphaned));
    }
    expired_reason(repos, transaction, stages, kernel_excess)
}

/// Why `transaction` ended `expired`, by the rule of [`ExpiredReason`]. `stages` and
/// `kernel_excess` are what [`details`] read for it. An ended transaction is neither answered
/// nor pushed again, so the records do not change after it expired.
pub(crate) fn expired_reason(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
    stages: Option<&Stages>,
    kernel_excess: Option<&Commitment>,
) -> Result<Option<ExpiredReason>, StoreError> {
    let entry = &transaction.entry;
    if entry.state != TxState::Expired {
        return Ok(None);
    }
    if crate::reorg_marks::inputs_reorged_at(repos, entry)?.is_some() {
        return Ok(Some(ExpiredReason::InputsReorged));
    }
    let post = repos.node_post(transaction.id)?;
    if entry.direction == TxDirection::Outgoing && post.as_ref().is_some_and(refused_every_time) {
        return Ok(Some(ExpiredReason::RejectedByNode));
    }
    let Some(stages) = stages else {
        return Ok(kernel_excess.map(|_| ExpiredReason::NotMined));
    };
    let (started, answers) = match flow(stages) {
        TxFlow::Payment => (
            entry.direction == TxDirection::Outgoing,
            [SlateStage::Standard2, SlateStage::Standard3],
        ),
        TxFlow::Invoice => (
            entry.direction == TxDirection::Incoming,
            [SlateStage::Invoice2, SlateStage::Invoice3],
        ),
    };
    let answered = answers.into_iter().any(|stage| stages.has(stage))
        || kernel_excess.is_some()
        || post.is_some()
        || repos.tx_marks(transaction.id)?.finalized_at.is_some();
    Ok(Some(if started && !answered {
        ExpiredReason::NoAnswer
    } else {
        ExpiredReason::NotMined
    }))
}

/// The height from which [`crate::finalize::postable`] refuses to post `transaction`, from its
/// stored stages. Only a legacy I1 adds its own cutoff, as there.
fn post_cutoff(
    repos: &dyn Repositories,
    stages: Option<&Stages>,
    transaction: &StoredTransaction,
) -> Result<Option<Height>, StoreError> {
    let entry = &transaction.entry;
    let (TxState::Finalized | TxState::Posted, Some(stages), Some(slate_id)) =
        (entry.state, stages, entry.slate_id)
    else {
        return Ok(None);
    };
    let ttl = |stage| {
        stages
            .decoded(stage)
            .and_then(|decoded| decoded.ttl_cutoff_height)
    };
    match entry.direction {
        TxDirection::Outgoing => {
            effective_cutoff(repos, transaction.id, ttl(SlateStage::Standard3))
        }
        TxDirection::Incoming => {
            let legacy_issued = repos
                .slate(slate_id, SlateStage::Invoice1)?
                .is_some_and(|stored| stored.codec == LEGACY_V3_JSON.as_str());
            Ok(earliest_cutoff(
                ttl(SlateStage::Invoice3),
                legacy_issued.then(|| ttl(SlateStage::Invoice1)).flatten(),
            ))
        }
    }
}

/// What an imported transaction carries beyond its log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedDetails {
    /// The old wallet's local log id.
    pub source_id: u32,
    pub kind: ImportedKind,
    pub input_count: u32,
    pub output_count: u32,
    /// How the chain scan judged it.
    pub check: ChainCheck,
}

/// Which slate flow a transaction belongs to. With the direction it tells the four kinds
/// apart: an incoming payment was received, an outgoing one sent; an incoming invoice was
/// issued by this wallet, an outgoing one paid by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxFlow {
    /// The sender started it with S1. Also an output a scan restored, which has no slate.
    Payment,
    /// The receiver started it with I1.
    Invoice,
}

/// A participant's message as the slate carries it, with the signature checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlateMessage {
    /// The party that wrote it: the sender or the receiver of the money, whoever started.
    pub role: Role,
    /// The signed text as [`display_message`] makes it safe to display.
    pub text: String,
}

/// The sender's report that it posted a received payment, while the payment waits for it.
/// Reports come only from a paired contact or to an epic1 address; a classic address gets
/// none. One is read only for a payment exchanged with a contact or that came to an epic1
/// address. Reads settings only for a payment that waits.
fn sender_report(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
    now: Timestamp,
) -> Result<Option<Timestamp>, StoreError> {
    let entry = &transaction.entry;
    if entry.slate_id.is_some()
        && entry.direction == TxDirection::Incoming
        && entry.state == TxState::Received
        && (crate::contact_link::tx_contact(repos, transaction.id)?.is_some()
            || crate::epic1_index::index_of(repos, transaction.id)?.is_some())
    {
        posted_report(repos, transaction.id, now)
    } else {
        Ok(None)
    }
}

/// When the receiver of a send this wallet made declined it unanswered. Read only for an
/// outgoing transaction.
fn receiver_decline(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
) -> Result<Option<Timestamp>, StoreError> {
    match transaction.entry.slate_id {
        Some(slate_id) if transaction.entry.direction == TxDirection::Outgoing => {
            receiver_declined_report(repos, slate_id)
        }
        _ => Ok(None),
    }
}

/// When the payer declined the invoice this wallet issued. Reads the setting only for an
/// incoming transaction with a slate.
fn payer_decline(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
) -> Result<Option<Timestamp>, StoreError> {
    match transaction.entry.slate_id {
        Some(slate_id) if transaction.entry.direction == TxDirection::Incoming => {
            payer_declined_report(repos, slate_id)
        }
        _ => Ok(None),
    }
}

/// The sender's report that it cancelled a payment this wallet received, or the issuer's that
/// it cancelled the invoice this wallet paid, while the transaction is not confirmed. Reads the
/// marks only for an incoming payment and an invoice's payment.
fn sender_cancel_report(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
    flow: TxFlow,
) -> Result<Option<Timestamp>, StoreError> {
    let entry = &transaction.entry;
    let cancelled_by_other = match entry.direction {
        TxDirection::Incoming => flow == TxFlow::Payment,
        TxDirection::Outgoing => flow == TxFlow::Invoice,
    };
    if entry.slate_id.is_some() && cancelled_by_other && entry.state != TxState::Confirmed {
        cancelled_report(repos, transaction.id)
    } else {
        Ok(None)
    }
}

/// The stages of one slate, latest first. A transaction stores stages of one flow only.
const LATEST_FIRST: [SlateStage; 6] = [
    SlateStage::Standard3,
    SlateStage::Standard2,
    SlateStage::Standard1,
    SlateStage::Invoice3,
    SlateStage::Invoice2,
    SlateStage::Invoice1,
];

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The stored transaction with what [`TransactionDetails`] adds to it. Reads only the
    /// store. Fails with [`WalletError::Locked`] or [`WalletError::UnknownTransaction`].
    #[instrument(skip_all, fields(wallet = %self.config().name, tx_id = %tx_id))]
    pub async fn transaction_details(
        &self,
        tx_id: TxId,
    ) -> Result<TransactionDetails, WalletError> {
        let session = self.session()?;
        let replaced_recently = session.chain_watch.replaced_recently();
        let base_fee = self.config().network.params().default_base_fee();
        let default_minimum = self.config().policy.default_minimum_confirmations;
        let codecs = codecs::legacy(base_fee);
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let entry = repos
                    .transaction(tx_id)?
                    .ok_or(WalletError::UnknownTransaction(tx_id))?;
                let stored = StoredTransaction { id: tx_id, entry };
                let mut outbox = PendingOutbox::default();
                let recoveries = Recoveries::read(repos, default_minimum, base_fee)?;
                details(
                    repos,
                    &codecs,
                    &session.slates,
                    &mut outbox,
                    &recoveries,
                    stored,
                    replaced_recently,
                    now,
                )
            })
        })
        .await
    }

    /// The details of the transactions `tx_ids` that exist, in the order given, in one read of
    /// the store: what is read once for every transaction of a call (the recoveries, the
    /// pending outbox) is read once for all of them. A caller that builds many rows one by
    /// one pays for the store once. An id no transaction has is left out. Reads only the
    /// store. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name, count = tx_ids.len()))]
    pub async fn transactions_details(
        &self,
        tx_ids: Vec<TxId>,
    ) -> Result<Vec<TransactionDetails>, WalletError> {
        let session = self.session()?;
        let replaced_recently = session.chain_watch.replaced_recently();
        let base_fee = self.config().network.params().default_base_fee();
        let default_minimum = self.config().policy.default_minimum_confirmations;
        let codecs = codecs::legacy(base_fee);
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let mut outbox = PendingOutbox::default();
                let recoveries = Recoveries::read(repos, default_minimum, base_fee)?;
                let mut found = Vec::with_capacity(tx_ids.len());
                for tx_id in tx_ids {
                    let Some(entry) = repos.transaction(tx_id)? else {
                        continue;
                    };
                    found.push(details(
                        repos,
                        &codecs,
                        &session.slates,
                        &mut outbox,
                        &recoveries,
                        StoredTransaction { id: tx_id, entry },
                        replaced_recently,
                        now,
                    )?);
                }
                Ok(found)
            })
        })
        .await
    }

    /// This wallet's send made under `slate_id`, with its details, as for a caller that gave
    /// the send its slate id and lost the reply. Reads only the store. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name, slate_id = %slate_id))]
    pub async fn sent_with_slate(
        &self,
        slate_id: SlateId,
    ) -> Result<Option<TransactionDetails>, WalletError> {
        let session = self.session()?;
        let replaced_recently = session.chain_watch.replaced_recently();
        let base_fee = self.config().network.params().default_base_fee();
        let default_minimum = self.config().policy.default_minimum_confirmations;
        let codecs = codecs::legacy(base_fee);
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let Some(stored) = repos.transaction_by_slate(uuid, TxDirection::Outgoing)? else {
                    return Ok(None);
                };
                let mut outbox = PendingOutbox::default();
                let recoveries = Recoveries::read(repos, default_minimum, base_fee)?;
                details(
                    repos,
                    &codecs,
                    &session.slates,
                    &mut outbox,
                    &recoveries,
                    stored,
                    replaced_recently,
                    now,
                )
                .map(Some)
            })
        })
        .await
    }

    /// When the receiver of this wallet's send under `slate_id` declined it unanswered. Such a
    /// send was erased, so neither [`Wallet::sent_with_slate`] nor the transaction list holds
    /// it: this is how a host answers "declined" for a slate id it gave. `None` when no
    /// decline was taken for it. Reads only the store. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config().name, slate_id = %slate_id))]
    pub async fn send_declined_at(
        &self,
        slate_id: SlateId,
    ) -> Result<Option<Timestamp>, WalletError> {
        let session = self.session()?;
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        self.blocking(move |_, _| {
            session
                .store
                .read(|repos| Ok(receiver_declined_report(repos, uuid)?))
        })
        .await
    }

    /// Every stored transaction of `account` with its details, newest first: in the reverse of
    /// the order they were stored in. Reads only the store. Fails with [`WalletError::Locked`]
    /// or an [`AccountError::UnknownAccount`].
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn transactions(
        &self,
        account: AccountIndex,
    ) -> Result<Vec<TransactionDetails>, WalletError> {
        let session = self.session()?;
        let replaced_recently = session.chain_watch.replaced_recently();
        let base_fee = self.config().network.params().default_base_fee();
        let default_minimum = self.config().policy.default_minimum_confirmations;
        let codecs = codecs::legacy(base_fee);
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                if repos.account(account)?.is_none() {
                    return Err(AccountError::UnknownAccount(account).into());
                }
                // Rows may need the pending outbox: it is read once for all of them.
                let mut outbox = PendingOutbox::default();
                let recoveries = Recoveries::read(repos, default_minimum, base_fee)?;
                repos
                    .transactions(account)?
                    .into_iter()
                    .rev()
                    .map(|stored| {
                        details(
                            repos,
                            &codecs,
                            &session.slates,
                            &mut outbox,
                            &recoveries,
                            stored,
                            replaced_recently,
                            now,
                        )
                    })
                    .collect()
            })
        })
        .await
    }
}

/// The recoveries and what their details need, read once for every transaction of a call.
struct Recoveries {
    stored: Vec<Recovery>,
    tip: Option<Height>,
    needed: u64,
    base_fee: Fee,
}

impl Recoveries {
    fn read(
        repos: &dyn Repositories,
        default_minimum: u64,
        base_fee: Fee,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            stored: repos.recoveries()?,
            tip: last_confirmed(repos)?,
            needed: minimum_confirmations(repos, default_minimum)?,
            base_fee,
        })
    }

    /// The recovery of the payment `tx_id`, as its details show it.
    fn of(
        &self,
        repos: &dyn Repositories,
        tx_id: TxId,
    ) -> Result<Option<RecoveryDetails>, StoreError> {
        let Some(recovery) = self.stored.iter().find(|recovery| recovery.tx_id == tx_id) else {
            return Ok(None);
        };
        let confirmations = match (recovery.kernel_height, self.tip) {
            (Some(height), Some(tip)) => tip
                .value()
                .checked_sub(height.value())
                .map_or(0, |blocks| blocks.saturating_add(1)),
            _ => 0,
        };
        Ok(Some(RecoveryDetails {
            sent_tx: recovery.sent_tx,
            received_tx: recovery.received_tx,
            state: recovery.state,
            confirmations,
            needed: self.needed,
            fee: repos
                .transaction(recovery.sent_tx)?
                .and_then(|entry| entry.fee),
            error: recovery.last_error.clone(),
        }))
    }

    /// The payment whose open recovery made the pair entry `tx_id`.
    fn pair_of(&self, tx_id: TxId) -> Option<TxId> {
        self.stored
            .iter()
            .find(|recovery| {
                recovery.state.is_open()
                    && (recovery.sent_tx == tx_id || recovery.received_tx == tx_id)
            })
            .map(|recovery| recovery.tx_id)
    }

    /// Whether [`Wallet::recover`] passes the checks it makes before it asks the node.
    fn recoverable(
        &self,
        repos: &dyn Repositories,
        transaction: &StoredTransaction,
        stages: Option<&Stages>,
    ) -> Result<bool, WalletError> {
        let open = self
            .stored
            .iter()
            .any(|recovery| recovery.tx_id == transaction.id && recovery.state.is_open());
        let Some(stages) = stages.filter(|stages| !open && stages.final_kernel().is_some()) else {
            return Ok(false);
        };
        // The slate the kernel was read from: a send's S3, or an invoice payment's I2.
        let Some(slate) = [SlateStage::Standard3, SlateStage::Invoice2]
            .into_iter()
            .find_map(|stage| stages.decoded(stage))
        else {
            return Ok(false);
        };
        // As the recovery asks for its inputs; the tip does not limit a selection of all.
        let request = SelectionRequest {
            account: transaction.entry.account,
            amount: Amount::ZERO,
            tip: self.tip.unwrap_or(Height::ZERO),
            minimum_confirmations: 1,
            max_outputs: NonZeroUsize::MIN,
            change_outputs: NonZeroUsize::MIN,
            strategy: SelectionStrategy::All,
            base_fee: self.base_fee,
        };
        match recovery_selection(
            repos,
            transaction.id,
            &transaction.entry,
            &slate.inputs,
            &request,
        ) {
            Ok(_) => Ok(true),
            Err(WalletError::NotRecoverable(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// The slate messages an imported entry kept in its record.
fn imported_messages(messages: &[lepic_store::ImportedMessage]) -> Vec<SlateMessage> {
    messages
        .iter()
        .map(|message| SlateMessage {
            role: if message.participant == 0 {
                Role::Sender
            } else {
                Role::Receiver
            },
            text: message.text.clone(),
        })
        .collect()
}

/// What the stored slates carry is decoded once per session by `slates`; the rest is read from
/// the store on each call.
#[allow(clippy::too_many_arguments)] // What one call reads once for all its transactions.
fn details(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    slates: &SlateCache,
    outbox: &mut PendingOutbox,
    recoveries: &Recoveries,
    transaction: StoredTransaction,
    replaced_recently: bool,
    now: Timestamp,
) -> Result<TransactionDetails, WalletError> {
    let tx_id = transaction.id;
    let stages = match transaction.entry.slate_id {
        Some(slate_id) => Some(slates.stages(repos, codecs, tx_id, slate_id)?),
        None => None,
    };
    let stages = stages.as_deref();
    let final_kernel = stages.and_then(Stages::final_kernel);
    let (kernel_excess, ttl_cutoff_height, messages, flow) = match stages {
        Some(stages) => (
            final_kernel.map(|(excess, _)| excess),
            stages.first().and_then(|slate| slate.ttl_cutoff_height),
            messages(stages),
            flow(stages),
        ),
        None => (None, None, Vec::new(), TxFlow::Payment),
    };
    // A confirmed transaction is final, and only a state change updates an entry, so its last
    // update is the moment it was confirmed.
    let mut confirmed_at =
        (transaction.entry.state == TxState::Confirmed).then_some(transaction.entry.updated_at);
    let (mut kernel_excess, mut ttl_cutoff_height, mut messages) =
        (kernel_excess, ttl_cutoff_height, messages);
    let record = repos.imported_transaction(tx_id)?;
    if let Some(record) = &record {
        // An imported entry has no stored slate: what it knew of its slate is in its record.
        kernel_excess = kernel_excess.or_else(|| {
            record
                .kernel_excess
                .and_then(|bytes| Commitment::from_bytes(&bytes).ok())
        });
        ttl_cutoff_height = ttl_cutoff_height.or(record.ttl_cutoff_height);
        if messages.is_empty() {
            messages = imported_messages(&record.messages);
        }
        if transaction.entry.state == TxState::Confirmed {
            confirmed_at = record.confirmed_at.or(confirmed_at);
        }
    }
    let origin = legacy_history::origin(repos, tx_id, &transaction.entry)?;
    let found = match origin {
        TxOrigin::FoundByScan => scan_found(repos, tx_id)?,
        TxOrigin::Wallet | TxOrigin::Imported | TxOrigin::OtherWallet => None,
    };
    let undelivered = undelivered(repos, outbox, &transaction)?;
    let output_commits = output_commits(repos, stages, &transaction, flow)?;
    let spent_commits = spent_commits(repos, stages, &transaction, flow)?;
    let sender_reported_posted_at = sender_report(repos, &transaction, now)?;
    let sender_reported_cancelled_at = sender_cancel_report(repos, &transaction, flow)?;
    let relay_cancellable = crate::relay_cancel::relay_cancellable(
        repos,
        transaction.entry.slate_id,
        transaction.entry.state,
    )?;
    let receiver_declined_at = receiver_decline(repos, &transaction)?;
    let payer_declined_at = payer_decline(repos, &transaction)?;
    let unverified =
        origin == TxOrigin::OtherWallet && crate::other_wallet::is_unverified(repos, tx_id)?;
    let coinbase = is_coinbase(repos, &transaction, &output_commits)?;
    let excess = kernel_excess.as_ref();
    Ok(TransactionDetails {
        chain_replaced: chain_replaced(repos, &transaction.entry, replaced_recently)?,
        recovery: recoveries.of(repos, tx_id)?,
        recovery_of: recoveries.pair_of(tx_id),
        recoverable: recoveries.recoverable(repos, &transaction, stages)?,
        expired_reason: expiry(repos, &transaction, stages, excess, coinbase)?,
        cancelled_reason: cancelled_reason(repos, &transaction)?,
        post_cutoff_height: post_cutoff(repos, stages, &transaction)?,
        relay_cancellable,
        coinbase,
        unverified,
        sender_reported_posted_at,
        sender_reported_cancelled_at,
        receiver_declined_at,
        unanswered_at: crate::unanswered::unanswered_at(repos, &transaction.entry)?,
        payer_declined_at,
        output_commits,
        spent_commits,
        undelivered,
        origin,
        found,
        imported: record.map(|record| ImportedDetails {
            source_id: record.source_id,
            kind: record.kind,
            input_count: record.input_count,
            output_count: record.output_count,
            check: record.check,
        }),
        kernel_excess,
        confirmed_height: repos.confirmed_height(tx_id)?,
        counterparty: repos.counterparty(tx_id)?.map(Destination::new),
        receive_listing: repos
            .receive_listing(tx_id)?
            .as_ref()
            .map(crate::namespace::Listing::from_stored)
            .transpose()?,
        epic1_index: crate::epic1_index::index_of(repos, tx_id)?,
        ttl_cutoff_height,
        confirmed_at,
        messages,
        flow,
        transaction,
    })
}

/// How a reorganisation touched the open transaction `entry`, by the marks of
/// [`crate::reorg_marks`] and, for [`ChainReplaced::Recent`], whether this session saw a block
/// replaced within the last 60 blocks.
fn chain_replaced(
    repos: &dyn Repositories,
    entry: &lepic_store::TransactionEntry,
    replaced_recently: bool,
) -> Result<Option<ChainReplaced>, StoreError> {
    if crate::state::is_final(entry.state) {
        return Ok(None);
    }
    if crate::reorg_marks::inputs_reorged_at(repos, entry)?.is_some() {
        return Ok(Some(ChainReplaced::InputsReplaced));
    }
    if crate::reorg_marks::reopened_at(repos, entry)?.is_some() {
        return Ok(Some(ChainReplaced::Reopened));
    }
    Ok(
        (replaced_recently && entry.direction == TxDirection::Incoming)
            .then_some(ChainReplaced::Recent),
    )
}

/// A block reward comes with no slate, and its output keeps the coinbase features after it is
/// spent.
fn is_coinbase(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
    output_commits: &[Commitment],
) -> Result<bool, StoreError> {
    let entry = &transaction.entry;
    if entry.direction != TxDirection::Incoming || entry.slate_id.is_some() {
        return Ok(false);
    }
    for commitment in output_commits {
        if repos
            .output(commitment.as_bytes())?
            .is_some_and(|output| output.id.features == OutputFeatures::Coinbase)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The slate ids of the pending outbox entries, read for the first row that needs them.
#[derive(Default)]
struct PendingOutbox(Option<Vec<Uuid>>);

impl PendingOutbox {
    fn holds(&mut self, repos: &dyn Repositories, slate_id: Uuid) -> Result<bool, StoreError> {
        let pending = match &mut self.0 {
            Some(pending) => pending,
            unread @ None => unread.insert(
                repos
                    .outbox(OutboxStatus::Pending)?
                    .into_iter()
                    .map(|stored| stored.entry.slate_id)
                    .collect(),
            ),
        };
        Ok(pending.contains(&slate_id))
    }
}

/// A delivered slate leaves no pending outbox entry of its own behind, so a pending one means no
/// attempt got through.
fn undelivered(
    repos: &dyn Repositories,
    outbox: &mut PendingOutbox,
    transaction: &StoredTransaction,
) -> Result<bool, StoreError> {
    let entry = &transaction.entry;
    let (TxDirection::Outgoing, TxState::Sent, Some(slate_id)) =
        (entry.direction, entry.state, entry.slate_id)
    else {
        return Ok(false);
    };
    outbox.holds(repos, slate_id)
}

/// A store link to a transaction does not say whether it created or spends the output, and
/// moves to the spender, so a stored slate decides first: each party adds its own outputs to
/// the stage it builds. A self-send stores both parties' stages under one slate id.
fn output_commits(
    repos: &dyn Repositories,
    stages: Option<&Stages>,
    transaction: &StoredTransaction,
    flow: TxFlow,
) -> Result<Vec<Commitment>, StoreError> {
    let tx_id = transaction.id;
    let entry = &transaction.entry;
    if let Some(stages) = stages {
        let (built, answered) = match (flow, entry.direction) {
            (TxFlow::Payment, TxDirection::Outgoing) => (SlateStage::Standard1, None),
            (TxFlow::Payment, TxDirection::Incoming) => {
                (SlateStage::Standard2, Some(SlateStage::Standard1))
            }
            (TxFlow::Invoice, TxDirection::Incoming) => (SlateStage::Invoice1, None),
            (TxFlow::Invoice, TxDirection::Outgoing) => {
                (SlateStage::Invoice2, Some(SlateStage::Invoice1))
            }
        };
        if let Some(slate) = stages.decoded(built) {
            let answered = answered.and_then(|stage| stages.decoded(stage));
            let theirs = |commitment: &Commitment| {
                answered.is_some_and(|slate| slate.outputs.contains(commitment))
            };
            let mut commits = Vec::new();
            for &commitment in &slate.outputs {
                if !theirs(&commitment) && repos.output(commitment.as_bytes())?.is_some() {
                    commits.push(commitment);
                }
            }
            return Ok(commits);
        }
    }
    let mut commits: Vec<Commitment> = found_output(repos, tx_id)?.into_iter().collect();
    for output in repos.outputs_of_transaction(tx_id)? {
        if !commits.contains(&output.id.commitment) {
            commits.push(output.id.commitment);
        }
    }
    Ok(commits)
}

fn spent_commits(
    repos: &dyn Repositories,
    stages: Option<&Stages>,
    transaction: &StoredTransaction,
    flow: TxFlow,
) -> Result<Vec<Commitment>, StoreError> {
    let tx_id = transaction.id;
    if let Some(spent) = crate::other_wallet::spent_by(repos, tx_id)? {
        return Ok(spent);
    }
    let entry = &transaction.entry;
    // Only the sender of a payment and the payer of an invoice add inputs.
    let built = match (flow, entry.direction) {
        (TxFlow::Payment, TxDirection::Outgoing) => SlateStage::Standard1,
        (TxFlow::Invoice, TxDirection::Outgoing) => SlateStage::Invoice2,
        _ => return Ok(Vec::new()),
    };
    let Some(slate) = stages.and_then(|stages| stages.decoded(built)) else {
        return Ok(Vec::new());
    };
    let mut commits = Vec::new();
    for &commitment in &slate.inputs {
        if repos.output(commitment.as_bytes())?.is_some() {
            commits.push(commitment);
        }
    }
    Ok(commits)
}

/// A transaction stores stages of one flow only, so any stored invoice stage makes it an
/// invoice.
fn flow(stages: &Stages) -> TxFlow {
    let invoice = [
        SlateStage::Invoice1,
        SlateStage::Invoice2,
        SlateStage::Invoice3,
    ]
    .into_iter()
    .any(|stage| stages.has(stage));
    if invoice {
        TxFlow::Invoice
    } else {
        TxFlow::Payment
    }
}

/// A later stage carries every message of an earlier one, since a party adds its own and keeps
/// the other's. A message whose signature does not verify under its party's excess is left out.
fn messages(stages: &Stages) -> Vec<SlateMessage> {
    LATEST_FIRST
        .into_iter()
        .find_map(|stage| stages.decoded(stage))
        .map(|slate| slate.messages.clone())
        .unwrap_or_default()
}

/// The messages of `slate` whose signatures verify, in the order the parties joined, each made
/// safe to display by [`display_message`].
pub fn verified_messages(slate: &Slate) -> Vec<SlateMessage> {
    slate
        .participants()
        .filter_map(|(role, participant)| {
            let message = participant.message.as_ref()?;
            verify_message(message, &participant.public_blind_excess)
                .ok()
                .map(|()| SlateMessage {
                    role,
                    text: display_message(message.text()),
                })
        })
        .collect()
}
