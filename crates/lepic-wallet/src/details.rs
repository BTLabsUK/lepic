// SPDX-License-Identifier: Apache-2.0
//! What the wallet knows about one stored transaction beyond its log entry.

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_primitives::output::OutputFeatures;
use lepic_slate::model::{Slate, SlateId};
use lepic_slate::registry::CodecRegistry;
use lepic_slate::role::Role;
use lepic_store::{
    AccountIndex, ChainCheck, ImportedKind, OutboxStatus, Repositories, SlateStage, StoreError,
    StoredTransaction, TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::transport::Destination;
use tracing::instrument;
use uuid::Uuid;

use crate::account::AccountError;
use crate::codecs;
use crate::epicbox_invoice::display_message;
use crate::error::WalletError;
use crate::legacy_history::{self, TxOrigin};
use crate::notices::{cancelled_report, posted_report, receiver_declined_report};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::verify_message;
use crate::release::release_check_with;
use crate::scan::{ScanFound, found_output, scan_found};
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
    /// The height from which the slate may no longer be completed, as its stored stages carry
    /// it. `None` when the slate sets none or no stage is stored.
    pub ttl_cutoff_height: Option<Height>,
    /// When this wallet saw the transaction confirmed. `None` unless it is confirmed.
    pub confirmed_at: Option<Timestamp>,
    /// For a finalized or posted send, the height from which a refresh that still misses its
    /// kernel makes it releasable: [`crate::release::RELEASE_AFTER_BLOCKS`] after it was
    /// finalized. `None` for any other transaction, and when its kernel is not known.
    pub releasable_from: Option<Height>,
    /// Whether [`Wallet::release`] may release the send now: a refresh looked its kernel up at
    /// or above `releasable_from` and did not find it. The release asks the node once more.
    pub releasable: bool,
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
    /// chain still confirms clears it. `None` for any other transaction.
    pub sender_reported_cancelled_at: Option<Timestamp>,
    /// For a send this wallet made, when its receiver declined it unanswered, as a wallet set to
    /// refuse payments nobody asked for does (ADR 0045), and the send was cancelled for it.
    /// Show the send as declined by the receiver. `None` for any other transaction.
    pub receiver_declined_at: Option<Timestamp>,
    /// Whether the transaction is a block reward this wallet received: an incoming entry with
    /// no slate whose output is a coinbase output, whether a mining node had this wallet build
    /// it or a scan found it. Its output is locked until its `lock_height`.
    pub coinbase: bool,
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
/// Reports come only from a method that carries notices, so another payment finds none. Reads
/// a setting only for a payment that waits.
fn sender_report(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
    now: Timestamp,
) -> Result<Option<Timestamp>, StoreError> {
    let entry = &transaction.entry;
    if entry.slate_id.is_some()
        && entry.direction == TxDirection::Incoming
        && entry.state == TxState::Received
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

/// The sender's report that it cancelled a payment this wallet received, while the payment is
/// not confirmed. Reads the marks only for an incoming payment.
fn sender_cancel_report(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
) -> Result<Option<Timestamp>, StoreError> {
    let entry = &transaction.entry;
    if entry.slate_id.is_some()
        && entry.direction == TxDirection::Incoming
        && entry.state != TxState::Confirmed
    {
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
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let entry = repos
                    .transaction(tx_id)?
                    .ok_or(WalletError::UnknownTransaction(tx_id))?;
                let stored = StoredTransaction { id: tx_id, entry };
                let mut outbox = PendingOutbox::default();
                details(repos, &codecs, &session.slates, &mut outbox, stored, now)
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
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        let uuid = Uuid::from_bytes(*slate_id.as_bytes());
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                let Some(stored) = repos.transaction_by_slate(uuid, TxDirection::Outgoing)? else {
                    return Ok(None);
                };
                let mut outbox = PendingOutbox::default();
                details(repos, &codecs, &session.slates, &mut outbox, stored, now).map(Some)
            })
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
        let codecs = codecs::legacy(self.config().network.params().default_base_fee());
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.read(|repos| {
                if repos.account(account)?.is_none() {
                    return Err(AccountError::UnknownAccount(account).into());
                }
                // Rows may need the pending outbox: it is read once for all of them.
                let mut outbox = PendingOutbox::default();
                repos
                    .transactions(account)?
                    .into_iter()
                    .rev()
                    .map(|stored| {
                        details(repos, &codecs, &session.slates, &mut outbox, stored, now)
                    })
                    .collect()
            })
        })
        .await
    }
}

/// What the stored slates carry is decoded once per session by `slates`; the rest is read from
/// the store on each call.
fn details(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    slates: &SlateCache,
    outbox: &mut PendingOutbox,
    transaction: StoredTransaction,
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
            messages = record
                .messages
                .iter()
                .map(|message| SlateMessage {
                    role: if message.participant == 0 {
                        Role::Sender
                    } else {
                        Role::Receiver
                    },
                    text: message.text.clone(),
                })
                .collect();
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
    let release = release_check_with(repos, &transaction, |_| Ok(final_kernel))?.ok();
    let undelivered = undelivered(repos, outbox, &transaction)?;
    let output_commits = output_commits(repos, stages, &transaction, flow)?;
    let spent_commits = spent_commits(repos, stages, &transaction, flow)?;
    let sender_reported_posted_at = sender_report(repos, &transaction, now)?;
    let sender_reported_cancelled_at = sender_cancel_report(repos, &transaction)?;
    let receiver_declined_at = receiver_decline(repos, &transaction)?;
    let unverified =
        origin == TxOrigin::OtherWallet && crate::other_wallet::is_unverified(repos, tx_id)?;
    let coinbase = is_coinbase(repos, &transaction, &output_commits)?;
    Ok(TransactionDetails {
        coinbase,
        unverified,
        sender_reported_posted_at,
        sender_reported_cancelled_at,
        receiver_declined_at,
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
        releasable_from: release.map(|check| check.from),
        releasable: release.is_some_and(|check| check.releasable()),
        kernel_excess,
        confirmed_height: repos.confirmed_height(tx_id)?,
        counterparty: repos.counterparty(tx_id)?.map(Destination::new),
        receive_listing: repos
            .receive_listing(tx_id)?
            .as_ref()
            .map(crate::namespace::Listing::from_stored)
            .transpose()?,
        ttl_cutoff_height,
        confirmed_at,
        messages,
        flow,
        transaction,
    })
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
