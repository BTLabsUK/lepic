//! What the wallet knows about one stored transaction beyond its log entry.

use jiff::Timestamp;
use lepic_crypto::Commitment;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_slate::model::Slate;
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
use crate::epicbox_invoice::display_message;
use crate::error::WalletError;
use crate::legacy_history::{self, TxOrigin};
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::verify_message;
use crate::refresh::{final_kernel, legacy_codecs, stored_slate, ttl_cutoff};
use crate::release::release_check;
use crate::scan::{ScanFound, found_output, scan_found};
use crate::wallet::Wallet;

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
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        self.blocking(move |_, _| {
            session.store.read(|repos| {
                let entry = repos
                    .transaction(tx_id)?
                    .ok_or(WalletError::UnknownTransaction(tx_id))?;
                details(repos, &codecs, StoredTransaction { id: tx_id, entry })
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
        let codecs = legacy_codecs(self.config().network.params().default_base_fee());
        self.blocking(move |_, _| {
            session.store.read(|repos| {
                if repos.account(account)?.is_none() {
                    return Err(AccountError::UnknownAccount(account).into());
                }
                repos
                    .transactions(account)?
                    .into_iter()
                    .rev()
                    .map(|stored| details(repos, &codecs, stored))
                    .collect()
            })
        })
        .await
    }
}

fn details(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    transaction: StoredTransaction,
) -> Result<TransactionDetails, WalletError> {
    let tx_id = transaction.id;
    let (kernel_excess, ttl_cutoff_height, messages, flow) = match transaction.entry.slate_id {
        Some(slate_id) => (
            final_kernel(repos, codecs, tx_id, slate_id)?.map(|(excess, _)| excess),
            ttl_cutoff(repos, codecs, tx_id, slate_id)?,
            messages(repos, codecs, tx_id, slate_id)?,
            flow(repos, slate_id)?,
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
        TxOrigin::Wallet | TxOrigin::Imported => None,
    };
    let release = release_check(repos, codecs, &transaction)?.ok();
    let undelivered = undelivered(repos, &transaction)?;
    let output_commits = output_commits(repos, codecs, &transaction, flow)?;
    Ok(TransactionDetails {
        output_commits,
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
        ttl_cutoff_height,
        confirmed_at,
        messages,
        flow,
        transaction,
    })
}

/// A delivered slate leaves no pending outbox entry of its own behind, so a pending one means no
/// attempt got through.
fn undelivered(
    repos: &dyn Repositories,
    transaction: &StoredTransaction,
) -> Result<bool, StoreError> {
    let entry = &transaction.entry;
    let (TxDirection::Outgoing, TxState::Sent, Some(slate_id)) =
        (entry.direction, entry.state, entry.slate_id)
    else {
        return Ok(false);
    };
    Ok(repos
        .outbox(OutboxStatus::Pending)?
        .iter()
        .any(|stored| stored.entry.slate_id == slate_id))
}

/// A store link to a transaction does not say whether it created or spends the output, and
/// moves to the spender, so a stored slate decides first: each party adds its own outputs to
/// the stage it builds. A self-send stores both parties' stages under one slate id.
fn output_commits(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    transaction: &StoredTransaction,
    flow: TxFlow,
) -> Result<Vec<Commitment>, StoreError> {
    let tx_id = transaction.id;
    let entry = &transaction.entry;
    if let Some(slate_id) = entry.slate_id {
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
        if let Some(slate) = stored_slate(repos, codecs, tx_id, slate_id, built)? {
            let answered = match answered {
                Some(stage) => stored_slate(repos, codecs, tx_id, slate_id, stage)?,
                None => None,
            };
            let theirs = |commitment: &Commitment| {
                answered.as_ref().is_some_and(|slate| {
                    slate
                        .outputs()
                        .iter()
                        .any(|output| output.commitment == *commitment)
                })
            };
            let mut commits = Vec::new();
            for output in slate.outputs() {
                if !theirs(&output.commitment)
                    && repos.output(output.commitment.as_bytes())?.is_some()
                {
                    commits.push(output.commitment);
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

/// A transaction stores stages of one flow only, so any stored invoice stage makes it an
/// invoice.
fn flow(repos: &dyn Repositories, slate_id: Uuid) -> Result<TxFlow, StoreError> {
    for stage in [
        SlateStage::Invoice1,
        SlateStage::Invoice2,
        SlateStage::Invoice3,
    ] {
        if repos.slate(slate_id, stage)?.is_some() {
            return Ok(TxFlow::Invoice);
        }
    }
    Ok(TxFlow::Payment)
}

/// A later stage carries every message of an earlier one, since a party adds its own and keeps
/// the other's. A message whose signature does not verify under its party's excess is left out.
fn messages(
    repos: &dyn Repositories,
    codecs: &CodecRegistry,
    tx_id: TxId,
    slate_id: Uuid,
) -> Result<Vec<SlateMessage>, StoreError> {
    for stage in LATEST_FIRST {
        if let Some(slate) = stored_slate(repos, codecs, tx_id, slate_id, stage)? {
            return Ok(verified_messages(&slate));
        }
    }
    Ok(Vec::new())
}

fn verified_messages(slate: &Slate) -> Vec<SlateMessage> {
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
