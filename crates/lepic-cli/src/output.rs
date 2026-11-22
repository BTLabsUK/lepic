// SPDX-License-Identifier: Apache-2.0
//! What commands print. With `--output json` every command prints exactly one JSON document on
//! stdout, its fields named as below; amounts are strings of EPIC with eight decimals, so they
//! survive parsers that read numbers as doubles. Logs go to stderr either way.

use std::fmt::Write as _;
use std::io::Write as _;

use lepic_store::RecoveryState;
use lepic_wallet::selection::Selection;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::amount::{AmountError, format_units, parse_amount};
use crate::exit::CliError;
use crate::settings::OutputFormat;

mod epic1;
mod mailbox;

pub use epic1::{
    Epic1AddressReport, Epic1AnswerReport, Epic1AnswersReport, Epic1AttemptReport, Epic1LinkReport,
    Epic1NotReadReport, Epic1PaidReport, Epic1ReadReport, Epic1RestoreReport, EpictxOpenReport,
};
pub(crate) use mailbox::probe_lines;
pub use mailbox::{
    MailboxAddReport, MailboxEntryReport, MailboxListReport, MailboxProbeReport,
    MailboxRemoveReport, ProbeStepReport,
};

// One report is built per command and rendered at once, so the size of its largest variant
// costs nothing worth a box around it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Report {
    Init(InitReport),
    Restore(RestoreReport),
    Scan(WalletScanReport),
    Info(InfoReport),
    Address(AddressReport),
    Outputs(OutputsReport),
    Consolidate(ConsolidateReport),
    Password(PasswordReport),
    Backup(BackupReport),
    Send(SendReport),
    Resend(ResendReport),
    Receive(ReceiveReport),
    SlateReceive(SlateReceiveReport),
    Finalize(FinalizeReport),
    Post(PostReport),
    Cancel(CancelReport),
    Recover(RecoverReport),
    List(TxListReport),
    Show(TxReport),
    InvoiceIssue(InvoiceIssueReport),
    InvoicePay(InvoicePayReport),
    InvoiceList(InvoiceListReport),
    InvoiceDecline(InvoiceDeclineReport),
    Inbox(InboxReport),
    Serve(ServeReport),
    ServeStatus(ServeStatusReport),
    EpicboxStatus(EpicboxStatusReport),
    HttpListen(HttpListenReport),
    TorAddress(TorAddressReport),
    TorListen(TorListenReport),
    NodeStatus(NodeStatusReport),
    ImportHistory(ImportHistoryReport),
    ContactInvite(ContactInviteReport),
    ContactPreview(ContactPreviewReport),
    ContactAccept(ContactAcceptReport),
    ContactLink(ContactLinkReport),
    ContactCollect(ContactCollectReport),
    Contact(ContactReport),
    ContactList(ContactListReport),
    ContactRemove(ContactRemoveReport),
    ContactKeyCheck(ContactKeyCheckReport),
    ContactCheck(ContactCheckReport),
    ContactMoveHome(ContactMoveHomeReport),
    ProfileShow(ProfileShowReport),
    ProfileSet(ProfileSetReport),
    ProfileDomainShow(ProfileDomainShowReport),
    ProfileDomainFile(ProfileDomainFileReport),
    ProfileDomainDocument(ProfileDomainDocumentReport),
    ProfileDomainAttach(ProfileDomainAttachReport),
    ContactSlate(ContactSlateReport),
    ContactInvoiceIssue(ContactInvoiceIssueReport),
    ContactInvoices(ContactInvoiceListReport),
    ContactExport(ContactExportReport),
    ContactBackup(ContactBackupReport),
    ContactImport(ContactImportReport),
    ContactPayloadPost(ContactPayloadPostReport),
    ContactPayloadList(ContactPayloadListReport),
    ContactPayloadAck(ContactPayloadAckReport),
    ContactQuarantine(ContactQuarantineReport),
    ApiClientAdd(ApiClientReport),
    ApiClientList(ApiClientListReport),
    ApiClientRemove(ApiClientReport),
    InPersonCode(InPersonCodeReport),
    InPersonRead(InPersonReadReport),
    InPersonPaid(InPersonPaidReport),
    InPersonPost(InPersonPostReport),
    InPersonTaken(InPersonTakenReport),
    InPersonAnswers(InPersonAnswersReport),
    Epic1Address(Epic1AddressReport),
    Epic1Link(Epic1LinkReport),
    Epic1Read(Epic1ReadReport),
    Epic1Paid(Epic1PaidReport),
    Epic1Answers(Epic1AnswersReport),
    Epic1Restore(Epic1RestoreReport),
    EpictxOpen(EpictxOpenReport),
    MailboxList(MailboxListReport),
    MailboxAdd(MailboxAddReport),
    MailboxRemove(MailboxRemoveReport),
    MailboxProbe(MailboxProbeReport),
}

#[derive(Serialize)]
pub struct InitReport {
    pub network: String,
    pub data_dir: String,
    /// Shown once, for the user to write down.
    #[serde(serialize_with = "expose")]
    pub recovery_phrase: Zeroizing<String>,
}

impl std::fmt::Debug for InitReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitReport")
            .field("network", &self.network)
            .field("data_dir", &self.data_dir)
            .field("recovery_phrase", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct RestoreReport {
    pub network: String,
    pub data_dir: String,
    /// `null` when the scan was skipped.
    pub scan: Option<ScanReport>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub start_height: u64,
    pub end_height: u64,
    pub found: u64,
    pub restored: u64,
}

/// What `wallet scan` did: every field of the engine's scan summary.
#[derive(Debug, Serialize)]
pub struct WalletScanReport {
    pub start_height: u64,
    pub end_height: u64,
    /// The scan continued one that was interrupted instead of starting over.
    pub resumed: bool,
    /// Outputs of this wallet found on chain, stored before or not.
    pub found: u64,
    /// Outputs found that were not stored, now stored with a transaction each.
    pub restored: u64,
    /// Outputs stored as spent that were found unspent.
    pub revived: u64,
    /// Locked outputs unlocked; only `--delete-unconfirmed` unlocks any.
    pub unlocked: u64,
    /// Unconfirmed outputs deleted; only `--delete-unconfirmed` deletes any.
    pub deleted: u64,
    /// Whether `--delete-unconfirmed` ran, so human output names its counts.
    #[serde(skip)]
    pub delete_unconfirmed: bool,
}

#[derive(Debug, Serialize)]
pub struct InfoReport {
    pub network: String,
    /// The chain tip the balances were computed at.
    pub height: u64,
    /// True when the node is behind the last refresh, so the balances were not updated.
    pub node_behind: bool,
    /// True when the node's tip is too far above the wallet's confirmed height to be taken from
    /// one answer, so the balances are at `height`, below the node's tip.
    pub catching_up: bool,
    /// The node's tip while `catching_up`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_height: Option<u64>,
    pub accounts: Vec<AccountReport>,
}

#[derive(Debug, Serialize)]
pub struct AccountReport {
    pub index: u32,
    pub label: String,
    pub total: Option<String>,
    pub spendable: Option<String>,
    pub awaiting_confirmation: Option<String>,
    pub awaiting_finalization: Option<String>,
    pub immature: Option<String>,
    pub locked: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddressReport {
    pub address: String,
}

/// What a consolidation spent, or for a dry run would spend, and the outputs it made.
#[derive(Debug, Default, Serialize)]
pub struct ConsolidateReport {
    pub dry_run: bool,
    /// The consolidation was made before under the same slate id and is not made again; only
    /// its account, transaction and slate id are given.
    pub repeated: bool,
    pub account: String,
    /// The outgoing entry of the self-send pair; none for a dry run.
    pub tx_id: Option<u32>,
    pub slate_id: Option<String>,
    /// Hex commitments of the outputs spent, the smallest first.
    pub inputs: Vec<String>,
    /// Sum of the values spent.
    pub total: String,
    pub smallest: Option<String>,
    pub largest: Option<String>,
    pub fee: Option<String>,
    /// Values of the outputs made.
    pub outputs: Vec<String>,
}

impl ConsolidateReport {
    pub(crate) fn of(
        account: String,
        selection: &Selection,
        tx_id: Option<u32>,
        slate_id: Option<String>,
    ) -> Self {
        let value = |amount: lepic_primitives::amount::Amount| format_units(amount.value());
        let spent = || selection.inputs.iter().map(|input| input.amount);
        Self {
            dry_run: tx_id.is_none(),
            repeated: false,
            account,
            tx_id,
            slate_id,
            inputs: selection
                .inputs
                .iter()
                .map(|input| input.id.commitment.to_hex())
                .collect(),
            total: value(selection.total),
            smallest: spent().min().map(value),
            largest: spent().max().map(value),
            fee: Some(format_units(selection.fee.value())),
            outputs: std::iter::once(selection.amount)
                .chain(selection.change.iter().copied())
                .map(value)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OutputsReport {
    pub account: String,
    pub outputs: Vec<OutputReport>,
}

#[derive(Debug, Serialize)]
pub struct OutputReport {
    /// Hex commitment.
    pub commitment: String,
    pub value: String,
    pub status: &'static str,
    /// Where the output counts in the balance; none for a spent output.
    pub category: Option<&'static str>,
    pub is_coinbase: bool,
    pub height: u64,
    /// First height the output can be spent at, when it has one.
    pub lock_height: Option<u64>,
    pub confirmations: u64,
    pub tx_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct PasswordReport {
    pub changed: bool,
}

/// A wallet backup written: the folder and the files in it.
#[derive(Debug, Serialize)]
pub struct BackupReport {
    pub dir: String,
    pub files: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SendReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    pub fee: String,
    pub transport: String,
    /// The Epicbox address, the file path or the HTTP endpoint the slate went to.
    pub destination: String,
    /// `sent`, or `posted` when the receiver answered over HTTP and the transaction was
    /// finalized and posted in the same command. For a repeat, the first send's state now.
    pub state: &'static str,
    /// The send was made before under the same `--slate-id`; this run sent nothing.
    pub repeated: bool,
    /// Whether a delivery attempt got the slate to the other party. `false` for a repeat that
    /// was never delivered, and for a send to a contact that no mailbox took yet: the outbox
    /// posts it again, and `tx resend` or `tx cancel` ends it.
    pub delivered: bool,
    /// Why the last post did not go, with the mailbox and its words when one refused. Only an
    /// undelivered send has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the outbox posts an undelivered send next.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    /// How the slate went: `legacy` JSON, the one format this wallet writes. Null for a repeat,
    /// which sent nothing.
    pub format: Option<&'static str>,
    /// The bytes the longest post of the payment takes on the relay, the S1 or the answer
    /// the receiver sends back. Absent when the slate went another way, and for a repeat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slate_bytes: Option<usize>,
    /// The most bytes the relay takes in one post. Absent with `slate_bytes`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slate_limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ResendReport {
    pub tx_id: u32,
    pub transport: String,
    /// The Epicbox address, the file path or the HTTP endpoint the slate went to.
    pub destination: String,
    /// As in [`SendReport::state`].
    pub state: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ReceiveReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    pub reply_file: String,
    /// The slate was received before; `reply_file` holds the reply stored then.
    pub repeated: bool,
}

/// A slate received through the API: the reply travels in the answer, not in a file.
#[derive(Debug, Serialize)]
pub struct SlateReceiveReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    /// The reply slate to give the sender, V3 slate JSON.
    pub slate: String,
    /// The slate was received before; `slate` is the reply stored then.
    pub repeated: bool,
}

#[derive(Debug, Serialize)]
pub struct FinalizeReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct PostReport {
    pub tx_id: u32,
    pub state: String,
    /// The node refused the push because its chain already holds the kernel.
    pub already_on_chain: bool,
    /// The block holding the kernel, when `already_on_chain`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
}

/// A recovery the node took, already held or could not be reached for; a failed one is an
/// error.
#[derive(Debug, Serialize)]
pub struct RecoverReport {
    /// The send recovered.
    pub tx_id: u32,
    /// The outgoing entry of the recovery's self-send pair.
    pub recovery_tx_id: u32,
    /// `posted`, `confirming` when the node already holds it, or `uncertain` when the node
    /// could not be reached.
    pub state: String,
}

/// The name a recovery's state has in reports and in the API.
pub(crate) const fn recovery_state_name(state: RecoveryState) -> &'static str {
    match state {
        RecoveryState::Uncertain => "uncertain",
        RecoveryState::Posted => "posted",
        RecoveryState::Confirming => "confirming",
        RecoveryState::Done => "done",
        RecoveryState::Failed => "failed",
    }
}

#[derive(Debug, Serialize)]
pub struct CancelReport {
    pub tx_id: u32,
    pub state: String,
    /// What the Epicbox relay said when asked to cancel the transaction for both parties:
    /// `cancelled`, `not_found_or_not_participant`, `unsupported`, `no_relay_id` or `failed`.
    /// Absent when the relay was not asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Why asking the relay failed, when `relay` is `failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TxListReport {
    pub account: String,
    pub transactions: Vec<TxReport>,
}

#[derive(Debug, Serialize)]
pub struct TxReport {
    pub tx_id: u32,
    pub direction: String,
    pub state: String,
    pub amount_credited: String,
    pub amount_debited: String,
    pub fee: Option<String>,
    pub slate_id: Option<String>,
    pub transport: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Slate stages stored for the transaction; listed by `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stages: Option<Vec<String>>,
    /// Hex excess of the final kernel; shown by `tx show` only, when a final slate is stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_excess: Option<String>,
    /// Block height the transaction was confirmed at; shown by `tx show` only, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_height: Option<u64>,
    /// The parties' messages whose signatures verify; listed by `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<MessageReport>>,
    /// `wallet`, `imported` or `found-by-scan`; shown by `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<&'static str>,
    /// `true` for a mining reward: an incoming coinbase output with no slate; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<bool>,
    /// For an imported transaction, what the old wallet recorded; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported: Option<Box<ImportedReport>>,
    /// For a payment received over Epicbox that waits for its sender, when the sender reported
    /// that it posted it, within the hour after; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_reported_posted_at: Option<String>,
    /// For a received payment that is not confirmed, when its sender reported that it
    /// cancelled it; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_reported_cancelled_at: Option<String>,
    /// For a send its receiver refused unanswered, when it said so (ADR 0045). Only a send kept
    /// from before the wallet erased such sends shows it. `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_declined_at: Option<String>,
    /// For an invoice this wallet issued, when its payer declined it. The invoice stays
    /// unpaid; cancel it to end it. `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_declined_at: Option<String>,
    /// For a payment received at a listing address, the service key (hex) and generation of
    /// that listing; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_listing: Option<ListingReport>,
    /// For a send `tx recover` recovered, its latest recovery; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<TxRecoveryReport>,
    /// For a send no mailbox or endpoint took yet, how its posts stand; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<TxDeliveryReport>,
}

/// How the posts of an undelivered send stand, as `tx show` lists them.
#[derive(Debug, Serialize)]
pub struct TxDeliveryReport {
    /// Always `true`: the report exists only for a send nothing took yet.
    pub undelivered: bool,
    /// No route took the send in the time the outbox allows before it marks one. A mark
    /// only: the outbox tries on, and `tx cancel` ends the send.
    pub stuck: bool,
    /// When the send is, or will be, marked stuck.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stuck_at: Option<String>,
    /// When the outbox posts it next.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    /// The posts made, over every route.
    pub attempts: u32,
    /// Why the last post did not go, with the mailbox and its words when one refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The recovery of a send, as `tx show` lists it.
#[derive(Debug, Serialize)]
pub struct TxRecoveryReport {
    /// The outgoing entry of the recovery's self-send pair.
    pub tx_id: u32,
    /// `uncertain`, `posted`, `confirming`, `done` or `failed`.
    pub state: String,
    /// Confirmations of the recovery's kernel, 0 before the chain has it.
    pub confirmations: u64,
    /// The confirmations after which the recovery is done.
    pub needed: u64,
    /// The recovery's own fee, in EPIC; absent while its sent entry does not hold one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A listing: the service key in hex and the generation.
#[derive(Debug, Serialize)]
pub struct ListingReport {
    pub service_key: String,
    pub generation: u32,
}

/// What `wallet import-history` did; counts are of records.
#[derive(Debug, Serialize)]
pub struct ImportHistoryReport {
    pub status: &'static str,
    pub transactions: u32,
    pub outputs: u32,
    pub accounts_named: u32,
    pub linked: u32,
    pub skipped: u32,
    pub confirmed_by_kernel: u32,
    pub dated: u32,
}

/// What the old wallet recorded of an imported transaction.
#[derive(Debug, Serialize)]
pub struct ImportedReport {
    pub source_id: u32,
    pub kind: &'static str,
    pub input_count: u32,
    pub output_count: u32,
    pub check: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MessageReport {
    /// `sender` or `receiver` of the money.
    pub role: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct InvoiceIssueReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    pub transport: String,
    /// The payer's Epicbox address or the file path the invoice went to.
    pub destination: String,
    /// The invoice slate file to give the payer; only for `--to-file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvoicePayReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    pub fee: String,
    pub transport: String,
    /// The issuer's allowed address or the file path the payment went to.
    pub destination: String,
    /// The reply to give the issuer, who finalizes it; only for an invoice slate file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_file: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvoiceListReport {
    pub invoices: Vec<ParkedInvoiceReport>,
}

#[derive(Debug, Serialize)]
pub struct ParkedInvoiceReport {
    pub slate_id: String,
    /// The allowed address of the sender, where a payment goes.
    pub sender: String,
    pub amount: String,
    /// The issuer's message, when its signature verifies, with hidden formatting removed.
    pub message: Option<String>,
    pub received_at: String,
    /// When a drain or listen deletes it unpaid.
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub struct InvoiceDeclineReport {
    pub slate_id: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct InboxReport {
    pub received: u32,
    pub finalized: u32,
    pub repeated: u32,
    pub rejected: u32,
    pub held: u32,
    /// Messages acknowledged and forgotten unread: anything over Epicbox that is not a stock
    /// slate, and notices of no known exchange.
    pub dropped: u32,
    /// Notices about invoices accepted from the other party: posted, declined or withdrawn.
    pub notices: u32,
    /// Notices for a slate this wallet does not hold yet, kept to apply when it arrives.
    pub buffered: u32,
    /// What the invoice expiry did; `null` when it could not run, which the log says why.
    pub expired: Option<ExpiredReport>,
}

#[derive(Debug, Default, Serialize)]
pub struct ExpiredReport {
    /// Slate ids of parked invoices deleted unpaid.
    pub deleted: Vec<String>,
    /// Invoices this wallet issued and cancelled unpaid.
    pub cancelled: Vec<u32>,
    /// Payments of invoices that were not posted within their TTL; `tx cancel` gives up on
    /// them.
    pub cancellable: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactInviteReport {
    pub contact_id: String,
    pub link: String,
    pub expires_at: String,
}

/// A code to show as a QR code, from `in-person invoice`.
#[derive(Debug, Serialize)]
pub struct InPersonCodeReport {
    pub tx_id: u32,
    pub slate_id: String,
    /// The raw `lepic.v1` bytes as hex, when they were not written to a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The height from which the code is refused.
    pub ttl_cutoff: u64,
    /// The relay of the code's reply mailbox, `domain[:port]`; absent when the answer comes
    /// back by hand.
    pub mailbox: Option<String>,
}

/// The relay a code names for its answer, as it is shown before posting.
#[derive(Debug, Serialize)]
pub struct InPersonHostReport {
    pub host: String,
    pub port: u16,
    /// The host is a mailbox of this wallet's list.
    pub in_relay_list: bool,
    /// `public` or `local_network`.
    pub host_rule: &'static str,
}

/// What a scanned code asks, from `in-person read`.
#[derive(Debug, Serialize)]
pub struct InPersonReadReport {
    pub slate_id: String,
    /// `invoice` for an I1, `send` for an S1.
    pub stage: &'static str,
    pub amount: String,
    /// The fee this wallet would pay, when it can tell now.
    pub fee: Option<String>,
    pub message: Option<String>,
    pub ttl_cutoff: u64,
    pub mailbox: Option<InPersonHostReport>,
    /// The domain the code is signed for; absent for a code not signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<InPersonDomainReport>,
    /// The payee's direct routes, in its order; the answer is posted to each.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub direct: Vec<InPersonRouteReport>,
}

/// The domain a scanned code is signed for, and whether its well-known file proves it.
#[derive(Debug, Serialize)]
pub struct InPersonDomainReport {
    pub domain: String,
    /// `checked`: the domain's file lists the key; `unchecked`: no file was given;
    /// `refused`: the file does not prove the claim, for `reason`.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The key that signed the code, hex.
    pub key: String,
    /// Unix seconds when the code was signed, as the code says.
    pub issued_at: u64,
}

/// A route an answer is posted to.
#[derive(Debug, Serialize)]
pub struct InPersonRouteReport {
    /// `epicbox`, `http` or `tor`.
    pub method: String,
    pub value: String,
}

/// An answer to a scanned code, from `in-person pay`.
#[derive(Debug, Serialize)]
pub struct InPersonPaidReport {
    pub tx_id: u32,
    pub slate_id: String,
    /// The sealed answer as hex, when it was not written to a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub mailbox: Option<InPersonHostReport>,
    /// The domain the paid code is signed for, from `in-person pay`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<InPersonDomainReport>,
}

/// An answer posted to the relay and the direct routes its code names, from `in-person post`.
#[derive(Debug, Serialize)]
pub struct InPersonPostReport {
    pub slate_id: String,
    /// A route took the answer.
    pub posted: bool,
    /// The check code the other screen shows for this answer, shown only once it is posted.
    pub check_code: String,
    /// What each route did, the reply mailbox first.
    pub routes: Vec<InPersonRoutePostReport>,
}

/// The post of an answer to one route.
#[derive(Debug, Serialize)]
pub struct InPersonRoutePostReport {
    pub method: String,
    pub value: String,
    /// `accepted`, `refused` or `failed`.
    pub outcome: &'static str,
    /// Why it was refused, as the payee said, or why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// An answer taken for a code this wallet showed, from `in-person take`.
#[derive(Debug, Serialize)]
pub struct InPersonTakenReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub answer: u32,
    pub check_code: String,
    /// An earlier answer had the same check code.
    pub same_code: bool,
    /// The same answer was taken before; nothing changed.
    pub duplicate: bool,
}

/// One answer to a code this wallet showed.
#[derive(Debug, Serialize)]
pub struct InPersonAnswerReport {
    pub number: u32,
    pub check_code: String,
    pub same_code: bool,
    pub received_at: String,
}

/// A code this wallet showed and its answers, from `in-person answers`.
#[derive(Debug, Serialize)]
pub struct InPersonAnswersReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub stage: &'static str,
    pub ttl_cutoff: u64,
    pub mailbox: Option<String>,
    /// An answer that checks arrived: the code is no longer shown.
    pub closed: bool,
    /// The answer that was finalized.
    pub finalized: Option<u32>,
    pub answers: Vec<InPersonAnswerReport>,
}

#[derive(Debug, Serialize)]
pub struct ContactPreviewReport {
    /// What the inviter calls itself, unverified.
    pub claimed_name: String,
    pub kind: &'static str,
    pub expires_at: String,
    pub home_relay: String,
    pub service: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactAcceptReport {
    pub contact_id: String,
    /// The reply as a link, to send by hand when `posted` is false.
    pub reply_link: String,
    pub posted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactLinkReport {
    /// `confirm` (send `link` back by hand), `paired`, `ignored`, or `invite` (an invite `link` was
    /// found, to answer).
    #[serde(deserialize_with = "pairing_outcome")]
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

/// The `outcome` of a [`ContactLinkReport`] serve answered, as one of the words it can be.
fn pairing_outcome<'de, D: Deserializer<'de>>(deserializer: D) -> Result<&'static str, D::Error> {
    known_word(deserializer, &["confirm", "paired", "ignored", "invite"])
}

/// A word a report field holds from a fixed set, read back from serve's JSON.
pub(crate) fn known_word<'de, D: Deserializer<'de>>(
    deserializer: D,
    words: &[&'static str],
) -> Result<&'static str, D::Error> {
    let word = String::deserialize(deserializer)?;
    words
        .iter()
        .find(|known| **known == word)
        .copied()
        .ok_or_else(|| serde::de::Error::unknown_variant(&word, &[]))
}

#[derive(Debug, Serialize)]
pub struct ContactCollectReport {
    pub mailboxes: usize,
    pub capped: usize,
    pub kept: usize,
    pub not_reached: usize,
    /// Mailboxes another socket of the same wallet took over; an open takes them back, and the
    /// session attaches them again when the hold-off ends.
    pub replaced: usize,
    pub quarantined: usize,
    pub quarantine_dropped: usize,
    pub buffered: usize,
    pub messages: usize,
    pub paired: usize,
    pub delivered: usize,
    /// Payments taken at the delivery mailboxes of open epic1 addresses and answers finalized.
    pub epic1: usize,
    /// Pairings in progress that ended with nothing stored.
    pub failed: Vec<ContactFailureReport>,
    pub unreachable: Vec<String>,
    /// The mailboxes of `unreachable` that answered without mux/1: not down, just not read.
    pub no_mux: Vec<String>,
    /// Sends no mailbox took for longer than the outbox allows before it marks one. The
    /// outbox keeps trying; `tx cancel` ends one.
    pub stuck: Vec<StuckSendReport>,
    /// The posts of this run that a mailbox refused, one per post, with the mailbox's words and
    /// the wait it asked for.
    pub refused: Vec<RefusedPostReport>,
}

/// A mailbox's refusal of a post, in the words it gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MailboxRefusalReport {
    /// The mailbox that refused, `domain:port`; absent for a native endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
    /// The mailbox's own words; absent when it gave none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The wait the mailbox asked for before the next post, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// The refusal passes: the outbox posts again after the wait. Any other refusal is final.
    pub retryable: bool,
    /// The refusal as one line: "mailbox X refused the post: <reason>, retry in N s".
    pub text: String,
}

impl From<&lepic_wallet_contacts::MailboxRefusal> for MailboxRefusalReport {
    fn from(refusal: &lepic_wallet_contacts::MailboxRefusal) -> Self {
        Self {
            mailbox: refusal.mailbox.clone(),
            reason: refusal.reason.clone(),
            retry_after_secs: refusal.retry_after.map(|wait| wait.as_secs()),
            retryable: refusal.retryable,
            text: refusal.to_string(),
        }
    }
}

/// A post a mailbox refused, as `contact collect` lists it.
#[derive(Debug, Serialize)]
pub struct RefusedPostReport {
    pub slate_id: String,
    #[serde(flatten)]
    pub refusal: MailboxRefusalReport,
}

/// A send marked stuck, as `contact collect` lists it.
#[derive(Debug, Serialize)]
pub struct StuckSendReport {
    pub tx_id: u32,
    pub slate_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stuck_at: Option<String>,
    /// Why the last post did not go, with the mailbox and its words when one refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactFailureReport {
    pub contact_id: String,
    /// `expired`, `changed-on-the-way`, `refused-already-used`, `refused-expired` or
    /// `refused-cancelled`.
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ContactReport {
    pub contact_id: String,
    pub label: String,
    pub claimed_name: Option<String>,
    pub kind: Option<&'static str>,
    pub state: String,
    /// The SAS entries as `emoji name`, four of them.
    pub sas: Vec<String>,
    /// The four SAS table indexes, in the order of `sas`; empty without a SAS.
    pub sas_indexes: Vec<u8>,
    /// `waiting`, `paired`, `verified`, `keys-changed` or `ended`.
    pub status: &'static str,
    /// When the contact was first heard in this pairing.
    pub peer_heard_at: Option<String>,
    /// When the contact's match verdict was accepted.
    pub peer_verified_at: Option<String>,
    /// The feature bits the contact claimed; 0 when none.
    pub peer_features: u32,
    /// The profile the contact told (ADR 0041), the upper half of its feature word; 0 when none.
    pub peer_profile: u32,
    /// `mismatch`, `peer-mismatch`, `unpaired` or `never-finished`, once the pairing ended.
    pub ended_reason: Option<&'static str>,
    pub ended_at: Option<String>,
    pub allow_invoices: bool,
    pub seal: String,
    pub home_relay: Option<String>,
    /// The relay host the contact asked to move to, until `contact move` applies it.
    pub requested_relay: Option<String>,
    pub lapsed: bool,
    /// When an envelope from the contact was last opened, if ever.
    pub last_heard: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactListReport {
    pub contacts: Vec<ContactReport>,
}

#[derive(Debug, Serialize)]
pub struct ContactRemoveReport {
    pub contact_id: String,
    pub removed: bool,
}

#[derive(Debug, Serialize)]
pub struct ContactSlateReport {
    /// `sealed`, `sent`, `plain`, `received`, `paid`, `finalized`, or `invoice` (an I1 shown,
    /// not paid: pass its amount to pay it).
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Where the slate or the answer was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The slate or the answer, when no file was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactCheckReport {
    pub contact_id: String,
}

/// `lepic profile show`.
#[derive(Debug, Serialize)]
pub struct ProfileShowReport {
    /// The profile this wallet tells paired contacts: the flag, `LEPIC_PROFILE`, the config file.
    pub profile: u16,
    /// The names of the bits set.
    pub names: Vec<&'static str>,
    /// The bits set that have no name, as a number.
    pub unnamed: u32,
}

/// `lepic profile set`.
#[derive(Debug, Serialize)]
pub struct ProfileSetReport {
    pub profile: u16,
    pub names: Vec<&'static str>,
    pub unnamed: u32,
    /// How many contact updates were queued.
    pub queued: u32,
    /// The profile the settings give, which later updates tell again when it differs.
    pub configured: u16,
}

/// `lepic profile domain show`.
#[derive(Debug, Serialize)]
pub struct ProfileDomainShowReport {
    /// The domain the settings give; none when unset.
    pub domain: Option<String>,
    pub network: String,
    /// This wallet's domain key on the network, 64 hex digits.
    pub domain_key: String,
}

/// `lepic profile domain file`.
#[derive(Debug, Serialize)]
pub struct ProfileDomainFileReport {
    pub path: String,
    pub bytes: usize,
    /// Where the file must be served; none when no domain is configured.
    pub url: Option<String>,
}

/// The text of the domain file, for the wallet API; the command writes it to a file.
#[derive(Debug, Serialize)]
pub struct ProfileDomainDocumentReport {
    pub document: String,
    /// Where the file must be served; none when no domain is configured.
    pub url: Option<String>,
}

/// `lepic profile domain attach`.
#[derive(Debug, Serialize)]
pub struct ProfileDomainAttachReport {
    pub domain: String,
    /// How many contact updates were queued.
    pub queued: u32,
}

#[derive(Debug, Serialize)]
pub struct ContactMoveHomeReport {
    /// The home relay moved to, `domain:port`.
    pub home_relay: String,
    /// How many contacts were told.
    pub moved: u32,
    /// When the old mailboxes stop being read, RFC 3339; absent without a drain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_until: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactKeyCheckReport {
    /// The new pairing the check went over.
    pub contact_id: String,
    pub old_contact_id: String,
}

#[derive(Debug, Serialize)]
pub struct ContactInvoiceIssueReport {
    pub contact_id: String,
    /// The user's label for the contact, else what it calls itself, in quotes.
    pub contact_name: String,
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
}

#[derive(Debug, Serialize)]
pub struct ContactInvoiceReport {
    pub slate_id: String,
    pub contact_id: String,
    /// The user's label for the contact, else what it calls itself, in quotes.
    pub contact_name: String,
    /// Whether the contact's SAS was checked.
    pub verified: bool,
    pub amount: String,
    pub purpose: Option<&'static str>,
    pub reference: Option<String>,
    /// The issuer's message, signed with the slate.
    pub message: Option<String>,
    pub received_at: String,
    /// Other requests from the same contact for the same amount within ten minutes.
    pub same_amount: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactInvoiceListReport {
    pub invoices: Vec<ContactInvoiceReport>,
}

#[derive(Debug, Serialize)]
pub struct ContactExportReport {
    pub file: String,
}

/// The contact backup document, for the wallet API; the command writes it to a file.
#[derive(Debug, Serialize)]
pub struct ContactBackupReport {
    pub backup: String,
}

#[derive(Debug, Serialize)]
pub struct ContactImportReport {
    pub imported: usize,
    pub skipped_existing: usize,
    pub skipped_conflict: usize,
}

#[derive(Debug, Serialize)]
pub struct ContactPayloadPostReport {
    pub contact_id: String,
    /// The id the other wallet keeps the payload under, 32 lowercase hex digits.
    pub payload_id: String,
    /// The other wallet's recorded features are known and do not claim app payloads; the
    /// payload was queued all the same.
    pub peer_lacks_app_payloads: bool,
}

#[derive(Debug, Serialize)]
pub struct ContactQuarantineReport {
    pub messages: Vec<QuarantinedMessageReport>,
}

#[derive(Debug, Serialize)]
pub struct QuarantinedMessageReport {
    pub id: String,
    pub contact_id: String,
    pub reason: &'static str,
    pub first_seen: String,
    pub attempts: u32,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct ContactPayloadListReport {
    pub payloads: Vec<ContactPayloadReport>,
}

#[derive(Debug, Serialize)]
pub struct ContactPayloadReport {
    pub id: String,
    pub contact_id: String,
    pub received_at: String,
    /// The bytes as lowercase hex.
    pub payload: String,
}

#[derive(Debug, Serialize)]
pub struct ContactPayloadAckReport {
    /// How many kept payloads were forgotten.
    pub acknowledged: usize,
}

/// A client of the owner TLS listener.
#[derive(Debug, Serialize)]
pub struct ApiClientReport {
    pub name: String,
    /// The SHA-256 of the client certificate's public key info, in hex.
    pub fingerprint: String,
    /// `read`, `receive` or `full`.
    pub role: &'static str,
}

/// The clients the owner TLS listener accepts, in file order.
#[derive(Debug, Serialize)]
pub struct ApiClientListReport {
    pub clients: Vec<ApiClientReport>,
}

/// What `serve` did before it was stopped.
#[derive(Debug, Serialize)]
pub struct ServeReport {
    pub socket: String,
    /// API requests answered, problems included.
    pub requests: u64,
    /// What the Epicbox listener received.
    pub inbox: InboxReport,
    /// What the HTTP listener answered; absent without `--http`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpListenReport>,
}

/// A running `serve`: facts only, which a monitor compares with its own thresholds.
#[derive(Debug, Serialize)]
pub struct ServeStatusReport {
    /// The socket the API answers on.
    pub socket: String,
    /// Seconds since serve started.
    pub uptime_s: u64,
    pub requests: RequestsReport,
    /// The Epicbox listener's connection: `connecting`, `connected`, `disconnected` or
    /// `stopped`; `null` before its first report.
    pub epicbox: Option<&'static str>,
    /// The node's tip at the wallet's last refresh that applied; `null` before the first.
    pub height: Option<u64>,
    /// The highest node tip the wallet confirmed; `null` before the first.
    pub node_tip: Option<u64>,
    pub refresh: MaintenanceReport,
    pub collect: MaintenanceReport,
    /// The HTTP listener; absent without `--http`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<ServeHttpStatus>,
    /// The owner TLS listener; absent without `--owner-tls`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_tls: Option<OwnerTlsStatus>,
}

/// The owner TLS listener of a running `serve --owner-tls`.
#[derive(Debug, Serialize)]
pub struct OwnerTlsStatus {
    /// The address it listens on, `ip:port`.
    pub address: String,
    /// The SHA-256 of the certificate's public key info, in hex, which clients pin.
    pub fingerprint: String,
}

/// The API's requests since serve started.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct RequestsReport {
    /// Requests answered, problems included.
    pub served: u64,
    /// Requests being answered now; an event stream counts while it is open.
    pub in_flight: u64,
    /// Connections closed unanswered: over the connection cap, from another user, or with a
    /// failed TLS handshake.
    pub refused: u64,
}

/// The HTTP listener of a running `serve --http`, with its counts so far.
#[derive(Debug, Serialize)]
pub struct ServeHttpStatus {
    #[serde(flatten)]
    pub listener: HttpListenReport,
    /// Who `build_coinbase` is answered to: `off`, `local` or `remote`.
    pub coinbase: &'static str,
}

/// One maintenance task of `serve`, since it started.
#[derive(Debug, Serialize)]
pub struct MaintenanceReport {
    /// Failures since the last success.
    pub consecutive_failures: u32,
    /// The error of the latest failure, kept after a success; `null` before any failure.
    pub last_error: Option<String>,
    /// `null` before the first success.
    pub last_success: Option<String>,
}

/// What `http listen`, or the HTTP listener of `serve`, did before it was stopped.
#[derive(Debug, Serialize)]
pub struct HttpListenReport {
    pub port: u16,
    /// `local` or `internet`.
    pub exposure: &'static str,
    pub received: u32,
    /// Payments answered again with the reply stored the first time.
    pub repeated: u32,
    pub refused: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TorAddressReport {
    /// `<56 characters>.onion`.
    pub onion: String,
}

/// What `tor listen` did before it was stopped.
#[derive(Debug, Serialize)]
pub struct TorListenReport {
    pub onion: String,
    /// The previous onion, when `--previous-onion` published it too.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_onion: Option<String>,
    pub received: u32,
    /// Payments answered again with the reply stored the first time.
    pub repeated: u32,
    pub refused: u32,
}

#[derive(Debug, Serialize)]
pub struct EpicboxStatusReport {
    pub relay: String,
    pub address: String,
    pub pending_deliveries: usize,
}

#[derive(Debug, Serialize)]
pub struct NodeStatusReport {
    pub node: String,
    pub node_version: String,
    pub block_header_version: u16,
    pub height: u64,
    pub last_block: String,
}

fn expose<S: Serializer>(secret: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret)
}

#[derive(Serialize)]
struct ErrorDocument<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    kind: &'a str,
    /// A finer name than `kind`: `payment_declined` for a send the payee declined.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    /// When the payee declined, with `code` `payment_declined`.
    #[serde(skip_serializing_if = "Option::is_none")]
    declined_at: Option<&'a str>,
    exit_code: u8,
    message: &'a str,
    causes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_id: Option<u32>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    recovery: &'a [String],
    /// The wait a mailbox asked for before the post goes again, in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_secs: Option<u64>,
    /// The mailbox, `host[:port]`, that refused the post, or that an epic1 link of an earlier
    /// release names.
    #[serde(skip_serializing_if = "Option::is_none")]
    mailbox: Option<String>,
}

/// The text a successful command prints. A report that carries the recovery phrase is rendered
/// into a buffer sized for it up front, so no reallocation leaves an unwiped copy behind.
fn write_contact_slate(out: &mut Vec<u8>, r: &ContactSlateReport) -> std::io::Result<()> {
    let what = match r.action {
        "sealed" => "Sealed",
        "sent" => "Queued for the contact's mailbox:",
        "received" => "Received",
        "paid" => "Paid",
        "finalized" => "Finalized and posted",
        _ => "An invoice, not paid:",
    };
    let stage = r.stage.unwrap_or("slate");
    write!(out, "{what} {stage}")?;
    if let Some(amount) = &r.amount {
        write!(out, " for {amount} EPIC")?;
    }
    if let Some(tx_id) = r.tx_id {
        write!(out, ", transaction {tx_id}")?;
    }
    if let Some(contact) = &r.contact_id {
        write!(out, ", contact {contact}")?;
    }
    writeln!(out, ".")?;
    if r.action == "invoice" {
        writeln!(
            out,
            "Pay it with `--amount <AMOUNT>` once the amount is right."
        )?;
    }
    if let Some(file) = &r.file {
        writeln!(out, "Written to {file}.")?;
    }
    if let Some(text) = &r.text {
        writeln!(out, "{text}")?;
    }
    Ok(())
}

/// ` (name, name, 0x8000)` for a profile; nothing for none.
fn profile_words(names: &[&str], unnamed: u32) -> String {
    let mut words: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    if unnamed != 0 {
        words.push(format!("{unnamed:#x}"));
    }
    if words.is_empty() {
        String::new()
    } else {
        format!(" ({})", words.join(", "))
    }
}

fn write_contact(out: &mut Vec<u8>, contact: &ContactReport) -> std::io::Result<()> {
    writeln!(
        out,
        "{}  {}  {}{}",
        contact.contact_id,
        if contact.label.is_empty() {
            "(no name)".to_owned()
        } else {
            printable(&contact.label)
        },
        contact.state,
        if contact.allow_invoices {
            ", invoices allowed"
        } else {
            ""
        }
    )?;
    if let Some(claimed) = &contact.claimed_name {
        writeln!(out, "    calls itself \"{}\"", printable(claimed))?;
    }
    if !contact.sas.is_empty() {
        writeln!(out, "    check: {}", contact.sas.join(" · "))?;
    }
    if contact.peer_profile != 0 {
        let (names, unnamed) = crate::profile::describe(contact.peer_profile);
        writeln!(
            out,
            "    profile {}{}",
            contact.peer_profile,
            profile_words(&names, unnamed)
        )?;
    }
    if let Some(host) = &contact.requested_relay {
        writeln!(out, "    asks to move to relay {}", printable(host))?;
    }
    if contact.lapsed {
        writeln!(out, "    not heard from in 90 days")?;
    }
    if let Some(heard) = &contact.last_heard {
        writeln!(out, "    last heard {heard}")?;
    }
    Ok(())
}

pub fn render(report: &Report, format: OutputFormat) -> Zeroizing<String> {
    let mut out = Zeroizing::new(Vec::with_capacity(rendered_len_bound(report)));
    match format {
        OutputFormat::Json => {
            // Serializing these plain structs cannot fail; an empty object keeps the
            // one-document rule.
            if serde_json::to_writer(&mut *out, report).is_err() {
                out.clear();
                out.extend_from_slice(b"{}");
            }
            out.push(b'\n');
        }
        OutputFormat::Human => {
            // Writing to a Vec cannot fail.
            let _ = write_human(&mut out, report);
        }
    }
    let bytes = std::mem::take(&mut *out);
    // Both renderers write only UTF-8; the fallback wipes the bytes it drops.
    Zeroizing::new(String::from_utf8(bytes).unwrap_or_else(|error| {
        drop(Zeroizing::new(error.into_bytes()));
        String::new()
    }))
}

/// At least as long as anything `render` writes for an init report in either format: JSON may
/// escape a byte as `\u00XX`, and the fixed text of both formats is shorter than the margin.
/// Other reports carry no secret and start empty.
fn rendered_len_bound(report: &Report) -> usize {
    const FIXED_TEXT: usize = 512;
    const ESCAPED_BYTE: usize = 6;
    match report {
        Report::Init(r) => [r.network.len(), r.data_dir.len(), r.recovery_phrase.len()]
            .iter()
            .fold(FIXED_TEXT, |total, len| {
                total.saturating_add(len.saturating_mul(ESCAPED_BYTE))
            }),
        _ => 0,
    }
}

/// The text a failed command prints: on stdout as JSON, or on stderr for people, with the hint
/// on a line of its own.
pub fn render_error(error: &CliError, format: OutputFormat, hint: Option<&str>) -> String {
    let chain = error.chain();
    let kind = error.kind();
    match format {
        OutputFormat::Json => {
            let (message, causes) = chain
                .split_first()
                .map_or(("", &[][..]), |(m, c)| (m.as_str(), c));
            json_line(&ErrorDocument {
                error: ErrorBody {
                    kind: kind.name(),
                    code: error.code(),
                    declined_at: error.declined_at(),
                    exit_code: kind.exit_code(),
                    message,
                    causes,
                    tx_id: error.tx_id(),
                    recovery: &crate::hint::recovery(error),
                    retry_after_secs: error.retry_after_secs(),
                    mailbox: error.mailbox(),
                },
            })
        }
        OutputFormat::Human => {
            let mut text = format!("error: {}\n", chain.join(": "));
            if let Some(hint) = hint {
                let _ = writeln!(text, "hint: {hint}");
            }
            let _ = writeln!(text, "exit code {} ({})", kind.exit_code(), kind.name());
            text
        }
    }
}

fn json_line(value: &impl Serialize) -> String {
    // Serializing these plain structs cannot fail; an empty object keeps the one-document rule.
    let mut text = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    text
}

/// A peer's text with control characters escaped, so it cannot move the cursor, clear the
/// screen or forge further lines of the view.
pub(crate) fn printable(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            shown.extend(c.escape_default());
        } else {
            shown.push(c);
        }
    }
    shown
}

/// What a transaction moved for the wallet, without the fee: credited minus debited, with the
/// fee given back for an outgoing one, whose debit includes it. Negative when sent.
fn net_amount(tx: &TxReport) -> String {
    let units = |text: &str| match parse_amount(text) {
        Ok(amount) => Some(i128::from(amount.value())),
        Err(AmountError::Zero) => Some(0),
        Err(_) => None,
    };
    let fee = match (tx.direction.as_str(), tx.fee.as_deref()) {
        ("outgoing", Some(fee)) => units(fee),
        _ => Some(0),
    };
    let net = units(&tx.amount_credited)
        .zip(units(&tx.amount_debited))
        .zip(fee)
        .and_then(|((credited, debited), fee)| credited.checked_sub(debited)?.checked_add(fee));
    match net.map(|net| (net < 0, u64::try_from(net.unsigned_abs()))) {
        Some((negative, Ok(units))) => {
            format!("{}{}", if negative { "-" } else { "" }, format_units(units))
        }
        _ => "-".to_owned(),
    }
}

/// `2026-10-03T11:24:52.099175357Z` reads `2026-10-03 11:24:52`.
pub(crate) fn short_time(timestamp: &str) -> String {
    timestamp
        .get(..19)
        .map_or_else(|| timestamp.to_owned(), |text| text.replacen('T', " ", 1))
}

/// The lines of an inbox report that say what the invoice expiry did, if anything.
fn write_expired(out: &mut Vec<u8>, expired: Option<&ExpiredReport>) -> std::io::Result<()> {
    let Some(expired) = expired else {
        return writeln!(out, "Invoice expiry did not run; the log says why.");
    };
    if !expired.deleted.is_empty() {
        writeln!(
            out,
            "Deleted {} parked invoices that were not paid in time.",
            expired.deleted.len()
        )?;
    }
    for tx_id in &expired.cancelled {
        writeln!(
            out,
            "Transaction {tx_id} cancelled; its invoice was not paid in time."
        )?;
    }
    for tx_id in &expired.cancellable {
        writeln!(
            out,
            "Transaction {tx_id} paid an invoice that was not posted in time; `lepic tx cancel \
             {tx_id}` gives up on it."
        )?;
    }
    Ok(())
}

fn write_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Init(_)
        | Report::Restore(_)
        | Report::Scan(_)
        | Report::Info(_)
        | Report::Address(_)
        | Report::Outputs(_)
        | Report::Consolidate(_)
        | Report::Password(_)
        | Report::Backup(_)
        | Report::ImportHistory(_)
        | Report::NodeStatus(_) => write_wallet_human(out, report),
        Report::Send(_)
        | Report::Resend(_)
        | Report::Receive(_)
        | Report::SlateReceive(_)
        | Report::Finalize(_)
        | Report::Post(_)
        | Report::Cancel(_)
        | Report::Recover(_)
        | Report::List(_)
        | Report::Show(_) => write_transaction_human(out, report),
        Report::InvoiceIssue(_)
        | Report::InvoicePay(_)
        | Report::InvoiceList(_)
        | Report::InvoiceDecline(_) => write_invoice_human(out, report),
        Report::Inbox(_)
        | Report::Serve(_)
        | Report::ServeStatus(_)
        | Report::HttpListen(_)
        | Report::TorAddress(_)
        | Report::TorListen(_)
        | Report::EpicboxStatus(_) => write_transport_human(out, report),
        Report::ContactInvite(_)
        | Report::ContactPreview(_)
        | Report::ContactAccept(_)
        | Report::ContactLink(_)
        | Report::ContactCollect(_) => write_pairing_human(out, report),
        Report::ContactBackup(r) => writeln!(out, "{}", r.backup),
        Report::Contact(_)
        | Report::ContactList(_)
        | Report::ContactRemove(_)
        | Report::ContactSlate(_)
        | Report::ContactKeyCheck(_)
        | Report::ContactCheck(_)
        | Report::ContactMoveHome(_)
        | Report::ProfileShow(_)
        | Report::ProfileSet(_)
        | Report::ProfileDomainShow(_)
        | Report::ProfileDomainFile(_)
        | Report::ProfileDomainDocument(_)
        | Report::ProfileDomainAttach(_)
        | Report::ContactInvoiceIssue(_)
        | Report::ContactInvoices(_)
        | Report::ContactExport(_)
        | Report::ContactImport(_)
        | Report::ContactPayloadPost(_)
        | Report::ContactPayloadList(_)
        | Report::ContactPayloadAck(_)
        | Report::ContactQuarantine(_) => write_contact_human(out, report),
        Report::InPersonCode(_)
        | Report::InPersonRead(_)
        | Report::InPersonPaid(_)
        | Report::InPersonPost(_)
        | Report::InPersonTaken(_)
        | Report::InPersonAnswers(_) => write_in_person_human(out, report),
        Report::Epic1Address(_)
        | Report::Epic1Link(_)
        | Report::Epic1Read(_)
        | Report::Epic1Paid(_)
        | Report::Epic1Answers(_)
        | Report::Epic1Restore(_)
        | Report::EpictxOpen(_) => epic1::write_epic1_human(out, report),
        Report::MailboxList(_)
        | Report::MailboxAdd(_)
        | Report::MailboxRemove(_)
        | Report::MailboxProbe(_) => mailbox::write_mailbox_human(out, report),
        Report::ApiClientAdd(r) => writeln!(
            out,
            "Client {} added with role {}: {}",
            r.name, r.role, r.fingerprint
        ),
        Report::ApiClientRemove(r) => writeln!(out, "Client {} removed.", r.name),
        Report::ApiClientList(r) if r.clients.is_empty() => writeln!(out, "No clients."),
        Report::ApiClientList(r) => r.clients.iter().try_for_each(|client| {
            writeln!(
                out,
                "{}  {}  {}",
                client.name, client.fingerprint, client.role
            )
        }),
    }
}

/// A consolidation, made, repeated or only estimated.
fn write_consolidate(out: &mut Vec<u8>, r: &ConsolidateReport) -> std::io::Result<()> {
    let tx_id = r.tx_id.map_or_else(String::new, |tx_id| tx_id.to_string());
    if r.repeated {
        return writeln!(
            out,
            "This consolidation was made before as transaction {tx_id}; nothing was spent again."
        );
    }
    let (spends, makes, stored) = if r.dry_run {
        (
            "A consolidation would spend".to_owned(),
            "make",
            " Nothing was stored.",
        )
    } else {
        (format!("Transaction {tx_id} spends"), "makes", "")
    };
    writeln!(
        out,
        "{spends} {} outputs of {} EPIC in total, for a fee of {} EPIC, and {makes} {} outputs: \
         {} EPIC.{stored}",
        r.inputs.len(),
        r.total,
        r.fee.as_deref().unwrap_or("0"),
        r.outputs.len(),
        r.outputs.join(", ")
    )?;
    if let (Some(smallest), Some(largest)) = (&r.smallest, &r.largest) {
        writeln!(
            out,
            "Smallest output spent {smallest} EPIC, largest {largest} EPIC."
        )?;
    }
    Ok(())
}

/// A wallet, scan or node report. Writes nothing for any other.
#[allow(clippy::too_many_lines)] // One arm per report it writes.
fn write_wallet_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Init(r) => {
            writeln!(out, "Wallet created on {} in {}.", r.network, r.data_dir)?;
            writeln!(
                out,
                "Write down the recovery phrase. It is not shown again:\n"
            )?;
            writeln!(out, "    {}\n", r.recovery_phrase.as_str())?;
            writeln!(
                out,
                "To receive, give the sender the address `lepic wallet address` prints, or\nanswer their slate file with `lepic tx receive <FILE>`."
            )
        }
        Report::Restore(r) => {
            writeln!(out, "Wallet restored on {} in {}.", r.network, r.data_dir)?;
            match &r.scan {
                Some(scan) => writeln!(
                    out,
                    "Scanned heights {} to {}: {} outputs found, {} restored.",
                    scan.start_height, scan.end_height, scan.found, scan.restored
                ),
                None => writeln!(out, "Chain not scanned."),
            }
        }
        Report::Scan(r) => {
            if r.resumed {
                writeln!(out, "Continued an interrupted scan.")?;
            }
            write!(
                out,
                "Scanned heights {} to {}: {} outputs found, {} restored, {} revived",
                r.start_height, r.end_height, r.found, r.restored, r.revived
            )?;
            if r.delete_unconfirmed {
                write!(out, ", {} unlocked, {} deleted", r.unlocked, r.deleted)?;
            }
            writeln!(out, ".")
        }
        Report::Info(r) => {
            writeln!(out, "Network {}, chain height {}.", r.network, r.height)?;
            if let Some(node_height) = r.node_height {
                writeln!(
                    out,
                    "Catching up to the node's tip {node_height}; balances are at height {}. \
                     Run `lepic wallet info` again.",
                    r.height
                )?;
            }
            if r.node_behind {
                writeln!(
                    out,
                    "The node is behind the last refresh; balances not updated. If the node is \
                     synced,\n`lepic wallet scan --reset-chain` recovers the wallet."
                )?;
            }
            for account in &r.accounts {
                writeln!(out, "\nAccount {} ({})", account.label, account.index)?;
                let rows = [
                    ("Total", &account.total),
                    ("Spendable", &account.spendable),
                    ("Awaiting confirmation", &account.awaiting_confirmation),
                    ("Awaiting finalization", &account.awaiting_finalization),
                    ("Immature", &account.immature),
                    ("Locked", &account.locked),
                ];
                for (name, value) in rows {
                    writeln!(out, "  {name:<22} {}", value.as_deref().unwrap_or("-"))?;
                }
            }
            Ok(())
        }
        Report::Address(r) => writeln!(out, "{}", r.address),
        Report::Outputs(r) => write_outputs(out, r),
        Report::Consolidate(r) => write_consolidate(out, r),
        Report::Password(_) => writeln!(out, "Wallet password changed."),
        Report::Backup(r) => {
            writeln!(
                out,
                "Wallet backup written to {}; it opens with the wallet password.",
                printable(&r.dir)
            )?;
            for file in &r.files {
                writeln!(out, "  {}", printable(file))?;
            }
            Ok(())
        }
        Report::ImportHistory(r) => {
            writeln!(out, "History import: {}.", r.status)?;
            writeln!(
                out,
                "{} transactions, {} outputs, {} accounts named, {} found outputs linked, {} \
                 skipped, {} confirmed by kernel, {} dated by block.",
                r.transactions,
                r.outputs,
                r.accounts_named,
                r.linked,
                r.skipped,
                r.confirmed_by_kernel,
                r.dated
            )
        }
        Report::NodeStatus(r) => {
            writeln!(out, "Node     {} (version {})", r.node, r.node_version)?;
            writeln!(out, "Height   {}", r.height)?;
            writeln!(out, "Block    {}", r.last_block)?;
            writeln!(out, "Header   version {}", r.block_header_version)
        }
        _ => Ok(()),
    }
}

/// A report on one transaction or the transaction list. Writes nothing for any other.
#[allow(clippy::too_many_lines)] // One arm per report it writes.
fn write_transaction_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Send(r) if r.repeated && !r.delivered => writeln!(
            out,
            "Transaction {} was made before under slate {} and is {}; nothing was sent now. It \
             is not delivered yet: run `lepic tx resend {}`.",
            r.tx_id, r.slate_id, r.state, r.tx_id
        ),
        Report::Send(r) if r.repeated => writeln!(
            out,
            "Transaction {} was made before under slate {} and is {}; nothing was sent now.",
            r.tx_id, r.slate_id, r.state
        ),
        Report::Send(r) if !r.delivered => {
            writeln!(
                out,
                "Transaction {} is stored for {} EPIC (fee {}) to {}, but no mailbox took it \
                 yet.\nSlate {}.",
                r.tx_id, r.amount, r.fee, r.destination, r.slate_id
            )?;
            if let Some(reason) = &r.reason {
                writeln!(out, "Last attempt: {reason}")?;
            }
            if let Some(next) = &r.next_attempt_at {
                writeln!(out, "The outbox posts it again at {next}.")?;
            }
            writeln!(
                out,
                "To drop it instead, run `lepic tx cancel {}`.",
                r.tx_id
            )
        }
        Report::Send(r) if r.state == "posted" => writeln!(
            out,
            "Transaction {} sent {} EPIC (fee {}) by {} to {}, finalized and posted.\nSlate {}.",
            r.tx_id, r.amount, r.fee, r.transport, r.destination, r.slate_id
        ),
        Report::Send(r) => writeln!(
            out,
            "Transaction {} sent {} EPIC (fee {}) by {} to {}.\nSlate {}.",
            r.tx_id, r.amount, r.fee, r.transport, r.destination, r.slate_id
        ),
        Report::Resend(r) if r.state == "posted" => writeln!(
            out,
            "Transaction {} sent again by {} to {}, finalized and posted.",
            r.tx_id, r.transport, r.destination
        ),
        Report::Resend(r) => writeln!(
            out,
            "Transaction {} sent again by {} to {}.",
            r.tx_id, r.transport, r.destination
        ),
        Report::Receive(r) if r.repeated => writeln!(
            out,
            "Transaction {} received this slate before; its reply is written again. Return {} \
             to the sender.\nSlate {}.",
            r.tx_id, r.reply_file, r.slate_id
        ),
        Report::Receive(r) => writeln!(
            out,
            "Transaction {} receives {} EPIC. Return {} to the sender.\nSlate {}.",
            r.tx_id, r.amount, r.reply_file, r.slate_id
        ),
        Report::Finalize(r) => writeln!(
            out,
            "Transaction {} finalized and {}.\nSlate {}.",
            r.tx_id, r.state, r.slate_id
        ),
        Report::Post(r) => match r.height {
            Some(height) if r.already_on_chain => writeln!(
                out,
                "Transaction {} is {}; its kernel is already on chain at height {height}.",
                r.tx_id, r.state
            ),
            _ => writeln!(out, "Transaction {} is {}.", r.tx_id, r.state),
        },
        Report::Cancel(r) => write_cancel(out, r),
        Report::Recover(r) if r.state == recovery_state_name(RecoveryState::Uncertain) => writeln!(
            out,
            "The recovery of transaction {} is stored as transaction {}; the node could not be \
             reached, and each refresh posts it again.",
            r.tx_id, r.recovery_tx_id
        ),
        Report::Recover(r) if r.state == recovery_state_name(RecoveryState::Confirming) => {
            writeln!(
                out,
                "The recovery of transaction {} is transaction {}, which the node already holds; \
                 it is confirming. Once it is confirmed, transaction {} can never be mined; pay \
                 again only after that.",
                r.tx_id, r.recovery_tx_id, r.tx_id
            )
        }
        Report::Recover(r) => writeln!(
            out,
            "The recovery of transaction {} is posted as transaction {}. Once it is confirmed, \
             transaction {} can never be mined; pay again only after that.",
            r.tx_id, r.recovery_tx_id, r.tx_id
        ),
        Report::List(r) => write_list(out, r),
        Report::Show(tx) => write_show(out, tx),
        _ => Ok(()),
    }
}

/// The outputs of an account, one row per output.
fn write_outputs(out: &mut Vec<u8>, r: &OutputsReport) -> std::io::Result<()> {
    if r.outputs.is_empty() {
        return writeln!(out, "No outputs in account {}.", r.account);
    }
    writeln!(
        out,
        "{:<66}  {:>20}  {:<11}  {:<21}  {:>9}  {:>7}  {:>5}",
        "COMMITMENT", "VALUE", "STATUS", "CATEGORY", "HEIGHT", "CONFS", "TX"
    )?;
    for output in &r.outputs {
        let tx = output
            .tx_id
            .map_or_else(|| "-".to_owned(), |id| id.to_string());
        let coinbase = if output.is_coinbase { " coinbase" } else { "" };
        writeln!(
            out,
            "{:<66}  {:>20}  {:<11}  {:<21}  {:>9}  {:>7}  {:>5}{coinbase}",
            output.commitment,
            output.value,
            output.status,
            output.category.unwrap_or("-"),
            output.height,
            output.confirmations,
            tx
        )?;
    }
    Ok(())
}

/// The transaction list of an account, one row per transaction.
/// `tx cancel`: the local state, then what the Epicbox relay said when it was asked.
fn write_cancel(out: &mut Vec<u8>, r: &CancelReport) -> std::io::Result<()> {
    writeln!(out, "Transaction {} is {}.", r.tx_id, r.state)?;
    match r.relay.as_deref() {
        None => Ok(()),
        Some("cancelled") => writeln!(
            out,
            "The epicbox relay cancelled it for the other party too."
        ),
        Some("not_found_or_not_participant") => writeln!(
            out,
            "The epicbox relay did not cancel it: it does not know the transaction, or this \
             wallet is not one of its parties."
        ),
        Some("no_relay_id") => writeln!(
            out,
            "It was never filed on an epicbox relay under an id, so only this wallet cancelled \
             it."
        ),
        Some("failed") => writeln!(
            out,
            "Asking the epicbox relay to cancel it failed ({}), so only this wallet cancelled it.",
            r.relay_error.as_deref().unwrap_or("no reason given")
        ),
        Some(_) => writeln!(
            out,
            "The epicbox relay cannot cancel transactions, so only this wallet cancelled it."
        ),
    }
}

fn write_list(out: &mut Vec<u8>, r: &TxListReport) -> std::io::Result<()> {
    if r.transactions.is_empty() {
        return writeln!(out, "No transactions in account {}.", r.account);
    }
    writeln!(
        out,
        "{:>5}  {:<8}  {:<9}  {:>20}  {:>11}  {:<9}  CREATED (UTC)",
        "ID", "DIR", "STATE", "AMOUNT", "FEE", "TRANSPORT"
    )?;
    for tx in &r.transactions {
        writeln!(
            out,
            "{:>5}  {:<8}  {:<9}  {:>20}  {:>11}  {:<9}  {}",
            tx.tx_id,
            tx.direction,
            tx.state,
            net_amount(tx),
            tx.fee.as_deref().unwrap_or("-"),
            tx.transport.as_deref().unwrap_or("-"),
            short_time(&tx.created_at)
        )?;
    }
    Ok(())
}

/// One transaction with every field the report holds.
fn write_show(out: &mut Vec<u8>, tx: &TxReport) -> std::io::Result<()> {
    let rows = [
        ("Transaction", tx.tx_id.to_string()),
        ("Direction", tx.direction.clone()),
        ("State", tx.state.clone()),
        ("Credited", tx.amount_credited.clone()),
        ("Debited", tx.amount_debited.clone()),
        ("Fee", tx.fee.clone().unwrap_or_else(|| "-".to_owned())),
        (
            "Slate",
            tx.slate_id.clone().unwrap_or_else(|| "-".to_owned()),
        ),
        (
            "Transport",
            tx.transport.clone().unwrap_or_else(|| "-".to_owned()),
        ),
        ("Created", tx.created_at.clone()),
        ("Updated", tx.updated_at.clone()),
        (
            "Stages",
            tx.stages
                .as_ref()
                .map_or_else(String::new, |stages| stages.join(" ")),
        ),
        (
            "Kernel",
            tx.kernel_excess.clone().unwrap_or_else(|| "-".to_owned()),
        ),
        (
            "Confirmed at",
            tx.confirmed_height
                .map_or_else(|| "-".to_owned(), |height| height.to_string()),
        ),
    ];
    for (name, value) in rows {
        writeln!(out, "{name:<12} {value}")?;
    }
    if let Some(at) = &tx.sender_reported_posted_at {
        writeln!(out, "{:<12} posted at {at}", "Sender says")?;
    }
    if let Some(at) = &tx.sender_reported_cancelled_at {
        writeln!(out, "{:<12} cancelled at {at}", "Sender says")?;
    }
    if let Some(at) = &tx.receiver_declined_at {
        writeln!(out, "{:<12} declined at {at}", "Receiver")?;
    }
    if let Some(at) = &tx.payer_declined_at {
        // The way out is shown only while the invoice still waits for payment.
        if tx.state == "received" {
            writeln!(
                out,
                "{:<12} declined by the payer at {at}; cancel it with `lepic tx cancel {}`",
                "Payer", tx.tx_id
            )?;
        } else {
            writeln!(out, "{:<12} declined by the payer at {at}", "Payer")?;
        }
    }
    if let Some(origin) = &tx.origin {
        writeln!(out, "{:<12} {origin}", "Origin")?;
    }
    if let Some(recovery) = &tx.recovery {
        write_recovery(out, recovery)?;
    }
    if let Some(delivery) = &tx.delivery {
        write_delivery(out, tx.tx_id, delivery)?;
    }
    if tx.coinbase == Some(true) {
        writeln!(out, "{:<12} mining reward", "Kind")?;
    }
    if let Some(imported) = &tx.imported {
        writeln!(
            out,
            "{:<12} old id {}, {}, {} in, {} out, chain {}",
            "Imported",
            imported.source_id,
            imported.kind,
            imported.input_count,
            imported.output_count,
            imported.check
        )?;
    }
    match tx.messages.as_deref() {
        Some(messages) if !messages.is_empty() => {
            for message in messages {
                let text = printable(&message.text);
                writeln!(out, "{:<12} {}: {text}", "Message", message.role)?;
            }
        }
        _ => writeln!(out, "{:<12} -", "Message")?,
    }
    Ok(())
}

/// The `Recovery` row of `tx show`.
/// The delivery lines of `tx show`: nothing took the send yet, and the way out.
fn write_delivery(
    out: &mut Vec<u8>,
    tx_id: u32,
    delivery: &TxDeliveryReport,
) -> std::io::Result<()> {
    let label = "Delivery";
    if delivery.stuck {
        writeln!(
            out,
            "{label:<12} stuck: no mailbox took it in a long time; the outbox keeps trying, or \
             drop it with `lepic tx cancel {tx_id}`"
        )?;
    } else {
        writeln!(
            out,
            "{label:<12} not delivered yet, {} attempts",
            delivery.attempts
        )?;
    }
    if let Some(reason) = &delivery.reason {
        writeln!(out, "{:<12} {reason}", "Last attempt")?;
    }
    if let Some(next) = &delivery.next_attempt_at {
        writeln!(out, "{:<12} {next}", "Next attempt")?;
    }
    Ok(())
}

fn write_recovery(out: &mut Vec<u8>, recovery: &TxRecoveryReport) -> std::io::Result<()> {
    write!(
        out,
        "{:<12} transaction {}, {}",
        "Recovery", recovery.tx_id, recovery.state
    )?;
    if recovery.state == recovery_state_name(RecoveryState::Confirming) {
        write!(
            out,
            ", {} of {} confirmations",
            recovery.confirmations, recovery.needed
        )?;
    }
    match &recovery.error {
        Some(error) => writeln!(out, ": {error}"),
        None => writeln!(out),
    }
}

/// An invoice report. Writes nothing for any other.
fn write_invoice_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::InvoiceIssue(r) => match &r.file {
            Some(file) => writeln!(
                out,
                "Transaction {} asks for {} EPIC. Give {file} to the payer.\nSlate {}.",
                r.tx_id, r.amount, r.slate_id
            ),
            None => writeln!(
                out,
                "Transaction {} asks for {} EPIC; the invoice went by {} to {}.\nSlate {}.",
                r.tx_id, r.amount, r.transport, r.destination, r.slate_id
            ),
        },
        Report::InvoicePay(r) => match &r.reply_file {
            Some(reply) => writeln!(
                out,
                "Transaction {} pays {} EPIC (fee {}). Return {reply} to the issuer.\nSlate {}.",
                r.tx_id, r.amount, r.fee, r.slate_id
            ),
            None => writeln!(
                out,
                "Transaction {} pays {} EPIC (fee {}); the payment went by {} to {}.\nSlate {}.",
                r.tx_id, r.amount, r.fee, r.transport, r.destination, r.slate_id
            ),
        },
        Report::InvoiceList(r) => {
            if r.invoices.is_empty() {
                return writeln!(
                    out,
                    "No invoices are waiting; requests from paired contacts arrive with \
                     `lepic contact collect` and wait in `lepic contact invoices`."
                );
            }
            for invoice in &r.invoices {
                writeln!(
                    out,
                    "{}  {} EPIC from {}",
                    invoice.slate_id, invoice.amount, invoice.sender
                )?;
                writeln!(
                    out,
                    "    received {}, expires {} (UTC)",
                    short_time(&invoice.received_at),
                    short_time(&invoice.expires_at)
                )?;
                if let Some(message) = &invoice.message {
                    writeln!(out, "    message: {}", printable(message))?;
                }
            }
            Ok(())
        }
        Report::InvoiceDecline(r) => {
            writeln!(
                out,
                "Invoice {} is {}; it is not paid.",
                r.slate_id, r.state
            )
        }
        _ => Ok(()),
    }
}

fn write_http_counts(out: &mut Vec<u8>, r: &HttpListenReport) -> std::io::Result<()> {
    writeln!(
        out,
        "Listened on port {} ({}): received {}, repeated {}, refused {}.",
        r.port, r.exposure, r.received, r.repeated, r.refused
    )
}

/// An inbox, listener, Tor or Epicbox report. Writes nothing for any other.
fn write_transport_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Inbox(r) => write_inbox(out, r),
        Report::Serve(r) => {
            writeln!(out, "Served {} requests on {}.", r.requests, r.socket)?;
            if let Some(http) = &r.http {
                write_http_counts(out, http)?;
            }
            write_inbox(out, &r.inbox)
        }
        Report::HttpListen(r) => write_http_counts(out, r),
        Report::TorAddress(r) => writeln!(out, "{}", r.onion),
        Report::TorListen(r) => {
            let at = match &r.previous_onion {
                Some(previous) => format!("{} and {previous}", r.onion),
                None => r.onion.clone(),
            };
            writeln!(
                out,
                "Listened at {at} over Tor: received {}, repeated {}, refused {}.",
                r.received, r.repeated, r.refused
            )
        }
        Report::EpicboxStatus(r) => {
            writeln!(out, "Relay    {}", r.relay)?;
            writeln!(out, "Address  {}", r.address)?;
            writeln!(out, "Pending  {} deliveries", r.pending_deliveries)
        }
        _ => Ok(()),
    }
}

fn write_inbox(out: &mut Vec<u8>, r: &InboxReport) -> std::io::Result<()> {
    writeln!(
        out,
        "Received {}, finalized {}, repeated {}, rejected {}, held for retry {}, dropped {}, \
         notices {}.",
        r.received, r.finalized, r.repeated, r.rejected, r.held, r.dropped, r.notices
    )?;
    if r.buffered > 0 {
        writeln!(out, "{} early notices kept.", r.buffered)?;
    }
    write_expired(out, r.expired.as_ref())
}

/// A pairing report. Writes nothing for any other.
#[allow(clippy::too_many_lines)] // One arm per report it writes.
fn write_pairing_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::ContactInvite(r) => {
            writeln!(out, "Share this invite: {}", r.link)?;
            writeln!(
                out,
                "It expires at {}. Contact {}.",
                short_time(&r.expires_at),
                r.contact_id
            )
        }
        Report::ContactPreview(r) => writeln!(
            out,
            "Pair with {} ({}, as it calls itself)? Its pairing lives on {}; the invite expires at {}.",
            printable(&r.claimed_name),
            r.kind,
            r.home_relay,
            short_time(&r.expires_at)
        ),
        Report::ContactAccept(r) if r.posted => writeln!(
            out,
            "Answered as contact {}; `lepic contact collect` takes the confirm.",
            r.contact_id
        ),
        Report::ContactAccept(r) => writeln!(
            out,
            "Answered as contact {}; send this back by hand: {}",
            r.contact_id, r.reply_link
        ),
        Report::ContactLink(r) => match (r.outcome, &r.link) {
            ("confirm", Some(link)) => writeln!(out, "Paired; send this back by hand: {link}"),
            ("paired", _) => writeln!(out, "Paired; compare the SAS with `lepic contact list`."),
            ("invite", Some(link)) => writeln!(
                out,
                "Found the invite: {link}\nAnswer it with `lepic contact accept <LINK>`."
            ),
            _ => writeln!(out, "The link answers nothing this wallet waits for."),
        },
        Report::ContactCollect(r) => {
            writeln!(
                out,
                "Collected {} messages from {} mailboxes; {} paired, {} sent.",
                r.messages, r.mailboxes, r.paired, r.delivered
            )?;
            for (count, what) in [
                (r.capped, "stopped at the message limit"),
                (r.kept, "kept a message for later"),
                (r.not_reached, "were not reached"),
                (r.replaced, "are read by another socket of this wallet"),
            ] {
                if count > 0 {
                    writeln!(out, "{count} mailboxes {what}.")?;
                }
            }
            if r.buffered > 0 {
                writeln!(out, "{} early notices kept.", r.buffered)?;
            }
            if r.epic1 > 0 {
                writeln!(out, "{} epic1 payments taken or finalized.", r.epic1)?;
            }
            if r.quarantined > 0 {
                writeln!(out, "{} messages quarantined.", r.quarantined)?;
            }
            if r.quarantine_dropped > 0 {
                writeln!(
                    out,
                    "{} messages dropped from quarantine.",
                    r.quarantine_dropped
                )?;
            }
            for stuck in &r.stuck {
                write!(
                    out,
                    "Transaction {} is stuck: no mailbox took it in a long time.",
                    stuck.tx_id
                )?;
                if let Some(reason) = &stuck.reason {
                    write!(out, " Last attempt: {reason}.")?;
                }
                writeln!(
                    out,
                    " The outbox keeps trying; drop it with `lepic tx cancel {}`.",
                    stuck.tx_id
                )?;
            }
            for refused in &r.refused {
                writeln!(
                    out,
                    "Payment {}: {}{}.",
                    refused.slate_id,
                    refused.refusal.text,
                    if refused.refusal.retryable {
                        "; the outbox posts it again"
                    } else {
                        ""
                    }
                )?;
            }
            for failed in &r.failed {
                let why = match failed.reason {
                    "expired" => "it expired",
                    "changed-on-the-way" => "the invite was changed on the way",
                    "refused-already-used" => "the invite was already used",
                    "refused-expired" => "the invite had expired",
                    _ => "the inviter cancelled it",
                };
                writeln!(out, "Pairing {} ended: {why}.", failed.contact_id)?;
            }
            for relay in &r.unreachable {
                if r.no_mux.contains(relay) {
                    writeln!(out, "{relay} does not offer mux/1, so it is not read.")?;
                } else {
                    writeln!(out, "{relay} isn't answering.")?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn write_profile(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::ProfileShow(r) => {
            writeln!(
                out,
                "Profile {}{}",
                r.profile,
                profile_words(&r.names, r.unnamed)
            )
        }
        Report::ProfileSet(r) => {
            writeln!(
                out,
                "Profile {}{} queued for {} contact(s); `lepic contact collect` sends them.",
                r.profile,
                profile_words(&r.names, r.unnamed),
                r.queued
            )?;
            if r.configured != r.profile {
                writeln!(
                    out,
                    "The settings give {}; later updates tell that again unless you set `profile` too.",
                    r.configured
                )?;
            }
            Ok(())
        }
        Report::ProfileDomainShow(r) => {
            writeln!(out, "Domain {}", r.domain.as_deref().unwrap_or("none"))?;
            writeln!(out, "Network {}", r.network)?;
            writeln!(out, "Domain key {}", r.domain_key)?;
            writeln!(
                out,
                "{{\"{}\":{{\"domain_keys\":[\"{}\"]}}}}",
                r.network, r.domain_key
            )
        }
        Report::ProfileDomainDocument(r) => writeln!(out, "{}", r.document),
        Report::ProfileDomainFile(r) => {
            writeln!(out, "Wrote {} ({} bytes).", r.path, r.bytes)?;
            match &r.url {
                Some(url) => writeln!(out, "Serve it at {url}, over HTTPS with no redirect."),
                None => writeln!(
                    out,
                    "The domain is not configured; set `domain` to see where to serve it."
                ),
            }
        }
        Report::ProfileDomainAttach(r) => writeln!(
            out,
            "{} contact updates queued for {}; `lepic contact collect` takes the answers.",
            r.queued, r.domain
        ),
        _ => Ok(()),
    }
}

/// The line `lepic contact move-home` prints: where the home went, and until when the old
/// mailboxes are read.
fn write_move_home(out: &mut Vec<u8>, r: &ContactMoveHomeReport) -> std::io::Result<()> {
    match &r.drain_until {
        Some(until) => writeln!(
            out,
            "Home relay moved to {}; {} contact(s) told. The old mailboxes are read until {until}.",
            r.home_relay, r.moved
        ),
        None => writeln!(
            out,
            "Home relay moved to {}; {} contact(s) told. The old mailboxes are not read again.",
            r.home_relay, r.moved
        ),
    }
}

/// An in-person report. Writes nothing for any other.
fn write_in_person_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::InPersonCode(r) => {
            match (&r.code, &r.file) {
                (_, Some(file)) => writeln!(out, "Code {} written to {file}.", r.slate_id)?,
                (Some(code), None) => writeln!(out, "Code {}: {code}", r.slate_id)?,
                (None, None) => {}
            }
            match &r.mailbox {
                Some(mailbox) => writeln!(
                    out,
                    "Answers come to {mailbox} until block {}; `lepic contact collect` takes them.",
                    r.ttl_cutoff
                ),
                None => writeln!(
                    out,
                    "Answers come back by hand until block {}: `lepic in-person take`.",
                    r.ttl_cutoff
                ),
            }
        }
        Report::InPersonRead(r) => write_in_person_read(out, r),
        Report::InPersonPaid(r) => {
            match (&r.envelope, &r.file) {
                (_, Some(file)) => writeln!(out, "Answer written to {file}.")?,
                (Some(envelope), None) => writeln!(out, "Answer: {envelope}")?,
                (None, None) => {}
            }
            if let Some(domain) = &r.domain {
                write_in_person_domain(out, domain)?;
            }
            writeln!(out, "Transaction {}.", r.tx_id)
        }
        Report::InPersonPost(r) => write_in_person_post(out, r),
        Report::InPersonTaken(r) if r.duplicate => writeln!(
            out,
            "Answer {} to {} was taken before.",
            r.answer, r.slate_id
        ),
        Report::InPersonTaken(r) => writeln!(
            out,
            "Answer {} to {}, check code {}{}.",
            r.answer,
            r.slate_id,
            r.check_code,
            if r.same_code {
                ", the same as an earlier answer"
            } else {
                ""
            }
        ),
        Report::InPersonAnswers(r) => {
            writeln!(
                out,
                "Code {} ({}), {} until block {}.",
                r.slate_id,
                r.stage,
                if r.closed { "closed" } else { "open" },
                r.ttl_cutoff
            )?;
            if r.answers.is_empty() {
                return writeln!(out, "No answers.");
            }
            r.answers.iter().try_for_each(|answer| {
                writeln!(
                    out,
                    "{}  {}  {}{}{}",
                    answer.number,
                    answer.check_code,
                    short_time(&answer.received_at),
                    if answer.same_code { "  same code" } else { "" },
                    if r.finalized == Some(answer.number) {
                        "  finalized"
                    } else {
                        ""
                    }
                )
            })
        }
        _ => Ok(()),
    }
}

/// Where an answer went, route by route; the check code only once a route took it.
fn write_in_person_post(out: &mut Vec<u8>, r: &InPersonPostReport) -> std::io::Result<()> {
    for route in &r.routes {
        writeln!(
            out,
            "{} {}: {}{}",
            route.method,
            printable(&route.value),
            route.outcome,
            route
                .reason
                .as_deref()
                .map(|reason| format!(" ({})", printable(reason)))
                .unwrap_or_default()
        )?;
    }
    if r.posted {
        writeln!(
            out,
            "Answer to {} posted; check code {}.",
            r.slate_id, r.check_code
        )
    } else {
        writeln!(out, "Answer to {} not taken; post it again.", r.slate_id)
    }
}

/// The domain line of a scanned code.
fn write_in_person_domain(out: &mut Vec<u8>, domain: &InPersonDomainReport) -> std::io::Result<()> {
    match (domain.state, domain.reason) {
        ("checked", _) => writeln!(out, "Signed for {} (checked).", domain.domain),
        ("refused", Some(reason)) => {
            writeln!(out, "Signed for {} (refused: {reason}).", domain.domain)
        }
        _ => writeln!(
            out,
            "Signed for {} (unchecked: give --domain-file to check it).",
            domain.domain
        ),
    }
}

/// What a scanned in-person code asks for.
fn write_in_person_read(out: &mut Vec<u8>, r: &InPersonReadReport) -> std::io::Result<()> {
    writeln!(
        out,
        "{} {} until block {}.",
        r.stage, r.amount, r.ttl_cutoff
    )?;
    if let Some(fee) = &r.fee {
        writeln!(out, "Fee {fee}.")?;
    }
    if let Some(message) = &r.message {
        writeln!(out, "Message: {}", printable(message))?;
    }
    if let Some(domain) = &r.domain {
        write_in_person_domain(out, domain)?;
    }
    for route in &r.direct {
        writeln!(
            out,
            "The answer also goes to {} {}.",
            route.method,
            printable(&route.value)
        )?;
    }
    match &r.mailbox {
        Some(host) => writeln!(
            out,
            "The answer goes to {}:{} ({}{}).",
            host.host,
            host.port,
            host.host_rule,
            if host.in_relay_list {
                ", a known relay"
            } else {
                ""
            }
        ),
        None => writeln!(out, "The answer is shown back by hand."),
    }
}

fn write_contact_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Contact(r) => write_contact(out, r),
        Report::ContactList(r) => {
            if r.contacts.is_empty() {
                return writeln!(out, "No contacts are paired.");
            }
            for contact in &r.contacts {
                write_contact(out, contact)?;
            }
            Ok(())
        }
        Report::ContactRemove(r) if r.removed => writeln!(out, "Pairing {} removed.", r.contact_id),
        Report::ContactRemove(r) => writeln!(out, "No pairing {}.", r.contact_id),
        Report::ContactSlate(r) => write_contact_slate(out, r),
        Report::ContactCheck(r) => writeln!(
            out,
            "Check sent to {}; `lepic contact collect` takes the answer.",
            r.contact_id
        ),
        Report::ProfileShow(_)
        | Report::ProfileSet(_)
        | Report::ProfileDomainShow(_)
        | Report::ProfileDomainFile(_)
        | Report::ProfileDomainDocument(_)
        | Report::ProfileDomainAttach(_) => write_profile(out, report),
        Report::ContactMoveHome(r) => write_move_home(out, r),
        Report::ContactKeyCheck(r) => writeln!(
            out,
            "Key check sent over pairing {} for {}; `lepic contact collect` takes the answer.",
            r.contact_id, r.old_contact_id
        ),
        Report::ContactInvoiceIssue(r) => writeln!(
            out,
            "Transaction {} asks {} for {} EPIC; the invoice waits in its mailbox.",
            r.tx_id,
            printable(&r.contact_name),
            r.amount
        ),
        Report::ContactInvoices(r) => write_contact_invoices(out, r),
        Report::ContactExport(r) => writeln!(out, "Pairing records written to {}.", r.file),
        Report::ContactImport(r) => writeln!(
            out,
            "{} pairings restored; {} were here already and {} clashed with another.",
            r.imported, r.skipped_existing, r.skipped_conflict
        ),
        Report::ContactPayloadPost(r) => {
            writeln!(out, "Payload {} queued for {}.", r.payload_id, r.contact_id)
        }
        Report::ContactPayloadList(r) => {
            if r.payloads.is_empty() {
                return writeln!(out, "No payloads wait.");
            }
            for payload in &r.payloads {
                writeln!(
                    out,
                    "{}  from {}  {}\n    {}",
                    payload.id, payload.contact_id, payload.received_at, payload.payload
                )?;
            }
            Ok(())
        }
        Report::ContactPayloadAck(r) => {
            writeln!(out, "{} payload(s) acknowledged.", r.acknowledged)
        }
        Report::ContactQuarantine(r) => write_contact_quarantine(out, r),
        _ => Ok(()),
    }
}

fn write_contact_invoices(out: &mut Vec<u8>, r: &ContactInvoiceListReport) -> std::io::Result<()> {
    if r.invoices.is_empty() {
        return writeln!(out, "No invoices from contacts wait.");
    }
    for invoice in &r.invoices {
        writeln!(
            out,
            "{}  {} EPIC from {}{}{}{}{}",
            invoice.slate_id,
            invoice.amount,
            printable(&invoice.contact_name),
            if invoice.verified {
                " (verified)"
            } else {
                " (not verified)"
            },
            invoice
                .purpose
                .map(|purpose| format!(", {purpose}"))
                .unwrap_or_default(),
            invoice
                .reference
                .as_deref()
                .map(|reference| format!(", reference {}", printable(reference)))
                .unwrap_or_default(),
            invoice
                .message
                .as_deref()
                .map(|message| format!(", message {}", printable(message)))
                .unwrap_or_default()
        )?;
        if !invoice.same_amount.is_empty() {
            writeln!(
                out,
                "    another request for the same amount came within ten minutes"
            )?;
        }
    }
    Ok(())
}

fn write_contact_quarantine(out: &mut Vec<u8>, r: &ContactQuarantineReport) -> std::io::Result<()> {
    if r.messages.is_empty() {
        return writeln!(out, "No messages in quarantine.");
    }
    for message in &r.messages {
        writeln!(
            out,
            "{}  from {}  {}  {}  {} bytes, {} attempts",
            message.id,
            message.contact_id,
            message.first_seen,
            message.reason,
            message.size,
            message.attempts
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and index (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use serde_json::Value;

    use super::*;
    use crate::exit::CliError;

    fn keys(text: &str) -> Vec<String> {
        assert_eq!(text.lines().count(), 1, "{text}");
        let value: Value = serde_json::from_str(text).unwrap();
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort_unstable();
        keys
    }

    fn text(value: &str) -> String {
        value.to_owned()
    }

    #[test]
    fn a_declined_invoice_shows_when_and_how_to_end_it() {
        let declined = || TxReport {
            payer_declined_at: Some(text("2026-11-10T09:00:00Z")),
            state: text("received"),
            ..tx(None)
        };
        let json: Value =
            serde_json::from_str(&render(&Report::Show(declined()), OutputFormat::Json)).unwrap();
        let human = render(&Report::Show(declined()), OutputFormat::Human);
        assert!(
            human.contains(
                "declined by the payer at 2026-11-10T09:00:00Z; cancel it with `lepic tx cancel 1`"
            ),
            "{}",
            human.as_str()
        );
        assert_eq!(json["payer_declined_at"], "2026-11-10T09:00:00Z");
        let cancelled = TxReport {
            state: text("cancelled"),
            ..declined()
        };
        let human = render(&Report::Show(cancelled), OutputFormat::Human);
        assert!(
            human.contains("declined by the payer at 2026-11-10T09:00:00Z\n"),
            "{}",
            human.as_str()
        );
        let plain = render(&Report::Show(tx(None)), OutputFormat::Json);
        assert!(!plain.contains("payer_declined_at"), "{}", plain.as_str());
    }

    fn tx(stages: Option<Vec<String>>) -> TxReport {
        TxReport {
            tx_id: 1,
            direction: text("outgoing"),
            state: text("sent"),
            amount_credited: text("0.00000000"),
            amount_debited: text("1.00000000"),
            fee: None,
            slate_id: None,
            transport: None,
            created_at: text("t"),
            updated_at: text("t"),
            stages,
            kernel_excess: None,
            confirmed_height: None,
            messages: None,
            origin: None,
            coinbase: None,
            imported: None,
            sender_reported_posted_at: None,
            sender_reported_cancelled_at: None,
            receiver_declined_at: None,
            payer_declined_at: None,
            receive_listing: None,
            recovery: None,
            delivery: None,
        }
    }

    fn scan_report(delete_unconfirmed: bool) -> WalletScanReport {
        WalletScanReport {
            start_height: 900,
            end_height: 1000,
            resumed: false,
            found: 5,
            restored: 2,
            revived: 1,
            unlocked: 3,
            deleted: 4,
            delete_unconfirmed,
        }
    }

    #[test]
    fn a_scan_names_unlocked_and_deleted_outputs_only_for_the_repair() {
        let plain = render(&Report::Scan(scan_report(false)), OutputFormat::Human).to_string();
        assert_eq!(
            plain,
            "Scanned heights 900 to 1000: 5 outputs found, 2 restored, 1 revived.\n"
        );
        let repair = render(&Report::Scan(scan_report(true)), OutputFormat::Human).to_string();
        assert_eq!(
            repair,
            "Scanned heights 900 to 1000: 5 outputs found, 2 restored, 1 revived, 3 unlocked, \
             4 deleted.\n"
        );
        let resumed = Report::Scan(WalletScanReport {
            resumed: true,
            ..scan_report(false)
        });
        let resumed = render(&resumed, OutputFormat::Human).to_string();
        assert!(
            resumed.starts_with("Continued an interrupted scan.\n"),
            "{resumed}"
        );
    }

    #[test]
    fn info_catching_up_names_both_heights() {
        let report = || InfoReport {
            network: text("mainnet"),
            height: 800,
            node_behind: false,
            catching_up: true,
            node_height: Some(863),
            accounts: vec![],
        };
        let human = render(&Report::Info(report()), OutputFormat::Human).to_string();
        assert!(
            human.contains("Catching up to the node's tip 863; balances are at height 800."),
            "{}",
            human.as_str()
        );
        let json: Value = serde_json::from_str(&json_line(&report())).unwrap();
        assert_eq!(json["catching_up"], true, "{json}");
        assert_eq!(json["node_height"], 863, "{json}");
    }

    #[test]
    fn a_node_behind_the_wallet_names_the_reset_scan() {
        let info = |node_behind| {
            let report = Report::Info(InfoReport {
                network: text("mainnet"),
                height: 20,
                node_behind,
                catching_up: false,
                node_height: None,
                accounts: vec![],
            });
            render(&report, OutputFormat::Human).to_string()
        };
        assert!(
            info(true).contains("`lepic wallet scan --reset-chain` recovers"),
            "{}",
            info(true)
        );
        assert!(!info(false).contains("reset-chain"), "{}", info(false));
    }

    /// The field names are the CLI's JSON interface; a change here is a breaking change.
    #[test]
    #[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
    fn every_json_document_keeps_its_field_names() {
        const TX: &[&str] = &[
            "amount_credited",
            "amount_debited",
            "created_at",
            "direction",
            "fee",
            "slate_id",
            "state",
            "transport",
            "tx_id",
            "updated_at",
        ];
        let account = AccountReport {
            index: 0,
            label: text("default"),
            total: None,
            spendable: None,
            awaiting_confirmation: None,
            awaiting_finalization: None,
            immature: None,
            locked: None,
        };
        let cases: Vec<(Report, Vec<&str>)> = vec![
            (
                Report::Init(InitReport {
                    network: text("mainnet"),
                    data_dir: text("/d"),
                    recovery_phrase: Zeroizing::new(text("words")),
                }),
                vec!["data_dir", "network", "recovery_phrase"],
            ),
            (
                Report::Restore(RestoreReport {
                    network: text("mainnet"),
                    data_dir: text("/d"),
                    scan: None,
                }),
                vec!["data_dir", "network", "scan"],
            ),
            (
                Report::Scan(scan_report(true)),
                vec![
                    "deleted",
                    "end_height",
                    "found",
                    "restored",
                    "resumed",
                    "revived",
                    "start_height",
                    "unlocked",
                ],
            ),
            (
                Report::Info(InfoReport {
                    network: text("mainnet"),
                    height: 1,
                    node_behind: false,
                    catching_up: false,
                    node_height: None,
                    accounts: vec![],
                }),
                vec![
                    "accounts",
                    "catching_up",
                    "height",
                    "network",
                    "node_behind",
                ],
            ),
            (
                Report::Address(AddressReport { address: text("a") }),
                vec!["address"],
            ),
            (
                Report::Outputs(OutputsReport {
                    account: text("default"),
                    outputs: vec![],
                }),
                vec!["account", "outputs"],
            ),
            (
                Report::Password(PasswordReport { changed: true }),
                vec!["changed"],
            ),
            (
                Report::Backup(BackupReport {
                    dir: text("d"),
                    files: vec![],
                }),
                vec!["dir", "files"],
            ),
            (
                Report::Send(SendReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                    fee: text("1"),
                    transport: text("file"),
                    destination: text("f"),
                    state: "sent",
                    repeated: false,
                    delivered: true,
                    reason: None,
                    next_attempt_at: None,
                    format: Some("legacy"),
                    slate_bytes: None,
                    slate_limit: None,
                }),
                vec![
                    "amount",
                    "delivered",
                    "destination",
                    "fee",
                    "format",
                    "repeated",
                    "slate_id",
                    "state",
                    "transport",
                    "tx_id",
                ],
            ),
            (
                Report::Resend(ResendReport {
                    tx_id: 1,
                    transport: text("epicbox"),
                    destination: text("a"),
                    state: "sent",
                }),
                vec!["destination", "state", "transport", "tx_id"],
            ),
            (
                Report::Receive(ReceiveReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                    reply_file: text("f"),
                    repeated: false,
                }),
                vec!["amount", "repeated", "reply_file", "slate_id", "tx_id"],
            ),
            (
                Report::Finalize(FinalizeReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    state: text("posted"),
                }),
                vec!["slate_id", "state", "tx_id"],
            ),
            (
                Report::Post(PostReport {
                    tx_id: 1,
                    state: text("posted"),
                    already_on_chain: false,
                    height: None,
                }),
                vec!["already_on_chain", "state", "tx_id"],
            ),
            (
                Report::Post(PostReport {
                    tx_id: 1,
                    state: text("posted"),
                    already_on_chain: true,
                    height: Some(7),
                }),
                vec!["already_on_chain", "height", "state", "tx_id"],
            ),
            (
                Report::Cancel(CancelReport {
                    tx_id: 1,
                    state: text("cancelled"),
                    relay: None,
                    relay_error: None,
                }),
                vec!["state", "tx_id"],
            ),
            (
                Report::Cancel(CancelReport {
                    tx_id: 1,
                    state: text("cancelled"),
                    relay: Some(text("failed")),
                    relay_error: Some(text("relay unreachable")),
                }),
                vec!["relay", "relay_error", "state", "tx_id"],
            ),
            (
                Report::Recover(RecoverReport {
                    tx_id: 1,
                    recovery_tx_id: 2,
                    state: text("posted"),
                }),
                vec!["recovery_tx_id", "state", "tx_id"],
            ),
            (
                Report::Show(TxReport {
                    recovery: Some(TxRecoveryReport {
                        tx_id: 2,
                        state: text("failed"),
                        confirmations: 0,
                        needed: 10,
                        fee: Some(text("0.00400000")),
                        error: Some(text("refused")),
                    }),
                    ..tx(None)
                }),
                [TX, &["recovery"]].concat(),
            ),
            (
                Report::List(TxListReport {
                    account: text("default"),
                    transactions: vec![],
                }),
                vec!["account", "transactions"],
            ),
            (Report::Show(tx(None)), TX.to_vec()),
            (
                Report::Show(tx(Some(vec![text("S1")]))),
                [TX, &["stages"]].concat(),
            ),
            (
                Report::Show(TxReport {
                    kernel_excess: Some(text("08ab")),
                    confirmed_height: Some(7),
                    ..tx(Some(vec![text("S3")]))
                }),
                [TX, &["stages", "kernel_excess", "confirmed_height"]].concat(),
            ),
            (
                Report::InvoiceIssue(InvoiceIssueReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                    transport: text("file"),
                    destination: text("f"),
                    file: Some(text("f")),
                }),
                vec![
                    "amount",
                    "destination",
                    "file",
                    "slate_id",
                    "transport",
                    "tx_id",
                ],
            ),
            (
                Report::InvoiceIssue(InvoiceIssueReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                    transport: text("epicbox"),
                    destination: text("a"),
                    file: None,
                }),
                vec!["amount", "destination", "slate_id", "transport", "tx_id"],
            ),
            (
                Report::InvoicePay(InvoicePayReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                    fee: text("1"),
                    transport: text("file"),
                    destination: text("f"),
                    reply_file: Some(text("f")),
                }),
                vec![
                    "amount",
                    "destination",
                    "fee",
                    "reply_file",
                    "slate_id",
                    "transport",
                    "tx_id",
                ],
            ),
            (
                Report::InvoicePay(InvoicePayReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                    fee: text("1"),
                    transport: text("epicbox"),
                    destination: text("a"),
                    reply_file: None,
                }),
                vec![
                    "amount",
                    "destination",
                    "fee",
                    "slate_id",
                    "transport",
                    "tx_id",
                ],
            ),
            (
                Report::InvoiceList(InvoiceListReport { invoices: vec![] }),
                vec!["invoices"],
            ),
            (
                Report::InvoiceDecline(InvoiceDeclineReport {
                    slate_id: text("s"),
                    state: text("declined"),
                }),
                vec!["slate_id", "state"],
            ),
            (
                Report::Inbox(InboxReport {
                    received: 0,
                    finalized: 0,
                    repeated: 0,
                    rejected: 0,
                    held: 0,
                    dropped: 0,
                    notices: 0,
                    buffered: 0,
                    expired: None,
                }),
                vec![
                    "buffered",
                    "dropped",
                    "expired",
                    "finalized",
                    "held",
                    "notices",
                    "received",
                    "rejected",
                    "repeated",
                ],
            ),
            (
                Report::Serve(ServeReport {
                    socket: text("s"),
                    requests: 0,
                    inbox: InboxReport {
                        received: 0,
                        finalized: 0,
                        repeated: 0,
                        rejected: 0,
                        held: 0,
                        dropped: 0,
                        notices: 0,
                        buffered: 0,
                        expired: None,
                    },
                    http: None,
                }),
                vec!["inbox", "requests", "socket"],
            ),
            (
                Report::EpicboxStatus(EpicboxStatusReport {
                    relay: text("r"),
                    address: text("a"),
                    pending_deliveries: 0,
                }),
                vec!["address", "pending_deliveries", "relay"],
            ),
            (
                Report::ContactInvite(ContactInviteReport {
                    contact_id: text("c"),
                    link: text("l"),
                    expires_at: text("t"),
                }),
                vec!["contact_id", "expires_at", "link"],
            ),
            (
                Report::ContactPreview(ContactPreviewReport {
                    claimed_name: text("n"),
                    kind: "person",
                    expires_at: text("t"),
                    home_relay: text("r"),
                    service: false,
                }),
                vec![
                    "claimed_name",
                    "expires_at",
                    "home_relay",
                    "kind",
                    "service",
                ],
            ),
            (
                Report::ContactAccept(ContactAcceptReport {
                    contact_id: text("c"),
                    reply_link: text("l"),
                    posted: true,
                }),
                vec!["contact_id", "posted", "reply_link"],
            ),
            (
                Report::ContactLink(ContactLinkReport {
                    outcome: "confirm",
                    contact_id: Some(text("c")),
                    link: Some(text("l")),
                }),
                vec!["contact_id", "link", "outcome"],
            ),
            (
                Report::ContactCollect(ContactCollectReport {
                    mailboxes: 1,
                    capped: 0,
                    kept: 0,
                    not_reached: 0,
                    replaced: 0,
                    quarantined: 0,
                    quarantine_dropped: 0,
                    buffered: 0,
                    messages: 2,
                    paired: 0,
                    delivered: 1,
                    epic1: 0,
                    failed: vec![],
                    unreachable: vec![],
                    no_mux: vec![],
                    stuck: vec![],
                    refused: vec![],
                }),
                vec![
                    "buffered",
                    "capped",
                    "delivered",
                    "epic1",
                    "failed",
                    "kept",
                    "mailboxes",
                    "messages",
                    "no_mux",
                    "not_reached",
                    "paired",
                    "quarantine_dropped",
                    "quarantined",
                    "refused",
                    "replaced",
                    "stuck",
                    "unreachable",
                ],
            ),
            (
                Report::Contact(ContactReport {
                    contact_id: text("c"),
                    label: text("l"),
                    claimed_name: None,
                    kind: Some("shop"),
                    state: text("paired"),
                    sas: vec![],
                    sas_indexes: vec![],
                    status: "paired",
                    peer_heard_at: None,
                    peer_verified_at: None,
                    peer_features: 0,
                    peer_profile: 0,
                    ended_reason: None,
                    ended_at: None,
                    allow_invoices: false,
                    seal: text("on"),
                    home_relay: None,
                    requested_relay: None,
                    lapsed: false,
                    last_heard: None,
                }),
                vec![
                    "allow_invoices",
                    "claimed_name",
                    "contact_id",
                    "ended_at",
                    "ended_reason",
                    "home_relay",
                    "kind",
                    "label",
                    "lapsed",
                    "last_heard",
                    "peer_features",
                    "peer_heard_at",
                    "peer_profile",
                    "peer_verified_at",
                    "requested_relay",
                    "sas",
                    "sas_indexes",
                    "seal",
                    "state",
                    "status",
                ],
            ),
            (
                Report::ContactList(ContactListReport { contacts: vec![] }),
                vec!["contacts"],
            ),
            (
                Report::ContactRemove(ContactRemoveReport {
                    contact_id: text("c"),
                    removed: true,
                }),
                vec!["contact_id", "removed"],
            ),
            (
                Report::ContactCheck(ContactCheckReport {
                    contact_id: text("c"),
                }),
                vec!["contact_id"],
            ),
            (
                Report::ProfileShow(ProfileShowReport {
                    profile: 3,
                    names: vec!["no-payments"],
                    unnamed: 0,
                }),
                vec!["names", "profile", "unnamed"],
            ),
            (
                Report::ProfileSet(ProfileSetReport {
                    profile: 3,
                    names: vec![],
                    unnamed: 0,
                    queued: 1,
                    configured: 0,
                }),
                vec!["configured", "names", "profile", "queued", "unnamed"],
            ),
            (
                Report::ProfileDomainShow(ProfileDomainShowReport {
                    domain: Some(text("d")),
                    network: text("n"),
                    domain_key: text("k"),
                }),
                vec!["domain", "domain_key", "network"],
            ),
            (
                Report::ProfileDomainFile(ProfileDomainFileReport {
                    path: text("p"),
                    bytes: 1,
                    url: None,
                }),
                vec!["bytes", "path", "url"],
            ),
            (
                Report::ProfileDomainDocument(ProfileDomainDocumentReport {
                    document: text("d"),
                    url: None,
                }),
                vec!["document", "url"],
            ),
            (
                Report::ProfileDomainAttach(ProfileDomainAttachReport {
                    domain: text("d"),
                    queued: 1,
                }),
                vec!["domain", "queued"],
            ),
            (
                Report::ContactMoveHome(ContactMoveHomeReport {
                    home_relay: text("h"),
                    moved: 1,
                    drain_until: Some(text("t")),
                }),
                vec!["drain_until", "home_relay", "moved"],
            ),
            (
                Report::ContactKeyCheck(ContactKeyCheckReport {
                    contact_id: text("c"),
                    old_contact_id: text("o"),
                }),
                vec!["contact_id", "old_contact_id"],
            ),
            (
                Report::ContactSlate(ContactSlateReport {
                    action: "received",
                    contact_id: Some(text("c")),
                    tx_id: Some(1),
                    slate_id: Some(text("s")),
                    stage: Some("S1"),
                    amount: Some(text("1")),
                    file: Some(text("f")),
                    text: None,
                }),
                vec![
                    "action",
                    "amount",
                    "contact_id",
                    "file",
                    "slate_id",
                    "stage",
                    "tx_id",
                ],
            ),
            (
                Report::ContactInvoiceIssue(ContactInvoiceIssueReport {
                    contact_id: text("c"),
                    contact_name: text("n"),
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                }),
                vec!["amount", "contact_id", "contact_name", "slate_id", "tx_id"],
            ),
            (
                Report::ContactInvoices(ContactInvoiceListReport { invoices: vec![] }),
                vec!["invoices"],
            ),
            (
                Report::ContactExport(ContactExportReport { file: text("f") }),
                vec!["file"],
            ),
            (
                Report::ContactBackup(ContactBackupReport { backup: text("b") }),
                vec!["backup"],
            ),
            (
                Report::ContactImport(ContactImportReport {
                    imported: 1,
                    skipped_existing: 0,
                    skipped_conflict: 0,
                }),
                vec!["imported", "skipped_conflict", "skipped_existing"],
            ),
            (
                Report::ContactPayloadPost(ContactPayloadPostReport {
                    contact_id: text("c"),
                    payload_id: text("p"),
                    peer_lacks_app_payloads: false,
                }),
                vec!["contact_id", "payload_id", "peer_lacks_app_payloads"],
            ),
            (
                Report::ContactQuarantine(ContactQuarantineReport { messages: vec![] }),
                vec!["messages"],
            ),
            (
                Report::ApiClientAdd(ApiClientReport {
                    name: text("n"),
                    fingerprint: text("f"),
                    role: "read",
                }),
                vec!["fingerprint", "name", "role"],
            ),
            (
                Report::ApiClientList(ApiClientListReport { clients: vec![] }),
                vec!["clients"],
            ),
            (
                Report::ContactPayloadList(ContactPayloadListReport { payloads: vec![] }),
                vec!["payloads"],
            ),
            (
                Report::ContactPayloadAck(ContactPayloadAckReport { acknowledged: 1 }),
                vec!["acknowledged"],
            ),
            (
                Report::HttpListen(HttpListenReport {
                    port: 3415,
                    exposure: "local",
                    received: 1,
                    repeated: 0,
                    refused: 0,
                }),
                vec!["exposure", "port", "received", "refused", "repeated"],
            ),
            (
                Report::TorAddress(TorAddressReport { onion: text("o") }),
                vec!["onion"],
            ),
            (
                Report::TorListen(TorListenReport {
                    onion: text("o"),
                    previous_onion: None,
                    received: 1,
                    repeated: 0,
                    refused: 0,
                }),
                vec!["onion", "received", "refused", "repeated"],
            ),
            (
                Report::TorListen(TorListenReport {
                    onion: text("o"),
                    previous_onion: Some(text("p")),
                    received: 1,
                    repeated: 0,
                    refused: 0,
                }),
                vec!["onion", "previous_onion", "received", "refused", "repeated"],
            ),
            (
                Report::NodeStatus(NodeStatusReport {
                    node: text("n"),
                    node_version: text("v"),
                    block_header_version: 6,
                    height: 1,
                    last_block: text("h"),
                }),
                vec![
                    "block_header_version",
                    "height",
                    "last_block",
                    "node",
                    "node_version",
                ],
            ),
        ];
        for (report, expected) in cases {
            let mut expected = expected;
            expected.sort_unstable();
            assert_eq!(
                keys(&render(&report, OutputFormat::Json)),
                expected,
                "{report:?}"
            );
        }
        let info = json_line(&InfoReport {
            network: text("mainnet"),
            height: 1,
            node_behind: false,
            catching_up: false,
            node_height: None,
            accounts: vec![account],
        });
        let value: Value = serde_json::from_str(&info).unwrap();
        let mut account_keys: Vec<&str> = value["accounts"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        account_keys.sort_unstable();
        assert_eq!(
            account_keys,
            [
                "awaiting_confirmation",
                "awaiting_finalization",
                "immature",
                "index",
                "label",
                "locked",
                "spendable",
                "total"
            ]
        );
        let expired = json_line(&ExpiredReport::default());
        assert_eq!(keys(&expired), ["cancellable", "cancelled", "deleted"]);
        let parked = json_line(&ParkedInvoiceReport {
            slate_id: text("s"),
            sender: text("a"),
            amount: text("1"),
            message: None,
            received_at: text("t"),
            expires_at: text("t"),
        });
        assert_eq!(
            keys(&parked),
            [
                "amount",
                "expires_at",
                "message",
                "received_at",
                "sender",
                "slate_id"
            ]
        );
        let scan = json_line(&ScanReport {
            start_height: 0,
            end_height: 1,
            found: 0,
            restored: 0,
        });
        assert_eq!(
            keys(&scan),
            ["end_height", "found", "restored", "start_height"]
        );
    }

    /// A buffer that grew would have left a copy of the phrase in freed memory.
    #[test]
    fn the_recovery_phrase_is_rendered_without_growing_the_buffer() {
        let phrase = ["abandon"; 24].join(" ");
        for data_dir in [text("/d"), "\u{1}\"\\".repeat(300)] {
            let report = Report::Init(InitReport {
                network: text("mainnet"),
                data_dir,
                recovery_phrase: Zeroizing::new(phrase.clone()),
            });
            let bound = rendered_len_bound(&report);
            for format in [OutputFormat::Json, OutputFormat::Human] {
                let rendered = render(&report, format);
                assert!(rendered.contains(&phrase));
                assert_eq!(rendered.capacity(), bound, "{format:?}");
            }
            assert_eq!(
                *render(&report, OutputFormat::Json),
                json_line(&report),
                "json output changed"
            );
        }
    }

    #[test]
    fn contact_invoices_name_the_contact_and_say_what_they_are_for() {
        let invoice = |name: &str, verified| ContactInvoiceReport {
            slate_id: text("s"),
            contact_id: text("c"),
            contact_name: name.to_owned(),
            verified,
            amount: text("2.5"),
            purpose: Some("deposit"),
            reference: Some(text("order 7")),
            message: Some(text("thanks")),
            received_at: text("t"),
            same_amount: vec![],
        };
        let shown = render(
            &Report::ContactInvoices(ContactInvoiceListReport {
                invoices: vec![invoice("Exchange X", true), invoice("\"Shop\"", false)],
            }),
            OutputFormat::Human,
        )
        .to_string();
        assert!(
            shown.contains(
                "s  2.5 EPIC from Exchange X (verified), deposit, reference order 7, message thanks"
            ),
            "{shown}"
        );
        assert!(shown.contains("from \"Shop\" (not verified)"), "{shown}");
    }

    #[test]
    fn the_transaction_list_shows_net_amounts_fees_and_short_times() {
        let mut sent = tx(None);
        sent.amount_credited = text("18.49200000");
        sent.amount_debited = text("20.00000000");
        sent.fee = Some(text("0.00800000"));
        sent.transport = Some(text("epicbox"));
        sent.created_at = text("2026-10-03T11:24:52.099175357Z");
        let mut received = tx(None);
        received.tx_id = 2;
        received.direction = text("incoming");
        received.amount_credited = text("2.25000000");
        received.amount_debited = text("0.00000000");
        let report = Report::List(TxListReport {
            account: text("default"),
            transactions: vec![sent, received],
        });
        let rendered = render(&report, OutputFormat::Human).to_string();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(
            lines[0].contains("AMOUNT") && lines[0].contains("FEE"),
            "{rendered}"
        );
        assert!(
            lines[1].contains("-1.50000000")
                && lines[1].contains("0.00800000")
                && lines[1].contains("epicbox")
                && lines[1].ends_with("2026-10-03 11:24:52"),
            "{rendered}"
        );
        assert!(
            lines[2].contains(" 2.25000000") && !lines[2].contains("-2"),
            "{rendered}"
        );
    }

    #[test]
    fn the_transaction_view_shows_its_kernel_and_confirmation_height() {
        let known = Report::Show(TxReport {
            kernel_excess: Some(text("08ab")),
            confirmed_height: Some(1234),
            ..tx(Some(vec![text("S1"), text("S2"), text("S3")]))
        });
        let rendered = render(&known, OutputFormat::Human).to_string();
        assert!(rendered.contains("\nKernel       08ab\n"), "{rendered}");
        assert!(rendered.contains("\nConfirmed at 1234\n"), "{rendered}");

        let unknown = render(&Report::Show(tx(Some(vec![]))), OutputFormat::Human).to_string();
        assert!(unknown.contains("\nKernel       -\n"), "{unknown}");
        assert!(unknown.contains("\nConfirmed at -\n"), "{unknown}");
    }

    #[test]
    fn a_shown_recovery_carries_its_fee_in_json() {
        let shown = |fee: Option<&str>| -> serde_json::Value {
            let report = Report::Show(TxReport {
                recovery: Some(TxRecoveryReport {
                    tx_id: 8,
                    state: text("posted"),
                    confirmations: 0,
                    needed: 10,
                    fee: fee.map(text),
                    error: None,
                }),
                ..tx(None)
            });
            serde_json::from_str(&render(&report, OutputFormat::Json)).unwrap()
        };
        let with_fee = shown(Some("0.00400000"));
        assert_eq!(with_fee["recovery"]["fee"], "0.00400000", "{with_fee}");
        let without = shown(None);
        assert!(without["recovery"].get("fee").is_none(), "{without}");
    }

    #[test]
    fn a_recovery_says_where_it_stands() {
        let recover = |state: &str| {
            let report = Report::Recover(RecoverReport {
                tx_id: 3,
                recovery_tx_id: 8,
                state: text(state),
            });
            render(&report, OutputFormat::Human).to_string()
        };
        assert_eq!(
            recover("posted"),
            "The recovery of transaction 3 is posted as transaction 8. Once it is confirmed, \
             transaction 3 can never be mined; pay again only after that.\n"
        );
        assert_eq!(
            recover("uncertain"),
            "The recovery of transaction 3 is stored as transaction 8; the node could not be \
             reached, and each refresh posts it again.\n"
        );
        assert_eq!(
            recover("confirming"),
            "The recovery of transaction 3 is transaction 8, which the node already holds; it is \
             confirming. Once it is confirmed, transaction 3 can never be mined; pay again only \
             after that.\n"
        );

        let show = |state: &str, error: Option<&str>| {
            let report = Report::Show(TxReport {
                recovery: Some(TxRecoveryReport {
                    tx_id: 8,
                    state: text(state),
                    confirmations: 3,
                    needed: 10,
                    fee: None,
                    error: error.map(text),
                }),
                ..tx(Some(vec![text("S3")]))
            });
            render(&report, OutputFormat::Human).to_string()
        };
        let confirming = show("confirming", None);
        assert!(
            confirming
                .contains("\nRecovery     transaction 8, confirming, 3 of 10 confirmations\n"),
            "{confirming}"
        );
        let failed = show("failed", Some("node refused"));
        assert!(
            failed.contains("\nRecovery     transaction 8, failed: node refused\n"),
            "{failed}"
        );
    }

    #[test]
    fn a_cancel_says_what_the_relay_answered() {
        let cancel = |relay: Option<&str>, relay_error: Option<&str>| {
            render(
                &Report::Cancel(CancelReport {
                    tx_id: 4,
                    state: text("cancelled"),
                    relay: relay.map(text),
                    relay_error: relay_error.map(text),
                }),
                OutputFormat::Human,
            )
            .to_string()
        };
        assert_eq!(cancel(None, None), "Transaction 4 is cancelled.\n");
        assert_eq!(
            cancel(Some("cancelled"), None),
            "Transaction 4 is cancelled.\nThe epicbox relay cancelled it for the other party too.\n"
        );
        let failed = cancel(Some("failed"), Some("relay unreachable"));
        assert!(
            failed.ends_with(
                "Asking the epicbox relay to cancel it failed (relay unreachable), so only this \
                 wallet cancelled it.\n"
            ),
            "{failed}"
        );
        for outcome in ["not_found_or_not_participant", "no_relay_id", "unsupported"] {
            let lines = cancel(Some(outcome), None);
            assert_eq!(lines.lines().count(), 2, "{outcome}: {lines}");
        }
    }

    #[test]
    fn the_transaction_view_lists_the_messages_with_control_characters_escaped() {
        let report = Report::Show(TxReport {
            messages: Some(vec![
                MessageReport {
                    role: text("sender"),
                    text: text("for the pizza"),
                },
                MessageReport {
                    role: text("receiver"),
                    text: text("got it\nState        confirmed\u{1b}[2J"),
                },
            ]),
            ..tx(Some(vec![text("S3")]))
        });
        let rendered = render(&report, OutputFormat::Human).to_string();
        assert!(
            rendered.ends_with(
                "\nMessage      sender: for the pizza\n\
                 Message      receiver: got it\\nState        confirmed\\u{1b}[2J\n"
            ),
            "{rendered}"
        );
        let json = render(&report, OutputFormat::Json).to_string();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["messages"][0]["role"], "sender");
        assert_eq!(
            value["messages"][1]["text"],
            "got it\nState        confirmed\u{1b}[2J"
        );

        let none = render(&Report::Show(tx(Some(vec![]))), OutputFormat::Human).to_string();
        assert!(none.ends_with("\nMessage      -\n"), "{none}");
    }

    #[test]
    fn a_repeated_receive_says_the_reply_was_written_again() {
        let rendered = |repeated| {
            let report = Report::Receive(ReceiveReport {
                tx_id: 4,
                slate_id: text("s"),
                amount: text("1.50000000"),
                reply_file: text("pay.slate.response"),
                repeated,
            });
            render(&report, OutputFormat::Human).to_string()
        };
        let first = rendered(false);
        let again = rendered(true);
        assert!(
            first.starts_with("Transaction 4 receives 1.50000000 EPIC."),
            "{first}"
        );
        assert!(
            again.starts_with(
                "Transaction 4 received this slate before; its reply is written again."
            ) && again.contains("Return pay.slate.response to the sender."),
            "{again}"
        );
    }

    #[test]
    fn a_parked_invoice_lists_with_its_message_escaped() {
        let report = Report::InvoiceList(InvoiceListReport {
            invoices: vec![ParkedInvoiceReport {
                slate_id: text("0436430c-2b02-624c-2032-570501212b00"),
                sender: text("esAddr@relay.example.org"),
                amount: text("3.00000000"),
                message: Some(text("for the bike\u{1b}[2J")),
                received_at: text("2026-10-05T01:00:00Z"),
                expires_at: text("2026-10-06T01:00:00Z"),
            }],
        });
        assert_eq!(
            render(&report, OutputFormat::Human).to_string(),
            "0436430c-2b02-624c-2032-570501212b00  3.00000000 EPIC from esAddr@relay.example.org\n\
             \x20   received 2026-10-05 01:00:00, expires 2026-10-06 01:00:00 (UTC)\n\
             \x20   message: for the bike\\u{1b}[2J\n"
        );
        let empty = Report::InvoiceList(InvoiceListReport { invoices: vec![] });
        assert!(
            render(&empty, OutputFormat::Human).contains("contact invoices"),
            "empty list names `contact invoices`"
        );
    }

    #[test]
    fn the_client_list_shows_each_role() {
        let client = |name: &str, role| ApiClientReport {
            name: text(name),
            fingerprint: text("ab12"),
            role,
        };
        let report = Report::ApiClientList(ApiClientListReport {
            clients: vec![client("gate", "receive"), client("watcher", "read")],
        });
        assert_eq!(
            render(&report, OutputFormat::Human).to_string(),
            "gate  ab12  receive\nwatcher  ab12  read\n"
        );
        assert_eq!(
            render(
                &Report::ApiClientAdd(client("gate", "receive")),
                OutputFormat::Human
            )
            .to_string(),
            "Client gate added with role receive: ab12\n"
        );
    }

    #[test]
    fn an_inbox_report_says_what_the_invoice_expiry_did() {
        let report = |expired| {
            let report = Report::Inbox(InboxReport {
                received: 0,
                finalized: 1,
                repeated: 0,
                rejected: 0,
                held: 0,
                dropped: 5,
                notices: 1,
                buffered: 0,
                expired,
            });
            render(&report, OutputFormat::Human).to_string()
        };
        assert_eq!(
            report(Some(ExpiredReport::default())),
            "Received 0, finalized 1, repeated 0, rejected 0, held for retry 0, dropped 5, \
             notices 1.\n"
        );
        let swept = report(Some(ExpiredReport {
            deleted: vec![text("s")],
            cancelled: vec![4],
            cancellable: vec![7],
        }));
        assert!(
            swept.contains("\nDeleted 1 parked invoices")
                && swept.contains("\nTransaction 4 cancelled;")
                && swept.contains("`lepic tx cancel 7` gives up on it.\n"),
            "{swept}"
        );
        assert!(
            report(None).ends_with("Invoice expiry did not run; the log says why.\n"),
            "{}",
            report(None)
        );
    }

    #[test]
    fn the_error_document_keeps_its_field_names() {
        let rendered = render_error(&CliError::Interrupted, OutputFormat::Json, None);
        assert_eq!(keys(&rendered), ["error"]);
        let value: Value = serde_json::from_str(&rendered).unwrap();
        let mut inner: Vec<&str> = value["error"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        inner.sort_unstable();
        assert_eq!(inner, ["causes", "exit_code", "kind", "message"]);
        assert_eq!(value["error"]["kind"], "interrupted");
        assert_eq!(value["error"]["exit_code"], 12);
    }

    #[test]
    fn a_refusal_with_a_wait_gives_retry_after_secs_and_one_without_leaves_it_out() {
        let refused = |wait: Option<u64>| {
            CliError::Contact(lepic_wallet_contacts::ContactError::Relay(
                lepic_epicbox::MailboxError::Protocol(lepic_epicbox::ClientError::PostRefused {
                    kind: lepic_epicbox::RelayErrorKind::InvalidRequest,
                    description: Some("Rate limit exceeded.".to_owned()),
                    retry_after: wait.map(std::time::Duration::from_secs),
                    mailbox: Some("relay.test:443".to_owned()),
                }),
            ))
        };
        let json = |error: &CliError| -> Value {
            serde_json::from_str(&render_error(error, OutputFormat::Json, None)).unwrap()
        };
        assert_eq!(json(&refused(Some(12)))["error"]["retry_after_secs"], 12);
        assert_eq!(json(&refused(None))["error"]["mailbox"], "relay.test:443");
        assert!(
            json(&CliError::Interrupted)["error"]
                .get("mailbox")
                .is_none()
        );
        assert!(
            json(&refused(None))["error"]
                .get("retry_after_secs")
                .is_none()
        );
        assert!(
            json(&CliError::Interrupted)["error"]
                .get("retry_after_secs")
                .is_none()
        );
    }

    #[test]
    fn an_interrupted_send_names_its_stored_transaction() {
        let error = CliError::SendInterrupted { tx_id: 4 };
        let value: Value =
            serde_json::from_str(&render_error(&error, OutputFormat::Json, None)).unwrap();
        assert_eq!(value["error"]["tx_id"], 4);
        assert_eq!(value["error"]["exit_code"], 12);
        let human = render_error(&error, OutputFormat::Human, None);
        assert!(human.contains("transaction 4 was stored"), "{human}");
    }

    #[test]
    fn error_output_is_cleaned_and_bounded() {
        let planted = format!("\u{1b}[2J\u{202E}\u{200B}{}\n{}", "x".repeat(50_000), "y");
        let error = CliError::Node(lepic_node::NodeError::Connect(Box::new(
            std::io::Error::other(planted),
        )));
        let hidden = |c: char| {
            c == '\u{1b}' || matches!(c, '\u{202A}'..='\u{202E}' | '\u{200B}'..='\u{200F}')
        };

        let human = render_error(&error, OutputFormat::Human, None);
        assert!(!human.chars().any(hidden), "{human:?}");
        assert!(human.lines().count() <= 3, "{human:?}");
        assert!(human.lines().all(|line| line.chars().count() < 1_024));

        let json = render_error(&error, OutputFormat::Json, None);
        let value: Value = serde_json::from_str(&json).unwrap();
        let causes = value["error"]["causes"].as_array().unwrap();
        for text in std::iter::once(&value["error"]["message"]).chain(causes) {
            let text = text.as_str().unwrap();
            assert!(
                !text.chars().any(|c| c.is_control() || hidden(c)),
                "{text:?}"
            );
            assert!(text.chars().count() <= 256);
        }
    }
}

#[cfg(test)]
mod refusal_tests {
    use std::time::Duration;

    use lepic_wallet_contacts::MailboxRefusal;

    use super::*;

    fn refusal(retryable: bool) -> MailboxRefusal {
        MailboxRefusal {
            mailbox: Some("relay.test:443".to_owned()),
            reason: Some("Rate limit exceeded".to_owned()),
            retry_after: Some(Duration::from_secs(12)),
            retryable,
        }
    }

    #[test]
    fn a_refusal_names_the_mailbox_reason_and_retry_seconds() {
        let report = MailboxRefusalReport::from(&refusal(true));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["mailbox"], "relay.test:443");
        assert_eq!(json["reason"], "Rate limit exceeded");
        assert_eq!(json["retry_after_secs"], 12);
        assert_eq!(json["retryable"], true);
        assert!(json["text"].as_str().unwrap().contains("retry in 12 s"));
    }

    #[test]
    fn a_collect_lists_each_refused_post_and_says_when_it_goes_again() {
        let collect = |retryable| {
            let mut report = ContactCollectReport {
                mailboxes: 0,
                capped: 0,
                kept: 0,
                not_reached: 0,
                replaced: 0,
                quarantined: 0,
                quarantine_dropped: 0,
                buffered: 0,
                messages: 0,
                paired: 0,
                delivered: 0,
                epic1: 0,
                failed: vec![],
                unreachable: vec![],
                no_mux: vec![],
                stuck: vec![],
                refused: vec![],
            };
            report.refused.push(RefusedPostReport {
                slate_id: "s1".to_owned(),
                refusal: MailboxRefusalReport::from(&refusal(retryable)),
            });
            report
        };
        let json = serde_json::to_value(collect(true)).unwrap();
        assert_eq!(json["refused"][0]["slate_id"], "s1");
        assert_eq!(json["refused"][0]["retry_after_secs"], 12);
        let mut out = Vec::new();
        write_human(&mut out, &Report::ContactCollect(collect(true))).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("retry in 12 s"), "{out}");
        assert!(out.contains("posts it again"), "{out}");
        let mut out = Vec::new();
        write_human(&mut out, &Report::ContactCollect(collect(false))).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains("posts it again"));
    }
}
