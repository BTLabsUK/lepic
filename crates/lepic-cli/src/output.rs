// SPDX-License-Identifier: Apache-2.0
//! What commands print. With `--output json` every command prints exactly one JSON document on
//! stdout, its fields named as below; amounts are strings of EPIC with eight decimals, so they
//! survive parsers that read numbers as doubles. Logs go to stderr either way.

use std::fmt::Write as _;
use std::io::Write as _;

use serde::{Serialize, Serializer};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use crate::amount::{AmountError, format_units, parse_amount};
use crate::exit::CliError;
use crate::settings::OutputFormat;

mod epic1;

pub use epic1::{
    Epic1AddressEntryReport, Epic1AddressReport, Epic1AddressesReport, Epic1AnswerReport,
    Epic1AnswersReport, Epic1AttemptReport, Epic1IssuerReport, Epic1LinkEntryReport,
    Epic1LinkReport, Epic1LinksReport, Epic1PaidReport, Epic1PostReport, Epic1ReadReport,
    Epic1RestoreReport, Epic1RetireReport, EpictxOpenReport,
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
    Password(PasswordReport),
    Send(SendReport),
    Resend(ResendReport),
    Receive(ReceiveReport),
    SlateReceive(SlateReceiveReport),
    Finalize(FinalizeReport),
    Post(PostReport),
    Cancel(TxStateReport),
    Release(TxStateReport),
    List(TxListReport),
    Show(TxReport),
    InvoiceIssue(InvoiceIssueReport),
    InvoicePay(InvoicePayReport),
    InvoiceList(InvoiceListReport),
    InvoiceDecline(InvoiceDeclineReport),
    Inbox(InboxReport),
    Serve(ServeReport),
    ServeStatus(ServeStatusReport),
    Methods(MethodsReport),
    EpicboxStatus(EpicboxStatusReport),
    Peer(PeerReport),
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
    ContactRequests(ContactRequestsReport),
    ContactRequestDismiss(ContactRequestDismissReport),
    ContactRequestCancel(ContactRequestCancelReport),
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
    PeerPins(PeerPinListReport),
    PeerForget(PeerForgetReport),
    Epic1Address(Epic1AddressReport),
    Epic1Addresses(Epic1AddressesReport),
    Epic1Link(Epic1LinkReport),
    Epic1Retire(Epic1RetireReport),
    Epic1Links(Epic1LinksReport),
    Epic1Read(Epic1ReadReport),
    Epic1Paid(Epic1PaidReport),
    Epic1Answers(Epic1AnswersReport),
    Epic1Post(Epic1PostReport),
    Epic1Restore(Epic1RestoreReport),
    Epic1Issuer(Epic1IssuerReport),
    EpictxOpen(EpictxOpenReport),
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
#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct AddressReport {
    pub address: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OutputsReport {
    pub account: String,
    pub outputs: Vec<OutputReport>,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordReport {
    pub changed: bool,
}

#[derive(Debug, Serialize, ToSchema)]
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
    /// Whether a delivery attempt got the slate to the other party. Only a repeat can report
    /// `false`; `tx resend` delivers it.
    pub delivered: bool,
    /// How the slate went to an HTTP or Tor listener: `native` through its `/api/v1/inbox`,
    /// or `legacy` through its foreign API. Absent for other transports and for a repeat.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialect: Option<&'static str>,
    /// How the slate went: `legacy` JSON, or `native` over Epicbox (RFC 0003 11.1) or to a
    /// listener's native endpoint. Null for a repeat, which sent nothing.
    pub format: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ResendReport {
    pub tx_id: u32,
    pub transport: String,
    /// The Epicbox address, the file path or the HTTP endpoint the slate went to.
    pub destination: String,
    /// As in [`SendReport::state`].
    pub state: &'static str,
    /// As in [`SendReport::dialect`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialect: Option<&'static str>,
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
#[derive(Debug, Serialize, ToSchema)]
pub struct SlateReceiveReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    /// The reply slate to give the sender, V3 slate JSON.
    pub slate: String,
    /// The slate was received before; `slate` is the reply stored then.
    pub repeated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FinalizeReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub state: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PostReport {
    pub tx_id: u32,
    pub state: String,
    /// The node refused the push because its chain already holds the kernel.
    pub already_on_chain: bool,
    /// The block holding the kernel, when `already_on_chain`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TxStateReport {
    pub tx_id: u32,
    pub state: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TxListReport {
    pub account: String,
    pub transactions: Vec<TxReport>,
}

#[derive(Debug, Serialize, ToSchema)]
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
    /// For a finalized or posted send, the height from which a refresh that still misses its
    /// kernel makes it releasable; shown by `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub releasable_from: Option<u64>,
    /// Whether `tx release` may release it now; shown by `tx show` with `releasable_from`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub releasable: Option<bool>,
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
    /// For a send its receiver refused unanswered, when it said so (ADR 0045); the send was
    /// cancelled then. `tx show` only.
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
    /// For a payment received at an epic1 address, the address's number in its account;
    /// `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epic1_index: Option<u32>,
}

/// A listing: the service key in hex and the generation.
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportedReport {
    pub source_id: u32,
    pub kind: &'static str,
    pub input_count: u32,
    pub output_count: u32,
    pub check: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
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
    /// Invoices stored for the user to pay or decline.
    pub parked: u32,
    /// Invoices this wallet issued that came back unpaid from a payer that does not pay them.
    pub bounced: u32,
    /// Messages acknowledged and forgotten unread, such as notices of no known exchange.
    pub dropped: u32,
    /// Notices about invoices accepted from the other party: posted, declined or withdrawn.
    pub notices: u32,
    /// Notices for a slate this wallet does not hold yet, kept to apply when it arrives.
    pub buffered: u32,
    /// What the invoice expiry did; `null` when it could not run, which the log says why.
    pub expired: Option<ExpiredReport>,
}

#[derive(Debug, Default, Serialize, ToSchema)]
pub struct ExpiredReport {
    /// Slate ids of parked invoices deleted unpaid.
    pub deleted: Vec<String>,
    /// Invoices this wallet issued and cancelled unpaid.
    pub cancelled: Vec<u32>,
    /// Payments of invoices that were not posted within their TTL; `tx cancel` gives up on
    /// them.
    pub cancellable: Vec<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactInviteReport {
    pub contact_id: String,
    pub link: String,
    pub expires_at: String,
}

/// A code to show as a QR code, from `in-person invoice`.
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct InPersonHostReport {
    pub host: String,
    pub port: u16,
    /// The host is this wallet's relay or one of its meeting relays.
    pub in_relay_list: bool,
    /// `public` or `local_network`.
    pub host_rule: &'static str,
}

/// What a scanned code asks, from `in-person read`.
#[derive(Debug, Serialize, ToSchema)]
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
}

/// An answer to a scanned code, from `in-person pay`.
#[derive(Debug, Serialize, ToSchema)]
pub struct InPersonPaidReport {
    pub tx_id: u32,
    pub slate_id: String,
    /// The sealed answer as hex, when it was not written to a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub mailbox: Option<InPersonHostReport>,
}

/// An answer posted to the relay its code names, from `in-person post`.
#[derive(Debug, Serialize, ToSchema)]
pub struct InPersonPostReport {
    pub slate_id: String,
    pub posted: bool,
    /// The check code the other screen shows for this answer, shown only once it is posted.
    pub check_code: String,
}

/// An answer taken for a code this wallet showed, from `in-person take`.
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct InPersonAnswerReport {
    pub number: u32,
    pub check_code: String,
    pub same_code: bool,
    pub received_at: String,
}

/// A code this wallet showed and its answers, from `in-person answers`.
#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactPreviewReport {
    /// What the inviter calls itself, unverified.
    pub claimed_name: String,
    pub kind: &'static str,
    pub expires_at: String,
    pub home_relay: String,
    pub service: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactAcceptReport {
    pub contact_id: String,
    /// The reply as a link, to send by hand when `posted` is false.
    pub reply_link: String,
    pub posted: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactLinkReport {
    /// `confirm` (send `link` back by hand), `paired`, `ignored`, or `invite` (pairing words
    /// found the invite `link`, to answer).
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactCollectReport {
    pub mailboxes: usize,
    pub capped: usize,
    pub kept: usize,
    pub refused: usize,
    pub timed_out: usize,
    pub not_reached: usize,
    pub quarantined: usize,
    pub quarantine_dropped: usize,
    pub buffered: usize,
    pub messages: usize,
    pub paired: usize,
    pub delivered: usize,
    /// Payments taken at epic1 link mailboxes and answers finalized.
    pub epic1: usize,
    /// Pairings in progress that ended with nothing stored.
    pub failed: Vec<ContactFailureReport>,
    pub unreachable: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactFailureReport {
    pub contact_id: String,
    /// `expired`, `changed-on-the-way`, `refused-already-used`, `refused-expired` or
    /// `refused-cancelled`.
    pub reason: &'static str,
}

#[derive(Debug, Serialize, ToSchema)]
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
    /// New slates to the contact go as native slates (`native_direct` set and claimed).
    pub native_slates: bool,
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

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactListReport {
    pub contacts: Vec<ContactReport>,
    /// The pair requests this wallet sent that wait for an answer, oldest first.
    pub sent_requests: Vec<SentRequestReport>,
}

/// A pair request this wallet sent that nobody answered yet.
#[derive(Debug, Serialize, ToSchema)]
pub struct SentRequestReport {
    /// The id `contact request-cancel` takes.
    pub contact_id: String,
    /// The address the request went to.
    pub to_address: Option<String>,
    pub created_at: String,
    /// When the request's invite stops being answerable.
    pub expires_at: String,
}

/// A pair request another wallet sent to this one.
#[derive(Debug, Serialize, ToSchema)]
pub struct PairRequestReport {
    /// The id `contact request-accept` and `contact request-dismiss` take.
    pub request_id: String,
    /// The sender's payments address, as the relay authenticated it.
    pub from_address: String,
    /// The name the sender's invite gives it, unverified.
    pub claimed_name: String,
    pub received_at: String,
    pub expires_at: String,
    /// The invite the request carries, for `contact accept`.
    pub invite_link: String,
}

/// `lepic contact requests`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ContactRequestsReport {
    pub requests: Vec<PairRequestReport>,
}

/// `lepic contact request-dismiss`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ContactRequestDismissReport {
    pub request_id: String,
    pub dismissed: bool,
}

/// `lepic contact request-cancel`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ContactRequestCancelReport {
    pub contact_id: String,
    pub cancelled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactCheckReport {
    pub contact_id: String,
}

/// `lepic profile show`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileShowReport {
    /// The profile this wallet tells paired contacts: the flag, `LEPIC_PROFILE`, the config file.
    pub profile: u16,
    /// The names of the bits set.
    pub names: Vec<&'static str>,
    /// The bits set that have no name, as a number.
    pub unnamed: u32,
}

/// `lepic profile set`.
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileDomainShowReport {
    /// The domain the settings give; none when unset.
    pub domain: Option<String>,
    pub network: String,
    /// This wallet's domain key on the network, 64 hex digits.
    pub domain_key: String,
}

/// `lepic profile domain file`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileDomainFileReport {
    pub path: String,
    pub bytes: usize,
    /// Where the file must be served; none when no domain is configured.
    pub url: Option<String>,
}

/// The text of the domain file, for the wallet API; the command writes it to a file.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileDomainDocumentReport {
    pub document: String,
    /// Where the file must be served; none when no domain is configured.
    pub url: Option<String>,
}

/// `lepic profile domain attach`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileDomainAttachReport {
    pub domain: String,
    /// How many contact updates were queued.
    pub queued: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactMoveHomeReport {
    /// The home relay moved to, `domain:port`.
    pub home_relay: String,
    /// How many contacts were told.
    pub moved: u32,
    /// When the old mailboxes stop being read, RFC 3339; absent without a drain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_until: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
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
    pub received_at: String,
    /// Other requests from the same contact for the same amount within ten minutes.
    pub same_amount: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactInvoiceListReport {
    pub invoices: Vec<ContactInvoiceReport>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactExportReport {
    pub file: String,
}

/// The contact backup document, for the wallet API; the command writes it to a file.
#[derive(Debug, Serialize, ToSchema)]
pub struct ContactBackupReport {
    pub backup: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactImportReport {
    pub imported: usize,
    pub skipped_existing: usize,
    pub skipped_conflict: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactPayloadPostReport {
    pub contact_id: String,
    /// The id the other wallet keeps the payload under, 32 lowercase hex digits.
    pub payload_id: String,
    /// The other wallet's recorded features are known and do not claim app payloads; the
    /// payload was queued all the same.
    pub peer_lacks_app_payloads: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactQuarantineReport {
    pub messages: Vec<QuarantinedMessageReport>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantinedMessageReport {
    pub id: String,
    pub contact_id: String,
    pub reason: &'static str,
    pub first_seen: String,
    pub attempts: u32,
    pub size: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactPayloadListReport {
    pub payloads: Vec<ContactPayloadReport>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactPayloadReport {
    pub id: String,
    pub contact_id: String,
    pub received_at: String,
    /// The bytes as lowercase hex.
    pub payload: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ContactPayloadAckReport {
    /// How many kept payloads were forgotten.
    pub acknowledged: usize,
}

/// The seal keys pinned for an account's direct payees, in origin order.
#[derive(Debug, Serialize, ToSchema)]
pub struct PeerPinListReport {
    pub account: String,
    pub pins: Vec<PeerPinReport>,
}

/// The seal key a LEPIC wallet showed at an origin.
#[derive(Debug, Serialize, ToSchema)]
pub struct PeerPinReport {
    /// `http://host:port`, `https://host:port`, or the onion name alone.
    pub origin: String,
    /// The pinned key, 64 hex digits.
    pub seal_key: String,
    /// When the key was pinned.
    pub first_seen: String,
    /// The last exchange that showed the key.
    pub last_seen: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerForgetReport {
    pub origin: String,
    /// False when no key was pinned for the origin.
    pub forgotten: bool,
}

/// A client of the owner TLS listener.
#[derive(Debug, Serialize)]
pub struct ApiClientReport {
    pub name: String,
    /// The SHA-256 of the client certificate's public key info, in hex.
    pub fingerprint: String,
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
#[derive(Debug, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct OwnerTlsStatus {
    /// The address it listens on, `ip:port`.
    pub address: String,
    /// The SHA-256 of the certificate's public key info, in hex, which clients pin.
    pub fingerprint: String,
}

/// The methods serve offers.
#[derive(Debug, Serialize, ToSchema)]
pub struct MethodsReport {
    /// The registered methods, in registry order.
    pub methods: Vec<MethodReport>,
}

/// One method and what it can do.
#[derive(Debug, Serialize, ToSchema)]
pub struct MethodReport {
    /// The method's id, as a send names it and as transactions store it.
    pub id: String,
    /// Whether it delivers a slate to a destination.
    pub delivers: bool,
    /// Whether this serve receives slates over it: true for Epicbox, whose listener serve
    /// always runs, and for HTTP when serve runs with `--http`.
    pub listens: bool,
    /// Whether it hands a slate to the caller and takes the answer back (files).
    pub exchanges: bool,
    /// Whether it sends LEPIC notices to counterparties.
    pub notices: bool,
    /// What a slate over it may carry.
    pub carries: CarriesReport,
}

/// What a slate over a method may carry.
#[derive(Debug, Serialize, ToSchema)]
pub struct CarriesReport {
    /// A LEPIC receiver may be given a key to seal its answer to.
    pub reply_key: bool,
}

/// The API's requests since serve started.
#[derive(Debug, Clone, Copy, Default, Serialize, ToSchema)]
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
#[derive(Debug, Serialize, ToSchema)]
pub struct ServeHttpStatus {
    #[serde(flatten)]
    pub listener: HttpListenReport,
    /// Who `build_coinbase` is answered to: `off`, `local` or `remote`.
    pub coinbase: &'static str,
}

/// One maintenance task of `serve`, since it started.
#[derive(Debug, Serialize, ToSchema)]
pub struct MaintenanceReport {
    /// Failures since the last success.
    pub consecutive_failures: u32,
    /// The error of the latest failure, kept after a success; `null` before any failure.
    pub last_error: Option<String>,
    /// `null` before the first success.
    pub last_success: Option<String>,
}

/// What `http listen`, or the HTTP listener of `serve`, did before it was stopped.
#[derive(Debug, Serialize, ToSchema)]
pub struct HttpListenReport {
    pub port: u16,
    /// `local` or `internet`.
    pub exposure: &'static str,
    pub received: u32,
    /// Payments answered again with the reply stored the first time.
    pub repeated: u32,
    pub refused: u32,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerReport {
    pub address: String,
    /// `unknown`, `lepic` or `no_invoices`.
    pub capability: &'static str,
    /// When its last message with the LEPIC marker came, RFC 3339.
    pub last_marked_at: Option<String>,
    /// When its last slate without the marker, or an invoice it sent back, came, RFC 3339.
    pub last_unmarked_at: Option<String>,
    /// Whether it is told of the end of an exchange that came marked.
    pub notices: bool,
    /// Whether its latest marked slate claimed native slates with a valid key. Recorded only
    /// by a wallet with native slates on.
    pub native_slates: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EpicboxStatusReport {
    pub relay: String,
    pub address: String,
    pub pending_deliveries: usize,
}

#[derive(Debug, Serialize, ToSchema)]
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
    exit_code: u8,
    message: &'a str,
    causes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_id: Option<u32>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    recovery: &'a [String],
    /// Seconds the listener asked the sender to wait before it posts again.
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_s: Option<u64>,
}

/// The text a successful command prints. A report that carries the recovery phrase is rendered
/// into a buffer sized for it up front, so no reallocation leaves an unwiped copy behind.
fn write_contact_slate(out: &mut Vec<u8>, r: &ContactSlateReport) -> std::io::Result<()> {
    let what = match r.action {
        "sealed" => "Sealed",
        "sent" => "Queued for the contact's mailbox:",
        "plain" => "Plain",
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
                    exit_code: kind.exit_code(),
                    message,
                    causes,
                    tx_id: error.tx_id(),
                    recovery: &crate::hint::recovery(error),
                    retry_after_s: error.retry_after().map(|wait| wait.as_secs()),
                },
            })
        }
        OutputFormat::Human => {
            let mut text = format!("error: {}\n", chain.join(": "));
            if let Some(wait) = error.retry_after() {
                let _ = writeln!(
                    text,
                    "the listener asks to try again in {} s",
                    wait.as_secs()
                );
            }
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
fn printable(text: &str) -> String {
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

/// `now` for a send `tx release` may release, the height a refresh must reach first for one
/// that may become releasable, and `-` for any other transaction.
fn release_text(tx: &TxReport) -> String {
    match (tx.releasable, tx.releasable_from) {
        (Some(true), _) => "now".to_owned(),
        (_, Some(height)) => format!("after a refresh at height {height} or above"),
        _ => "-".to_owned(),
    }
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
fn short_time(timestamp: &str) -> String {
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

#[expect(clippy::too_many_lines, reason = "one arm per report kind")]
fn write_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Init(_)
        | Report::Restore(_)
        | Report::Scan(_)
        | Report::Info(_)
        | Report::Address(_)
        | Report::Outputs(_)
        | Report::Password(_)
        | Report::ImportHistory(_)
        | Report::NodeStatus(_) => write_wallet_human(out, report),
        Report::Send(_)
        | Report::Resend(_)
        | Report::Receive(_)
        | Report::SlateReceive(_)
        | Report::Finalize(_)
        | Report::Post(_)
        | Report::Cancel(_)
        | Report::Release(_)
        | Report::List(_)
        | Report::Show(_) => write_transaction_human(out, report),
        Report::InvoiceIssue(_)
        | Report::InvoicePay(_)
        | Report::InvoiceList(_)
        | Report::InvoiceDecline(_)
        | Report::Peer(_) => write_invoice_human(out, report),
        Report::Inbox(_)
        | Report::Serve(_)
        | Report::ServeStatus(_)
        | Report::Methods(_)
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
        | Report::ContactRequests(_)
        | Report::ContactRequestDismiss(_)
        | Report::ContactRequestCancel(_)
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
        | Report::Epic1Addresses(_)
        | Report::Epic1Link(_)
        | Report::Epic1Retire(_)
        | Report::Epic1Links(_)
        | Report::Epic1Read(_)
        | Report::Epic1Paid(_)
        | Report::Epic1Answers(_)
        | Report::Epic1Post(_)
        | Report::Epic1Restore(_)
        | Report::Epic1Issuer(_)
        | Report::EpictxOpen(_) => epic1::write_epic1_human(out, report),
        Report::ApiClientAdd(r) => writeln!(out, "Client {} added: {}", r.name, r.fingerprint),
        Report::ApiClientRemove(r) => writeln!(out, "Client {} removed.", r.name),
        Report::ApiClientList(r) if r.clients.is_empty() => writeln!(out, "No clients."),
        Report::ApiClientList(r) => r
            .clients
            .iter()
            .try_for_each(|client| writeln!(out, "{}  {}", client.name, client.fingerprint)),
        Report::PeerPins(r) if r.pins.is_empty() => {
            writeln!(out, "No pinned keys for account {}.", r.account)
        }
        Report::PeerPins(r) => r.pins.iter().try_for_each(|pin| {
            writeln!(
                out,
                "{}  {}  pinned {}, last seen {}",
                pin.origin, pin.seal_key, pin.first_seen, pin.last_seen
            )
        }),
        Report::PeerForget(r) if r.forgotten => writeln!(out, "Forgot the key of {}.", r.origin),
        Report::PeerForget(r) => writeln!(out, "No key was pinned for {}.", r.origin),
    }
}

/// A wallet, scan or node report. Writes nothing for any other.
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
        Report::Password(_) => writeln!(out, "Wallet password changed."),
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
        Report::Cancel(r) => writeln!(out, "Transaction {} is {}.", r.tx_id, r.state),
        Report::Release(r) => writeln!(
            out,
            "Transaction {} is released and {}; its inputs can be spent again.",
            r.tx_id, r.state
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
        ("Release", release_text(tx)),
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
    if let Some(index) = tx.epic1_index {
        writeln!(out, "{:<12} epic1 address {index}", "Received at")?;
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

/// An invoice report, or what is known about a peer's invoices. Writes nothing for any other.
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
        Report::Peer(r) => match r.capability {
            "lepic" if r.native_slates => writeln!(
                out,
                "{} runs LEPIC: it pays invoices, is sent notices and takes native slates.",
                r.address
            ),
            "lepic" => writeln!(
                out,
                "{} runs LEPIC: it pays invoices and is sent notices.",
                r.address
            ),
            "no_invoices" => writeln!(
                out,
                "{} answered without LEPIC last, or sent an invoice back: it does not pay \
                 invoices and is sent no notices. Send it a slate file instead.",
                r.address
            ),
            _ => writeln!(
                out,
                "Nothing is known yet about {}: it has not paid an invoice or sent one back.",
                r.address
            ),
        },
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
fn write_methods(out: &mut Vec<u8>, report: &MethodsReport) -> std::io::Result<()> {
    let yes = |flag: bool| if flag { "yes" } else { "no" };
    writeln!(out, "Method   Delivers  Listens  Exchanges  Notices")?;
    for method in &report.methods {
        writeln!(
            out,
            "{:<8} {:<9} {:<8} {:<10} {}",
            method.id,
            yes(method.delivers),
            yes(method.listens),
            yes(method.exchanges),
            yes(method.notices)
        )?;
    }
    Ok(())
}

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
        Report::Methods(r) => write_methods(out, r),
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
        "Received {}, finalized {}, repeated {}, rejected {}, held for retry {}, parked {}, \
         bounced {}, dropped {}, notices {}.",
        r.received,
        r.finalized,
        r.repeated,
        r.rejected,
        r.held,
        r.parked,
        r.bounced,
        r.dropped,
        r.notices
    )?;
    if r.buffered > 0 {
        writeln!(out, "{} early notices kept.", r.buffered)?;
    }
    write_expired(out, r.expired.as_ref())
}

/// A pairing report. Writes nothing for any other.
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
                (r.refused, "had an acknowledgement refused"),
                (r.timed_out, "ran out of time"),
                (r.not_reached, "were not reached"),
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
                writeln!(out, "{relay} isn't answering.")?;
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
            writeln!(out, "Transaction {}.", r.tx_id)
        }
        Report::InPersonPost(r) => writeln!(
            out,
            "Answer to {} posted; check code {}.",
            r.slate_id, r.check_code
        ),
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
            if r.contacts.is_empty() && r.sent_requests.is_empty() {
                return writeln!(out, "No contacts are paired.");
            }
            for contact in &r.contacts {
                write_contact(out, contact)?;
            }
            for sent in &r.sent_requests {
                writeln!(
                    out,
                    "Request {} to {} waits for an answer until {}.",
                    sent.contact_id,
                    sent.to_address.as_deref().unwrap_or("an unknown address"),
                    sent.expires_at
                )?;
            }
            Ok(())
        }
        Report::ContactRequests(r) => {
            if r.requests.is_empty() {
                return writeln!(out, "No pair requests wait.");
            }
            for request in &r.requests {
                writeln!(
                    out,
                    "Request {} from {} ({}), until {}.",
                    request.request_id,
                    request.from_address,
                    request.claimed_name,
                    request.expires_at
                )?;
            }
            Ok(())
        }
        Report::ContactRequestDismiss(r) => writeln!(out, "Request {} dismissed.", r.request_id),
        Report::ContactRequestCancel(r) => writeln!(out, "Request {} withdrawn.", r.contact_id),
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
            "{}  {} EPIC from {}{}{}{}",
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
            releasable_from: None,
            releasable: None,
            messages: None,
            origin: None,
            coinbase: None,
            imported: None,
            sender_reported_posted_at: None,
            sender_reported_cancelled_at: None,
            receiver_declined_at: None,
            payer_declined_at: None,
            receive_listing: None,
            epic1_index: None,
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
            network: text("floonet"),
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
                network: text("floonet"),
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
                    network: text("floonet"),
                    data_dir: text("/d"),
                    recovery_phrase: Zeroizing::new(text("words")),
                }),
                vec!["data_dir", "network", "recovery_phrase"],
            ),
            (
                Report::Restore(RestoreReport {
                    network: text("floonet"),
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
                    network: text("floonet"),
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
                    dialect: None,
                    format: Some("legacy"),
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
                    dialect: None,
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
                Report::Cancel(TxStateReport {
                    tx_id: 1,
                    state: text("cancelled"),
                }),
                vec!["state", "tx_id"],
            ),
            (
                Report::Release(TxStateReport {
                    tx_id: 1,
                    state: text("cancelled"),
                }),
                vec!["state", "tx_id"],
            ),
            (
                Report::Show(TxReport {
                    releasable_from: Some(1_444),
                    releasable: Some(false),
                    ..tx(Some(vec![text("S3")]))
                }),
                [TX, &["stages", "releasable_from", "releasable"]].concat(),
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
                    parked: 0,
                    bounced: 0,
                    dropped: 0,
                    notices: 0,
                    buffered: 0,
                    expired: None,
                }),
                vec![
                    "bounced",
                    "buffered",
                    "dropped",
                    "expired",
                    "finalized",
                    "held",
                    "notices",
                    "parked",
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
                        parked: 0,
                        bounced: 0,
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
                Report::Peer(PeerReport {
                    address: text("a"),
                    capability: "unknown",
                    last_marked_at: None,
                    last_unmarked_at: None,
                    notices: false,
                    native_slates: false,
                }),
                vec![
                    "address",
                    "capability",
                    "last_marked_at",
                    "last_unmarked_at",
                    "native_slates",
                    "notices",
                ],
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
                    refused: 0,
                    timed_out: 0,
                    not_reached: 0,
                    quarantined: 0,
                    quarantine_dropped: 0,
                    buffered: 0,
                    messages: 2,
                    paired: 0,
                    delivered: 1,
                    epic1: 0,
                    failed: vec![],
                    unreachable: vec![],
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
                    "not_reached",
                    "paired",
                    "quarantine_dropped",
                    "quarantined",
                    "refused",
                    "timed_out",
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
                    native_slates: false,
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
                    "native_slates",
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
                Report::ContactList(ContactListReport {
                    contacts: vec![],
                    sent_requests: vec![],
                }),
                vec!["contacts", "sent_requests"],
            ),
            (
                Report::ContactRequests(ContactRequestsReport { requests: vec![] }),
                vec!["requests"],
            ),
            (
                Report::ContactRequestDismiss(ContactRequestDismissReport {
                    request_id: text("r"),
                    dismissed: true,
                }),
                vec!["dismissed", "request_id"],
            ),
            (
                Report::ContactRequestCancel(ContactRequestCancelReport {
                    contact_id: text("c"),
                    cancelled: true,
                }),
                vec!["cancelled", "contact_id"],
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
                }),
                vec!["fingerprint", "name"],
            ),
            (
                Report::ApiClientList(ApiClientListReport { clients: vec![] }),
                vec!["clients"],
            ),
            (
                Report::PeerPins(PeerPinListReport {
                    account: text("default"),
                    pins: vec![PeerPinReport {
                        origin: text("https://wallet.example:443"),
                        seal_key: text("00"),
                        first_seen: text("t"),
                        last_seen: text("t"),
                    }],
                }),
                vec!["account", "pins"],
            ),
            (
                Report::PeerForget(PeerForgetReport {
                    origin: text("https://wallet.example:443"),
                    forgotten: true,
                }),
                vec!["forgotten", "origin"],
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
            network: text("floonet"),
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
                network: text("floonet"),
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
            shown.contains("s  2.5 EPIC from Exchange X (verified), deposit, reference order 7"),
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
    fn the_transaction_view_says_when_a_send_can_be_released() {
        let view = |releasable_from, releasable| {
            let report = Report::Show(TxReport {
                releasable_from,
                releasable,
                ..tx(Some(vec![text("S3")]))
            });
            render(&report, OutputFormat::Human).to_string()
        };
        let waiting = view(Some(1_444), Some(false));
        assert!(
            waiting.contains("\nRelease      after a refresh at height 1444 or above\n"),
            "{waiting}"
        );
        let ready = view(Some(1_444), Some(true));
        assert!(ready.contains("\nRelease      now\n"), "{ready}");
        let other = view(None, None);
        assert!(other.contains("\nRelease      -\n"), "{other}");

        let released = Report::Release(TxStateReport {
            tx_id: 3,
            state: text("cancelled"),
        });
        assert_eq!(
            render(&released, OutputFormat::Human).to_string(),
            "Transaction 3 is released and cancelled; its inputs can be spent again.\n"
        );
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
            "empty list names where contact requests wait"
        );
    }

    #[test]
    fn a_peer_report_says_it_takes_native_slates() {
        let report = Report::Peer(PeerReport {
            address: text("esPeer@relay.example.org"),
            capability: "lepic",
            last_marked_at: None,
            last_unmarked_at: None,
            notices: true,
            native_slates: true,
        });
        assert_eq!(
            render(&report, OutputFormat::Human).to_string(),
            "esPeer@relay.example.org runs LEPIC: it pays invoices, is sent notices and takes \
             native slates.\n"
        );
    }

    #[test]
    fn a_peer_report_says_what_is_known_about_invoices() {
        let line = |capability| {
            let report = Report::Peer(PeerReport {
                address: text("esPeer@relay.example.org"),
                capability,
                last_marked_at: None,
                last_unmarked_at: None,
                notices: false,
                native_slates: false,
            });
            render(&report, OutputFormat::Human).to_string()
        };
        assert_eq!(
            line("unknown"),
            "Nothing is known yet about esPeer@relay.example.org: it has not paid an invoice or \
             sent one back.\n"
        );
        assert_eq!(
            line("lepic"),
            "esPeer@relay.example.org runs LEPIC: it pays invoices and is sent notices.\n"
        );
        assert_eq!(
            line("no_invoices"),
            "esPeer@relay.example.org answered without LEPIC last, or sent an invoice back: it \
             does not pay invoices and is sent no notices. Send it a slate file instead.\n"
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
                parked: 2,
                bounced: 0,
                dropped: 5,
                notices: 1,
                buffered: 0,
                expired,
            });
            render(&report, OutputFormat::Human).to_string()
        };
        assert_eq!(
            report(Some(ExpiredReport::default())),
            "Received 0, finalized 1, repeated 0, rejected 0, held for retry 0, parked 2, \
             bounced 0, dropped 5, notices 1.\n"
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
