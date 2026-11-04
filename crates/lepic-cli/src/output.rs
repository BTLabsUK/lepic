// SPDX-License-Identifier: Apache-2.0
//! What commands print. With `--output json` every command prints exactly one JSON document on
//! stdout, its fields named as below; amounts are strings of EPIC with eight decimals, so they
//! survive parsers that read numbers as doubles. Logs go to stderr either way.

use std::fmt::Write as _;
use std::io::Write as _;

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

use crate::amount::{AmountError, format_units, parse_amount};
use crate::exit::CliError;
use crate::settings::OutputFormat;

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
    Send(SendReport),
    Resend(ResendReport),
    Receive(ReceiveReport),
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
    ContactCard(ContactCardReport),
    Contact(ContactReport),
    ContactList(ContactListReport),
    ContactRemove(ContactRemoveReport),
    ContactKeyCheck(ContactKeyCheckReport),
    ContactSlate(ContactSlateReport),
    ContactInvoiceIssue(ContactInvoiceIssueReport),
    ContactInvoices(ContactInvoiceListReport),
    ContactExport(ContactExportReport),
    ContactImport(ContactImportReport),
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

#[derive(Debug, Serialize)]
pub struct AddressReport {
    pub address: String,
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
    /// Whether a delivery attempt got the slate to the other party. Only a repeat can report
    /// `false`; `tx resend` delivers it.
    pub delivered: bool,
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

#[derive(Debug, Serialize)]
pub struct TxStateReport {
    pub tx_id: u32,
    pub state: String,
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
    /// For a payment received at a listing address, the directory key (hex) and generation of
    /// that listing; `tx show` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_listing: Option<ListingReport>,
}

/// A listing: the directory key in hex and the generation.
#[derive(Debug, Serialize)]
pub struct ListingReport {
    pub dkey: String,
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
    /// Invoices stored for the user to pay or decline.
    pub parked: u32,
    /// Invoices this wallet issued that came back unpaid from a payer that does not pay them.
    pub bounced: u32,
    /// Messages acknowledged and forgotten unread, such as notices of no known exchange.
    pub dropped: u32,
    /// Notices about invoices accepted from the other party: posted, declined or withdrawn.
    pub notices: u32,
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

#[derive(Debug, Serialize)]
pub struct ContactInviteReport {
    pub contact_id: String,
    pub link: String,
    pub expires_at: String,
    /// The five pairing words as `emoji name`, when they were offered.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub words: Vec<String>,
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

#[derive(Debug, Serialize)]
pub struct ContactAcceptReport {
    pub contact_id: String,
    /// The reply as a link, to send by hand when `posted` is false.
    pub reply_link: String,
    pub posted: bool,
}

#[derive(Debug, Serialize)]
pub struct ContactLinkReport {
    /// `confirm` (send `link` back by hand), `paired`, `ignored`, or `invite` (pairing words
    /// found the invite `link`, to answer).
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactCollectReport {
    pub mailboxes: usize,
    pub messages: usize,
    pub paired: usize,
    pub delivered: usize,
    /// Pairings in progress that ended with nothing stored.
    pub failed: Vec<ContactFailureReport>,
    pub unreachable: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ContactFailureReport {
    pub contact_id: String,
    /// `expired`, `changed-on-the-way`, `refused-already-used`, `refused-expired` or
    /// `refused-cancelled`.
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ContactCardReport {
    pub contact_id: String,
    pub link: String,
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
    pub allow_invoices: bool,
    pub seal: String,
    pub home_relay: Option<String>,
    /// The relay host the contact asked to move to, until `contact move` applies it.
    pub requested_relay: Option<String>,
    pub lapsed: bool,
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

#[derive(Debug, Serialize)]
pub struct ContactImportReport {
    pub imported: usize,
    pub skipped_existing: usize,
    pub skipped_conflict: usize,
}

/// What `serve` did before it was stopped.
#[derive(Debug, Serialize)]
pub struct ServeReport {
    pub socket: String,
    /// Requests answered, whatever their exit code.
    pub requests: u32,
    /// What the Epicbox listener received.
    pub inbox: InboxReport,
}

/// What `http listen` did before it was stopped.
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

#[derive(Debug, Serialize)]
pub struct TorAddressReport {
    /// `<56 characters>.onion`.
    pub onion: String,
}

/// What `tor listen` did before it was stopped.
#[derive(Debug, Serialize)]
pub struct TorListenReport {
    pub onion: String,
    pub received: u32,
    /// Payments answered again with the reply stored the first time.
    pub repeated: u32,
    pub refused: u32,
}

#[derive(Debug, Serialize)]
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
    exit_code: u8,
    message: &'a str,
    causes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_id: Option<u32>,
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
    if let Some(host) = &contact.requested_relay {
        writeln!(out, "    asks to move to relay {}", printable(host))?;
    }
    if contact.lapsed {
        writeln!(out, "    not heard from in 90 days")?;
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

fn write_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Init(_)
        | Report::Restore(_)
        | Report::Scan(_)
        | Report::Info(_)
        | Report::Address(_)
        | Report::ImportHistory(_)
        | Report::NodeStatus(_) => write_wallet_human(out, report),
        Report::Send(_)
        | Report::Resend(_)
        | Report::Receive(_)
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
        | Report::HttpListen(_)
        | Report::TorAddress(_)
        | Report::TorListen(_)
        | Report::EpicboxStatus(_) => write_transport_human(out, report),
        Report::ContactInvite(_)
        | Report::ContactPreview(_)
        | Report::ContactAccept(_)
        | Report::ContactLink(_)
        | Report::ContactCollect(_)
        | Report::ContactCard(_) => write_pairing_human(out, report),
        Report::Contact(_)
        | Report::ContactList(_)
        | Report::ContactRemove(_)
        | Report::ContactSlate(_)
        | Report::ContactKeyCheck(_)
        | Report::ContactInvoiceIssue(_)
        | Report::ContactInvoices(_)
        | Report::ContactExport(_)
        | Report::ContactImport(_) => write_contact_human(out, report),
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
    if let Some(origin) = &tx.origin {
        writeln!(out, "{:<12} {origin}", "Origin")?;
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

/// An inbox, listener, Tor or Epicbox report. Writes nothing for any other.
fn write_transport_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::Inbox(r) => write_inbox(out, r),
        Report::Serve(r) => {
            writeln!(out, "Served {} requests on {}.", r.requests, r.socket)?;
            write_inbox(out, &r.inbox)
        }
        Report::HttpListen(r) => writeln!(
            out,
            "Listened on port {} ({}): received {}, repeated {}, refused {}.",
            r.port, r.exposure, r.received, r.repeated, r.refused
        ),
        Report::TorAddress(r) => writeln!(out, "{}", r.onion),
        Report::TorListen(r) => writeln!(
            out,
            "Listened at {} over Tor: received {}, repeated {}, refused {}.",
            r.onion, r.received, r.repeated, r.refused
        ),
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
    write_expired(out, r.expired.as_ref())
}

/// A pairing report. Writes nothing for any other.
fn write_pairing_human(out: &mut Vec<u8>, report: &Report) -> std::io::Result<()> {
    match report {
        Report::ContactInvite(r) => {
            writeln!(out, "Share this invite: {}", r.link)?;
            if !r.words.is_empty() {
                writeln!(out, "Or read out these words: {}", r.words.join(", "))?;
            }
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
        Report::ContactCard(r) => writeln!(
            out,
            "Show this card: {}\nThen scan the other one with `lepic contact scan-card {} <LINK>`.",
            r.link, r.contact_id
        ),
        _ => Ok(()),
    }
}

/// A report on paired contacts. Writes nothing for any other.
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
        Report::ContactInvoices(r) => {
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
        Report::ContactExport(r) => writeln!(out, "Pairing records written to {}.", r.file),
        Report::ContactImport(r) => writeln!(
            out,
            "{} pairings restored; {} were here already and {} clashed with another.",
            r.imported, r.skipped_existing, r.skipped_conflict
        ),
        _ => Ok(()),
    }
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
            imported: None,
            sender_reported_posted_at: None,
            sender_reported_cancelled_at: None,
            receive_listing: None,
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
    fn a_node_behind_the_wallet_names_the_reset_scan() {
        let info = |node_behind| {
            let report = Report::Info(InfoReport {
                network: text("floonet"),
                height: 20,
                node_behind,
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
                    accounts: vec![],
                }),
                vec!["accounts", "height", "network", "node_behind"],
            ),
            (
                Report::Address(AddressReport { address: text("a") }),
                vec!["address"],
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
                }),
                vec![
                    "amount",
                    "delivered",
                    "destination",
                    "fee",
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
                    expired: None,
                }),
                vec![
                    "bounced",
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
                        expired: None,
                    },
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
                }),
                vec![
                    "address",
                    "capability",
                    "last_marked_at",
                    "last_unmarked_at",
                    "notices",
                ],
            ),
            (
                Report::ContactInvite(ContactInviteReport {
                    contact_id: text("c"),
                    link: text("l"),
                    expires_at: text("t"),
                    words: vec![text("w")],
                }),
                vec!["contact_id", "expires_at", "link", "words"],
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
                    messages: 2,
                    paired: 0,
                    delivered: 1,
                    failed: vec![],
                    unreachable: vec![],
                }),
                vec![
                    "delivered",
                    "failed",
                    "mailboxes",
                    "messages",
                    "paired",
                    "unreachable",
                ],
            ),
            (
                Report::ContactCard(ContactCardReport {
                    contact_id: text("c"),
                    link: text("l"),
                }),
                vec!["contact_id", "link"],
            ),
            (
                Report::Contact(ContactReport {
                    contact_id: text("c"),
                    label: text("l"),
                    claimed_name: None,
                    kind: Some("shop"),
                    state: text("paired"),
                    sas: vec![],
                    allow_invoices: false,
                    seal: text("on"),
                    home_relay: None,
                    requested_relay: None,
                    lapsed: false,
                }),
                vec![
                    "allow_invoices",
                    "claimed_name",
                    "contact_id",
                    "home_relay",
                    "kind",
                    "label",
                    "lapsed",
                    "requested_relay",
                    "sas",
                    "seal",
                    "state",
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
                Report::ContactImport(ContactImportReport {
                    imported: 1,
                    skipped_existing: 0,
                    skipped_conflict: 0,
                }),
                vec!["imported", "skipped_conflict", "skipped_existing"],
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
                    received: 1,
                    repeated: 0,
                    refused: 0,
                }),
                vec!["onion", "received", "refused", "repeated"],
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
    fn a_peer_report_says_what_is_known_about_invoices() {
        let line = |capability| {
            let report = Report::Peer(PeerReport {
                address: text("esPeer@relay.example.org"),
                capability,
                last_marked_at: None,
                last_unmarked_at: None,
                notices: false,
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
