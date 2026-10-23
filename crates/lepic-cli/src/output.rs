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
    AllowAdd(AllowedSenderReport),
    AllowRemove(AllowRemoveReport),
    AllowList(AllowListReport),
    InvoiceAddress(InvoiceAddressReport),
    EpicboxStatus(EpicboxStatusReport),
    Peer(PeerReport),
    HttpListen(HttpListenReport),
    TorAddress(TorAddressReport),
    TorListen(TorListenReport),
    NodeStatus(NodeStatusReport),
    ImportHistory(ImportHistoryReport),
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
    /// finalized and posted in the same command.
    pub state: &'static str,
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
    /// The payer's invoice address or the file path the invoice went to.
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
    /// Invoices stored on the invoice address for the user to pay or decline.
    pub parked: u32,
    /// Invoices this wallet issued that came back unpaid from a payer that does not pay them.
    pub bounced: u32,
    /// Messages on the invoice address acknowledged and forgotten unread.
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
pub struct AllowedSenderReport {
    pub address: String,
    pub label: String,
    pub added_at: String,
}

#[derive(Debug, Serialize)]
pub struct AllowRemoveReport {
    pub address: String,
    /// False when the address was not allowed.
    pub removed: bool,
}

#[derive(Debug, Serialize)]
pub struct AllowListReport {
    pub senders: Vec<AllowedSenderReport>,
}

#[derive(Debug, Serialize)]
pub struct InvoiceAddressReport {
    pub address: String,
    pub index: u32,
    /// The address moved to `index` in this command.
    pub rotated: bool,
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
}

/// The text a successful command prints. A report that carries the recovery phrase is rendered
/// into a buffer sized for it up front, so no reallocation leaves an unwiped copy behind.
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
        Report::List(r) => {
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
        Report::Show(tx) => {
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
                    "No invoices are waiting; `lepic epicbox drain --invoices` fetches new ones."
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
        Report::Inbox(r) => {
            writeln!(
                out,
                "Received {}, finalized {}, repeated {}, rejected {}, held for retry {}, parked \
                 {}, bounced {}, dropped {}, notices {}.",
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
        Report::AllowAdd(r) => writeln!(out, "Invoices from {} are accepted.", r.address),
        Report::AllowRemove(r) if r.removed => {
            writeln!(out, "Invoices from {} are no longer accepted.", r.address)
        }
        Report::AllowRemove(r) => writeln!(out, "{} was not allowed.", r.address),
        Report::AllowList(r) => {
            if r.senders.is_empty() {
                return writeln!(
                    out,
                    "No senders are allowed; `lepic epicbox allow add <ADDRESS>` adds one."
                );
            }
            for sender in &r.senders {
                let label = if sender.label.is_empty() {
                    "-"
                } else {
                    &sender.label
                };
                writeln!(
                    out,
                    "{}  {}  added {}",
                    sender.address,
                    printable(label),
                    short_time(&sender.added_at)
                )?;
            }
            Ok(())
        }
        Report::InvoiceAddress(r) => {
            writeln!(out, "{}", r.address)?;
            if r.rotated {
                writeln!(
                    out,
                    "Moved to invoice address index {}; the previous address is no longer read.",
                    r.index
                )?;
            }
            Ok(())
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
        Report::Peer(r) => match r.capability {
            "lepic" => writeln!(
                out,
                "{} runs LEPIC: it pays invoices and is sent notices.",
                r.address
            ),
            "no_invoices" => writeln!(
                out,
                "{} sent an invoice back unpaid: it does not pay invoices. Send it a slate file \
                 instead.",
                r.address
            ),
            _ => writeln!(
                out,
                "Nothing is known yet about {}: it has not paid an invoice or sent one back.",
                r.address
            ),
        },
        Report::NodeStatus(r) => {
            writeln!(out, "Node     {} (version {})", r.node, r.node_version)?;
            writeln!(out, "Height   {}", r.height)?;
            writeln!(out, "Block    {}", r.last_block)?;
            writeln!(out, "Header   version {}", r.block_header_version)
        }
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
                }),
                vec![
                    "amount",
                    "destination",
                    "fee",
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
                Report::AllowAdd(AllowedSenderReport {
                    address: text("a"),
                    label: text("l"),
                    added_at: text("t"),
                }),
                vec!["added_at", "address", "label"],
            ),
            (
                Report::AllowRemove(AllowRemoveReport {
                    address: text("a"),
                    removed: true,
                }),
                vec!["address", "removed"],
            ),
            (
                Report::AllowList(AllowListReport { senders: vec![] }),
                vec!["senders"],
            ),
            (
                Report::InvoiceAddress(InvoiceAddressReport {
                    address: text("a"),
                    index: 1,
                    rotated: false,
                }),
                vec!["address", "index", "rotated"],
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
                }),
                vec!["address", "capability"],
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
            render(&empty, OutputFormat::Human).contains("epicbox drain --invoices"),
            "empty list names the drain"
        );
    }

    #[test]
    fn a_peer_report_says_what_is_known_about_invoices() {
        let line = |capability| {
            let report = Report::Peer(PeerReport {
                address: text("esPeer@relay.example.org"),
                capability,
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
            "esPeer@relay.example.org sent an invoice back unpaid: it does not pay invoices. \
             Send it a slate file instead.\n"
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
