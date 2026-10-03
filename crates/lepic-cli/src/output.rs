//! What commands print. With `--output json` every command prints exactly one JSON document on
//! stdout, its fields named as below; amounts are strings of EPIC with eight decimals, so they
//! survive parsers that read numbers as doubles. Logs go to stderr either way.

use std::fmt::Write as _;

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

use crate::exit::CliError;
use crate::settings::OutputFormat;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Report {
    Init(InitReport),
    Restore(RestoreReport),
    Info(InfoReport),
    Address(AddressReport),
    Send(SendReport),
    Receive(ReceiveReport),
    Finalize(FinalizeReport),
    Post(TxStateReport),
    Cancel(TxStateReport),
    List(TxListReport),
    Show(TxReport),
    Inbox(InboxReport),
    EpicboxStatus(EpicboxStatusReport),
    NodeStatus(NodeStatusReport),
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
    /// The Epicbox address or the file path the slate went to.
    pub destination: String,
}

#[derive(Debug, Serialize)]
pub struct ReceiveReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    pub reply_file: String,
}

#[derive(Debug, Serialize)]
pub struct FinalizeReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub state: String,
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
}

#[derive(Debug, Serialize)]
pub struct InboxReport {
    pub received: u32,
    pub finalized: u32,
    pub repeated: u32,
    pub rejected: u32,
    pub held: u32,
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

/// The text a successful command prints.
pub fn render(report: &Report, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => json_line(report),
        OutputFormat::Human => human(report),
    }
}

/// The text a failed command prints: on stdout as JSON, or on stderr for people.
pub fn render_error(error: &CliError, format: OutputFormat) -> String {
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

fn human(report: &Report) -> String {
    let mut out = String::new();
    // Writing to a String cannot fail.
    let _ = write_human(&mut out, report);
    out
}

fn write_human(out: &mut String, report: &Report) -> std::fmt::Result {
    match report {
        Report::Init(r) => {
            writeln!(out, "Wallet created on {} in {}.", r.network, r.data_dir)?;
            writeln!(
                out,
                "Write down the recovery phrase. It is not shown again:\n"
            )?;
            writeln!(out, "    {}\n", r.recovery_phrase.as_str())
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
        Report::Info(r) => {
            writeln!(out, "Network {}, chain height {}.", r.network, r.height)?;
            if r.node_behind {
                writeln!(
                    out,
                    "The node is behind the last refresh; balances not updated."
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
        Report::Send(r) => writeln!(
            out,
            "Transaction {} sent {} EPIC (fee {}) by {} to {}.\nSlate {}.",
            r.tx_id, r.amount, r.fee, r.transport, r.destination, r.slate_id
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
        Report::Post(r) | Report::Cancel(r) => {
            writeln!(out, "Transaction {} is {}.", r.tx_id, r.state)
        }
        Report::List(r) => {
            if r.transactions.is_empty() {
                return writeln!(out, "No transactions in account {}.", r.account);
            }
            writeln!(
                out,
                "{:>5}  {:<8}  {:<9}  {:>21}  {:>21}  {:<20}",
                "ID", "DIR", "STATE", "CREDITED", "DEBITED", "CREATED"
            )?;
            for tx in &r.transactions {
                writeln!(
                    out,
                    "{:>5}  {:<8}  {:<9}  {:>21}  {:>21}  {:<20}",
                    tx.tx_id,
                    tx.direction,
                    tx.state,
                    tx.amount_credited,
                    tx.amount_debited,
                    tx.created_at
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
            ];
            for (name, value) in rows {
                writeln!(out, "{name:<12} {value}")?;
            }
            Ok(())
        }
        Report::Inbox(r) => writeln!(
            out,
            "Received {}, finalized {}, repeated {}, rejected {}, held for retry {}.",
            r.received, r.finalized, r.repeated, r.rejected, r.held
        ),
        Report::EpicboxStatus(r) => {
            writeln!(out, "Relay    {}", r.relay)?;
            writeln!(out, "Address  {}", r.address)?;
            writeln!(out, "Pending  {} deliveries", r.pending_deliveries)
        }
        Report::NodeStatus(r) => {
            writeln!(out, "Node     {} (version {})", r.node, r.node_version)?;
            writeln!(out, "Height   {}", r.height)?;
            writeln!(out, "Block    {}", r.last_block)?;
            writeln!(out, "Header   version {}", r.block_header_version)
        }
    }
}
