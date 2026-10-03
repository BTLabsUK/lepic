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
    Info(InfoReport),
    Address(AddressReport),
    Send(SendReport),
    Resend(ResendReport),
    Receive(ReceiveReport),
    Finalize(FinalizeReport),
    Post(PostReport),
    Cancel(TxStateReport),
    List(TxListReport),
    Show(TxReport),
    InvoiceIssue(InvoiceIssueReport),
    InvoicePay(InvoicePayReport),
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
pub struct ResendReport {
    pub tx_id: u32,
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
}

#[derive(Debug, Serialize)]
pub struct InvoiceIssueReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    /// The invoice slate file to give the payer.
    pub file: String,
}

#[derive(Debug, Serialize)]
pub struct InvoicePayReport {
    pub tx_id: u32,
    pub slate_id: String,
    pub amount: String,
    pub fee: String,
    /// The reply to give the issuer, who finalizes it.
    pub reply_file: String,
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
            ];
            for (name, value) in rows {
                writeln!(out, "{name:<12} {value}")?;
            }
            Ok(())
        }
        Report::InvoiceIssue(r) => writeln!(
            out,
            "Transaction {} asks for {} EPIC. Give {} to the payer.\nSlate {}.",
            r.tx_id, r.amount, r.file, r.slate_id
        ),
        Report::InvoicePay(r) => writeln!(
            out,
            "Transaction {} pays {} EPIC (fee {}). Return {} to the issuer.\nSlate {}.",
            r.tx_id, r.amount, r.fee, r.reply_file, r.slate_id
        ),
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
        }
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
                Report::Resend(ResendReport {
                    tx_id: 1,
                    transport: text("epicbox"),
                    destination: text("a"),
                }),
                vec!["destination", "transport", "tx_id"],
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
                    file: text("f"),
                }),
                vec!["amount", "file", "slate_id", "tx_id"],
            ),
            (
                Report::InvoicePay(InvoicePayReport {
                    tx_id: 1,
                    slate_id: text("s"),
                    amount: text("1"),
                    fee: text("1"),
                    reply_file: text("f"),
                }),
                vec!["amount", "fee", "reply_file", "slate_id", "tx_id"],
            ),
            (
                Report::Inbox(InboxReport {
                    received: 0,
                    finalized: 0,
                    repeated: 0,
                    rejected: 0,
                    held: 0,
                }),
                vec!["finalized", "held", "received", "rejected", "repeated"],
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
}
