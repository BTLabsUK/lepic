//! The command tree. Nouns, then verbs. Global options are the only options shared by every
//! command; an option name keeps one meaning wherever it appears (`tests/command_tree.rs`).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::exit::EXIT_CODES_HELP;

const NEW_PASSWORD_HELP: &str = "\
The new wallet password comes from LEPIC_PASSWORD, else from a hidden prompt, else from one line
of standard input. LEPIC_PASSWORD stays in the process environment while the command runs, where
the same user's processes can read it; the prompt and standard input do not leave it there. A new
wallet password has at least 8 characters.";

const RESTORE_HELP: &str = "\
Reads the recovery phrase, then the new wallet password unless LEPIC_PASSWORD is set, from hidden
prompts or one line each of standard input. LEPIC_PASSWORD stays in the process environment while
the command runs, where the same user's processes can read it. A new wallet password has at least 8
characters.";

const IMPORT_SEED_HELP: &str = "\
Reads the password of the wallet.seed file, then the new wallet password unless LEPIC_PASSWORD is
set, from hidden prompts or one line each of standard input. LEPIC_PASSWORD stays in the process
environment while the command runs, where the same user's processes can read it. A new wallet
password has at least 8 characters.";

const LONG_ABOUT: &str = "\
A light Epic Cash wallet

Commands that open the wallet read its password from LEPIC_PASSWORD, else from a hidden prompt,
else from one line of standard input. Secrets are never taken from arguments. LEPIC_PASSWORD stays
in the process environment while the command runs, where the same user's processes can read it;
the prompt and standard input do not leave it there.";

#[derive(Debug, Parser)]
#[command(
    name = "lepic",
    version,
    about = "A light Epic Cash wallet",
    after_help = EXIT_CODES_HELP,
    long_about = LONG_ABOUT,
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub command: Command,
}

/// Settings a flag gives. Each falls back to its `LEPIC_*` variable, then the config file,
/// then the default.
#[derive(Debug, Default, Clone, Args)]
#[command(next_help_heading = "Global options")]
pub struct GlobalArgs {
    /// Directory holding the wallet database and vault [env: LEPIC_DATA_DIR]
    #[arg(long, global = true, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,
    /// Chain the wallet is on [env: LEPIC_NETWORK] [default: mainnet]
    #[arg(long, global = true, value_name = "NETWORK")]
    pub network: Option<NetworkArg>,
    /// Config file [env: LEPIC_CONFIG] [default: ~/.lepic/config.toml when it exists]
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Log filter: a level or tracing directives [env: LEPIC_LOG_LEVEL] [default: warn]
    #[arg(long, global = true, value_name = "FILTER")]
    pub log_level: Option<String>,
    /// Log line format on stderr [env: LEPIC_LOG_FORMAT] [default: compact]
    #[arg(long, global = true, value_name = "FORMAT")]
    pub log_format: Option<LogFormatArg>,
    /// Command output on stdout [env: LEPIC_OUTPUT] [default: human]
    #[arg(long, global = true, value_name = "FORMAT")]
    pub output: Option<OutputArg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NetworkArg {
    Mainnet,
    Floonet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormatArg {
    Pretty,
    Compact,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputArg {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create, restore and inspect the wallet
    #[command(subcommand)]
    Wallet(WalletCommand),
    /// Send, receive and manage transactions
    #[command(subcommand)]
    Tx(TxCommand),
    /// Ask for a payment, or pay one asked for, over Epicbox or through slate files
    #[command(subcommand)]
    Invoice(InvoiceCommand),
    /// Exchange slates through an Epicbox relay
    #[command(subcommand)]
    Epicbox(EpicboxCommand),
    /// Take payments sent straight to this wallet over HTTP
    #[command(subcommand)]
    Http(HttpCommand),
    /// Take payments at the wallet's onion address over Tor
    #[command(subcommand)]
    Tor(TorCommand),
    /// Query the node
    #[command(subcommand)]
    Node(NodeCommand),
}

#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    /// Create a wallet from new entropy and print its recovery phrase
    #[command(after_help = NEW_PASSWORD_HELP)]
    Init(InitArgs),
    /// Recreate a wallet from its recovery phrase and scan the chain for its outputs
    #[command(after_help = RESTORE_HELP)]
    Restore(RestoreArgs),
    /// Recreate a wallet from an epic-wallet wallet.seed file and scan the chain
    #[command(after_help = IMPORT_SEED_HELP)]
    ImportSeed(ImportSeedArgs),
    /// Refresh against the node and show accounts and balances
    Info,
    /// Show the wallet's Epicbox address
    Address,
    /// Scan the chain for the wallet's outputs and bring the wallet in line with it
    #[command(after_help = WALLET_SCAN_HELP)]
    Scan(WalletScanArgs),
}

const WALLET_SCAN_HELP: &str = "\
Without options the scan starts shortly before the last completed scan, or at genesis when no
scan has completed or a restore scan is still pending. It ends at the node's tip. Ctrl-C stops
it and keeps what it found; the next scan with the same options continues from there.";

#[derive(Debug, Args)]
pub struct WalletScanArgs {
    /// Start at this height; 0 scans the whole chain
    #[arg(long, value_name = "HEIGHT", conflicts_with = "reset_chain")]
    pub start_height: Option<u64>,
    /// Also unlock locked outputs found on chain and delete unconfirmed outputs not found,
    /// cancelling their transactions
    #[arg(long)]
    pub delete_unconfirmed: bool,
    /// Forget the chain heights the wallet stored and scan from genesis, for a wallet ahead of
    /// its node's chain
    #[arg(long)]
    pub reset_chain: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Words in the recovery phrase
    #[arg(long, value_name = "COUNT", default_value = "24")]
    pub words: WordsArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WordsArg {
    #[value(name = "12")]
    Twelve,
    #[value(name = "15")]
    Fifteen,
    #[value(name = "18")]
    Eighteen,
    #[value(name = "21")]
    TwentyOne,
    #[value(name = "24")]
    TwentyFour,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    #[command(flatten)]
    pub scan: ScanArgs,
}

#[derive(Debug, Args)]
pub struct ImportSeedArgs {
    /// The wallet.seed file to read
    #[arg(value_name = "FILE")]
    pub seed_file: PathBuf,
    #[command(flatten)]
    pub scan: ScanArgs,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Do not scan the chain after restoring
    #[arg(long)]
    pub no_scan: bool,
}

#[derive(Debug, Subcommand)]
pub enum TxCommand {
    /// Create a transaction and deliver its first slate
    #[command(after_help = SEND_HTTP_HELP)]
    Send(SendArgs),
    /// Accept a slate file and write the reply next to it
    Receive(ReceiveArgs),
    /// Finalize a reply slate file, to a send or to an invoice, and post the transaction
    Finalize(FinalizeArgs),
    /// Deliver the first slate of a send again, after a failed delivery
    #[command(after_help = "\
Use it when `tx send` exited with code 11. The transaction keeps its inputs locked until it is
delivered and finalized, or cancelled with `lepic tx cancel`.")]
    Resend(ResendArgs),
    /// Post a finalized transaction again
    Post(PostArgs),
    /// Cancel a transaction that is not posted
    Cancel(TxIdArgs),
    /// Release the inputs of a finalized or posted send the network never took
    #[command(after_help = "\
A send is releasable once a refresh a day of blocks (1440) after it was finalized still finds
its kernel nowhere on chain; `lepic tx show` says when. The node is asked once more first, and
the release is refused while its chain or its pool holds the transaction. If another node still
holds it and mines it later, a new send that spends the same inputs fails. A refresh within
10080 blocks, about a week, of the release then finds it: the transaction shows `confirmed` and
its change is back in the balance.")]
    Release(TxIdArgs),
    /// List the transactions of an account
    List(ListArgs),
    /// Show one transaction
    Show(TxIdArgs),
}

const SEND_HTTP_HELP: &str = "\
To an http(s):// address the wallet listening there, epic-wallet `listen -m http` or `lepic http
listen`, answers at once, and the transaction is finalized and posted in the same command. A
missing port is 3415 for http and 443 for https. Plain http goes only to this computer unless
--allow-plain-http is given, since the slate then travels unencrypted.

To an onion address, `<56 characters>.onion` with or without http://, the wallet's own tor is
started from --tor-binary for the send and stopped after it, and the other wallet, `lepic tor
listen` or any wallet receiving over Tor, answers at once. Reaching an onion that is not online
takes up to about two and a half minutes before the send fails.";

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Amount in EPIC, for example 1.5
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub destination: DestinationArgs,
    #[command(flatten)]
    pub plain_http: PlainHttpArg,
    #[command(flatten)]
    pub tor: TorBinaryArgs,
    #[command(flatten)]
    pub fluff: FluffArg,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub spend: SpendArgs,
}

/// How a payment chooses and spends its inputs.
#[derive(Debug, Args)]
pub struct SpendArgs {
    /// Confirmations an output needs before it is spent
    #[arg(long, value_name = "COUNT", default_value_t = 10)]
    pub min_confirmations: u64,
    /// Outputs the change is split into
    #[arg(long, value_name = "COUNT", default_value_t = 1)]
    pub change_outputs: usize,
    /// How inputs are chosen
    #[arg(long, value_name = "STRATEGY", default_value = "all")]
    pub selection: SelectionArg,
    /// Blocks after which the other party must refuse the slate
    #[arg(long, value_name = "BLOCKS")]
    pub ttl_blocks: Option<u64>,
}

#[derive(Debug, Args)]
pub struct ResendArgs {
    #[command(flatten)]
    pub tx: TxIdArgs,
    #[command(flatten)]
    pub destination: DestinationArgs,
    #[command(flatten)]
    pub plain_http: PlainHttpArg,
    #[command(flatten)]
    pub tor: TorBinaryArgs,
    #[command(flatten)]
    pub fluff: FluffArg,
}

#[derive(Debug, Args)]
pub struct PlainHttpArg {
    /// Allow an http:// address on another computer, so the slate travels unencrypted
    #[arg(long)]
    pub allow_plain_http: bool,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct DestinationArgs {
    /// Epicbox address the slate goes to, or for a send the http(s):// or onion address of a
    /// listening wallet
    #[arg(long, value_name = "ADDRESS")]
    pub to: Option<String>,
    /// Write the slate to this file, as V3 slate JSON
    #[arg(long, value_name = "FILE")]
    pub to_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SelectionArg {
    /// Spend every eligible output, as epic-wallet does by default
    All,
    /// Spend the fewest small outputs that cover the amount
    Smallest,
}

#[derive(Debug, Args)]
pub struct AccountArg {
    /// Account label
    #[arg(short = 'a', long, value_name = "LABEL", default_value = "default")]
    pub account: String,
}

#[derive(Debug, Args)]
pub struct MessageArg {
    /// Message to the other party, signed with the slate
    #[arg(short = 'm', long, value_name = "TEXT")]
    pub message: Option<String>,
}

#[derive(Debug, Args)]
pub struct SlateFileArg {
    /// The slate file to read, V2 or V3 slate JSON
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct ReceiveArgs {
    #[command(flatten)]
    pub slate: SlateFileArg,
    #[command(flatten)]
    pub reply: ReplyFileArg,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
}

#[derive(Debug, Args)]
pub struct ReplyFileArg {
    /// Where the reply goes, as V3 slate JSON [default: <FILE>.response]
    #[arg(long, value_name = "FILE")]
    pub reply_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct FinalizeArgs {
    #[command(flatten)]
    pub slate: SlateFileArg,
    #[command(flatten)]
    pub fluff: FluffArg,
}

#[derive(Debug, Args)]
pub struct FluffArg {
    /// Broadcast to all peers at once instead of through the stem phase, when the transaction
    /// is posted
    #[arg(long)]
    pub fluff: bool,
}

#[derive(Debug, Args)]
pub struct TxIdArgs {
    /// Local transaction id, as `tx list` shows it
    #[arg(value_name = "TX_ID")]
    pub tx_id: u32,
}

#[derive(Debug, Args)]
pub struct PostArgs {
    #[command(flatten)]
    pub tx: TxIdArgs,
    #[command(flatten)]
    pub fluff: FluffArg,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub account: AccountArg,
}

#[derive(Debug, Subcommand)]
pub enum InvoiceCommand {
    /// Ask a payer for an amount, at their invoice address or through a slate file
    #[command(after_help = "\
Over Epicbox the invoice goes to the payer's invoice address, which `lepic epicbox
invoice-address` prints on their side; it arrives only once the payer allows your address with
`lepic epicbox allow add`. Their payment comes back to your address, and `lepic epicbox listen`
or `lepic epicbox drain` finalizes and posts it. An invoice left unpaid for
invoice_expiry_hours is cancelled by the next listen or drain.")]
    Issue(IssueArgs),
    /// Pay an invoice parked on the invoice address, or an invoice slate file
    #[command(after_help = "\
The payer types the amount again; an invoice for any other amount is refused. A parked invoice
is paid over Epicbox to the address its sender was allowed under. For a slate file the reply is
written next to it, and the issuer runs `lepic tx finalize` on it. A file whose name is a slate
id is given with a directory, as in ./<SLATE_ID>.")]
    Pay(PayArgs),
    /// List the invoices parked on the invoice address, waiting to be paid or declined
    #[command(after_help = "\
`lepic epicbox drain --invoices` fetches new ones. An invoice not paid within
invoice_expiry_hours of its arrival is deleted by the next drain or listen.")]
    List,
    /// Decline an invoice parked on the invoice address, so it is never paid
    Decline(SlateIdArg),
}

#[derive(Debug, Args)]
pub struct IssueArgs {
    /// Amount to ask for, in EPIC; the payer adds the fee
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub destination: DestinationArgs,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
}

#[derive(Debug, Args)]
pub struct PayArgs {
    /// Slate id of a parked invoice, as `invoice list` shows it, or an invoice slate file, V2
    /// or V3 slate JSON
    #[arg(value_name = "INVOICE")]
    pub invoice: String,
    /// The amount the invoice asks for, in EPIC
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub reply: ReplyFileArg,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub spend: SpendArgs,
}

#[derive(Debug, Args)]
pub struct SlateIdArg {
    /// Slate id of the parked invoice, as `invoice list` shows it
    #[arg(value_name = "SLATE_ID")]
    pub slate_id: String,
}

#[derive(Debug, Subcommand)]
pub enum EpicboxCommand {
    /// Stay connected and handle slates as they arrive, until interrupted
    #[command(after_help = "\
Payments of invoices you issued are finalized and posted as they arrive. Every few minutes,
and once at the start, invoices left unpaid for invoice_expiry_hours are expired. The invoice
address is not listened on; `lepic epicbox drain --invoices` reads it.")]
    Listen,
    /// Handle every pending slate once, then disconnect
    Drain(DrainArgs),
    /// Show the relay, the address and the deliveries still pending
    Status,
    /// Choose the senders whose invoices the invoice address accepts
    #[command(subcommand)]
    Allow(AllowCommand),
    /// Show the invoice address, the one to give a service that invoices you
    #[command(after_help = "\
The invoice address is derived from the recovery phrase at an index of its own, 1 or higher;
a restored wallet starts again at 1. Rotating moves to the next index, and invoices sent to
the old address are no longer read.")]
    InvoiceAddress(InvoiceAddressArgs),
    /// Show whether a peer is known to pay invoices
    #[command(after_help = "\
What this wallet learned from the peer's own messages, matched on the key: lepic once a
payment or notice from it carried the LEPIC marker, no_invoices once it sent an invoice back
unpaid, unknown before either. Nothing is sent.")]
    Peer(PeerArgs),
}

#[derive(Debug, Args)]
pub struct PeerArgs {
    /// Full Epicbox address of the peer
    #[arg(value_name = "ADDRESS")]
    pub address: String,
}

#[derive(Debug, Args)]
pub struct DrainArgs {
    /// Read the invoice address instead of the payments address: park invoices from allowed
    /// senders and drop everything else unread
    #[arg(long)]
    pub invoices: bool,
}

#[derive(Debug, Subcommand)]
pub enum AllowCommand {
    /// Accept invoices from an address, and pay them only to it
    #[command(after_help = "\
Invoices are matched on the key of the address, before the @, because the relay vouches for
the key of a message and never for its domain. Payments always go to the address given here.
Adding a key again replaces its address and label.")]
    Add(AllowAddArgs),
    /// Stop accepting invoices from an address; invoices already parked from it stay
    Remove(AddressArg),
    /// List the allowed senders
    List,
}

#[derive(Debug, Args)]
pub struct AllowAddArgs {
    #[command(flatten)]
    pub address: AddressArg,
    /// A name for the sender, shown by `epicbox allow list`
    #[arg(long, value_name = "TEXT", default_value = "")]
    pub label: String,
}

#[derive(Debug, Args)]
pub struct AddressArg {
    /// Full Epicbox address of the sender, as it gave it
    #[arg(value_name = "ADDRESS")]
    pub address: String,
}

#[derive(Debug, Args)]
pub struct InvoiceAddressArgs {
    /// Move to a new invoice address and abandon the current one
    #[arg(long)]
    pub rotate: bool,
}

#[derive(Debug, Subcommand)]
pub enum HttpCommand {
    /// Answer payments sent to this wallet over HTTP, until interrupted
    #[command(after_help = "\
Serves the wallet foreign API at /v2/foreign, as epic-wallet `listen -m http` does: senders
using `send -m http` or `lepic tx send --to http://...` are paid at once. Only payments are
answered, never invoices. Without --internet it listens on 127.0.0.1 only. With --internet it
listens on every interface, for a port forwarded from the internet: anyone who reaches the port
can send the wallet payments. A request may take up to a minute; at most 16 connections are
served at once and 30 payments a minute are taken.")]
    Listen(HttpListenArgs),
}

#[derive(Debug, Args)]
pub struct HttpListenArgs {
    /// Port to listen on; 0 lets the system pick one
    #[arg(long, value_name = "PORT", default_value_t = 3415)]
    pub port: u16,
    /// Listen on every network interface instead of this computer only
    #[arg(long)]
    pub internet: bool,
}

/// The tor binary the wallet runs for Tor.
#[derive(Debug, Args)]
pub struct TorBinaryArgs {
    /// The tor binary to run, as the Tor Expert Bundle ships it
    #[arg(long, value_name = "PATH")]
    pub tor_binary: Option<PathBuf>,
    /// Directory of the libraries the tor binary needs, put on the library path
    #[arg(long, value_name = "DIR", requires = "tor_binary")]
    pub lib_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum TorCommand {
    /// Show the wallet's onion address, which tor listen publishes
    #[command(after_help = "\
The onion address is the wallet's payment-proof address in onion form, the address epic-wallet
`address` prints too, so it stays the same after a restore from the recovery phrase.")]
    Address,
    /// Answer payments sent to the wallet's onion address over Tor, until interrupted
    #[command(after_help = "\
Runs the tor binary given with --tor-binary for this wallet, with its files in tor/ inside the
data directory, and publishes the wallet's onion address. Payments reach the wallet foreign API
on a listener on 127.0.0.1 that only tor forwards to; only payments are answered, never
invoices. The onion address is printed once others can reach it.")]
    Listen(TorListenArgs),
}

#[derive(Debug, Args)]
pub struct TorListenArgs {
    #[command(flatten)]
    pub tor: TorBinaryArgs,
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Show the node's version and chain tip
    Status,
}
