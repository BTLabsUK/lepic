//! The command tree. Nouns, then verbs. Global options are the only options shared by every
//! command; an option name keeps one meaning wherever it appears (`tests/command_tree.rs`).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::exit::EXIT_CODES_HELP;

const NEW_PASSWORD_HELP: &str = "\
The new wallet password comes from LEPIC_PASSWORD, else from a hidden prompt, else from one line
of standard input. LEPIC_PASSWORD stays in the process environment while the command runs, where
the same user's processes can read it; the prompt and standard input do not leave it there.";

const RESTORE_HELP: &str = "\
Reads the recovery phrase, then the new wallet password unless LEPIC_PASSWORD is set, from hidden
prompts or one line each of standard input. LEPIC_PASSWORD stays in the process environment while
the command runs, where the same user's processes can read it.";

const IMPORT_SEED_HELP: &str = "\
Reads the password of the wallet.seed file, then the new wallet password unless LEPIC_PASSWORD is
set, from hidden prompts or one line each of standard input. LEPIC_PASSWORD stays in the process
environment while the command runs, where the same user's processes can read it.";

const PASSWORD_HELP: &str = "\
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
    before_long_help = PASSWORD_HELP,
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
    /// Ask for a payment, or pay one asked for, through slate files
    #[command(subcommand)]
    Invoice(InvoiceCommand),
    /// Exchange slates through an Epicbox relay
    #[command(subcommand)]
    Epicbox(EpicboxCommand),
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
    Send(SendArgs),
    /// Accept a slate file and write the reply next to it
    Receive(ReceiveArgs),
    /// Finalize a reply slate file, to a send or to an invoice, and post the transaction
    Finalize(FinalizeArgs),
    /// Post a finalized transaction again
    Post(PostArgs),
    /// Cancel a transaction that is not posted
    Cancel(TxIdArgs),
    /// List the transactions of an account
    List(ListArgs),
    /// Show one transaction
    Show(TxIdArgs),
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Amount in EPIC, for example 1.5
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub destination: DestinationArgs,
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
#[group(required = true, multiple = false)]
pub struct DestinationArgs {
    /// Epicbox address of the receiver
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
    /// Broadcast to all peers at once instead of through the stem phase
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
    /// Write an invoice slate file asking the payer for an amount
    Issue(IssueArgs),
    /// Pay an invoice slate file and write the reply next to it
    #[command(after_help = "\
The payer types the amount again; an invoice for any other amount is refused. The issuer then
runs `lepic tx finalize` on the reply.")]
    Pay(PayArgs),
}

#[derive(Debug, Args)]
pub struct IssueArgs {
    /// Amount to ask for, in EPIC; the payer adds the fee
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    /// Write the slate to this file, as V3 slate JSON
    #[arg(long, value_name = "FILE")]
    pub to_file: PathBuf,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
}

#[derive(Debug, Args)]
pub struct PayArgs {
    #[command(flatten)]
    pub slate: SlateFileArg,
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

#[derive(Debug, Subcommand)]
pub enum EpicboxCommand {
    /// Stay connected and handle slates as they arrive, until interrupted
    Listen,
    /// Handle every pending slate once, then disconnect
    Drain,
    /// Show the relay, the address and the deliveries still pending
    Status,
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Show the node's version and chain tip
    Status,
}
