// SPDX-License-Identifier: Apache-2.0
//! The command tree. Nouns, then verbs. Global options are the only options shared by every
//! command; an option name keeps one meaning wherever it appears (`tests/cli/command_tree.rs`).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::exit::EXIT_CODES_HELP;

const NEW_PASSWORD_HELP: &str = "\
The new wallet password comes from the file LEPIC_PASSWORD_FILE names, else LEPIC_PASSWORD, else
from a hidden prompt, else from one line of standard input. LEPIC_PASSWORD stays in the process
environment while the command runs, where the same user's processes can read it; the prompt and
standard input do not leave it there.";

const RESTORE_HELP: &str = "\
Reads the recovery phrase, then the new wallet password unless LEPIC_PASSWORD is set, from hidden
prompts or one line each of standard input. LEPIC_PASSWORD stays in the process environment while
the command runs, where the same user's processes can read it.";

const IMPORT_SEED_HELP: &str = "\
Reads the password of the wallet.seed file, then the new wallet password unless LEPIC_PASSWORD is
set, from hidden prompts or one line each of standard input. LEPIC_PASSWORD stays in the process
environment while the command runs, where the same user's processes can read it.";

const LONG_ABOUT: &str = "\
A light Epic Cash wallet

Commands that open the wallet read its password from the file LEPIC_PASSWORD_FILE names (owner-only),
else from LEPIC_PASSWORD, else from a hidden prompt, else from one line of standard input. Secrets
are never taken from arguments. LEPIC_PASSWORD stays in the process environment while the command
runs, where the same user's processes can read it; the file, the prompt and standard input do not
leave it there.";

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
    /// Chain the wallet is on: mainnet or floonet, the test chain [env: LEPIC_NETWORK] [default:
    /// mainnet]
    #[arg(long, global = true, value_name = "NETWORK")]
    pub network: Option<NetworkArg>,
    /// Config file [env: LEPIC_CONFIG] [default: ~/.lepic/config.toml when it exists]
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Settings file with the servers [env: LEPIC_SETTINGS] [default: ~/.lepic/settings.toml,
    /// ~/.lepic/settings-floonet.toml on floonet; written on first use]
    #[arg(long, global = true, value_name = "FILE")]
    pub settings: Option<PathBuf>,
    /// Log filter: a level or tracing directives [env: LEPIC_LOG_LEVEL] [default: warn]
    #[arg(long, global = true, value_name = "FILTER")]
    pub log_level: Option<String>,
    /// Log line format on stderr [env: LEPIC_LOG_FORMAT] [default: compact]
    #[arg(long, global = true, value_name = "FORMAT")]
    pub log_format: Option<LogFormatArg>,
    /// Command output on stdout [env: LEPIC_OUTPUT] [default: human]
    #[arg(long, global = true, value_name = "FORMAT")]
    pub output: Option<OutputArg>,
    /// Profile bits to tell paired contacts, by name: no-payments, automated [env:
    /// LEPIC_PROFILE] [default: none]
    #[arg(
        long,
        global = true,
        value_name = "NAMES",
        conflicts_with = "profile_bits"
    )]
    pub profile: Option<String>,
    /// Profile bits to tell paired contacts, as a number 0 to 65535 or 0x hex [env: LEPIC_PROFILE]
    #[arg(long, global = true, value_name = "N")]
    pub profile_bits: Option<String>,
    /// Domain to claim to paired contacts, like example.com [env: LEPIC_DOMAIN] [default: none]
    #[arg(long, global = true, value_name = "DOMAIN")]
    pub domain: Option<String>,
    /// Which connections to make: all; tor-only, only through the tor the epicbox_tor settings
    /// name, offline without one; or offline, none [env: LEPIC_CONNECTION_MODE] [default: all]
    #[arg(long, global = true, value_name = "MODE")]
    pub connection_mode: Option<ConnectionModeArg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ConnectionModeArg {
    All,
    TorOnly,
    Offline,
}

impl From<ConnectionModeArg> for crate::settings::ConnectionMode {
    fn from(mode: ConnectionModeArg) -> Self {
        match mode {
            ConnectionModeArg::All => Self::All,
            ConnectionModeArg::TorOnly => Self::TorOnly,
            ConnectionModeArg::Offline => Self::Offline,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum NetworkArg {
    Mainnet,
    Floonet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum LogFormatArg {
    Pretty,
    Compact,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum OutputArg {
    Human,
    Json,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
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
    /// Pair with contacts, and exchange invoices and slates with them through their mailboxes
    Contact(ContactArgs),
    /// Ask for or make a payment face to face, through a code scanned once
    #[command(name = "in-person")]
    InPerson(InPersonArgs),
    /// Take payments at an epic1 address through links, and pay epic1 links
    Epic1(Epic1Args),
    /// List, add, remove and test the mailboxes native mail goes to
    #[command(subcommand, after_help = MAILBOX_HELP)]
    Mailbox(MailboxCommand),
    /// Look into .epictx files
    #[command(subcommand)]
    Epictx(EpictxCommand),
    /// Show or change what this wallet tells its paired contacts about the host
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Hold the wallet open and answer the wallet API on a local socket
    #[command(after_help = SERVE_HELP)]
    Serve(ServeArgs),
    /// Choose who may use the wallet API from another machine
    #[command(subcommand)]
    Api(ApiCommand),
    /// Open the interactive shell, which `lepic` without a command opens at a terminal
    #[command(after_help = SHELL_HELP)]
    Shell,
}

const MAILBOX_HELP: &str = "\
The list is the mailboxes this release ships, plus those added, minus the shipped ones removed;
it holds 1 to 16. `add` and `remove` write `[mailboxes] added` and `removed` in settings.toml and
leave the rest of the file as it was. While `lepic serve` runs they go through it, and its
sessions take the new list at once. A mailbox is a public name reached over TLS: an address, a
name of this computer or one only a private network resolves is refused.";

const SHELL_HELP: &str = "\
Opens the wallet once and keeps it open between commands, which are typed without `lepic`. Tab
completes commands and flags; `help` lists the shell's own words. The wallet locks after
shell_idle_lock_minutes without a command (15 by default, 0 never) and when the shell closes.
Needs a terminal on standard input and output.";

const SERVE_HELP: &str = "\
Opens the wallet once, as other commands do, and holds the data directory until it stops. It
listens on Epicbox, expires unpaid invoices, collects contact mailboxes and refreshes the wallet
while it runs, and answers the wallet API, HTTP with JSON bodies, on a local socket: for example
`curl --unix-socket SOCKET http://lepic/api/v1/status`. GET /api/v1/openapi.json describes every
operation.
Only the user that runs it can use the socket. Ctrl-C or SIGTERM stops it.

Where the mailbox offers mux/1, it holds push sessions to it: the payments address and every live
contact and pairing mailbox are attached, and a collect runs when mail is pushed or a session
attaches, at most one a second. The collect still runs every 30 seconds for the mailboxes no
session reads and when a session is down. relay_sockets (LEPIC_RELAY_SOCKETS) is shared, one
socket a mailbox for payments and contacts, or split, one for each; split is the default when a
tor is named.

With --owner-tls it also answers the wallet API over TLS on the address `[api] owner_tls` sets
in settings.toml, to the clients `lepic api client add` lists, each with its role. It writes its
certificate to api-tls.pem in the data directory; clients trust that file, issued to
`lepic-wallet`, and present their own certificate. Changing the password and contact export and
import stay on the socket.

With --metrics the API also answers GET /api/v1/metrics in the Prometheus text format: balances,
payments by state, the delivery queue, refresh and mailbox health, heights and counters since
start. Prometheus cannot read a socket: scrape it over --owner-tls with a `read` client.";

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
#[command(
    mut_arg("port", |arg| arg.requires("http")),
    mut_arg("internet", |arg| arg.requires("http")),
    mut_arg("coinbase", |arg| arg.requires("http"))
)]
pub struct ServeArgs {
    /// Unix socket to listen on [default: lepic.sock in the data directory]
    #[arg(long, value_name = "SOCKET")]
    pub socket: Option<PathBuf>,
    /// Also answer payments sent over HTTP, as `lepic http listen` does
    #[arg(long)]
    pub http: bool,
    /// Also answer the wallet API over TLS to the listed clients
    #[arg(long)]
    pub owner_tls: bool,
    /// Also answer GET /api/v1/metrics, counts and heights in the Prometheus text format
    #[arg(long)]
    pub metrics: bool,
    /// A public address of this serve that payers post in-person answers to, as
    /// https://host[:port] or http://<onion>.onion[:port]; repeat for more. Loopback and
    /// local-network hosts are refused. Without the flag, LEPIC_SERVE_PUBLIC_URL, comma-separated.
    /// None: in-person codes name no direct route
    #[arg(long = "public-url", value_name = "URL", value_delimiter = ',')]
    #[serde(default)]
    pub public_url: Vec<String>,
    #[command(flatten)]
    pub listen: HttpListenArgs,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ApiCommand {
    /// List, add and remove the clients `serve --owner-tls` accepts
    #[command(subcommand)]
    Client(ApiClientCommand),
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ApiClientCommand {
    /// Accept a client by the key of its certificate
    #[command(after_help = "\
Lists the SHA-256 of the certificate's public key in api-clients in the data directory, with the \
client's role. The key must be Ed25519. A running serve reads the file at each request.")]
    Add(ApiClientAddArgs),
    /// List the accepted clients
    List,
    /// Stop accepting a client, from its next connection
    Remove(ApiClientNameArg),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ApiClientAddArgs {
    /// Name to list the client under: letters, digits, `.`, `-` and `_`
    pub name: String,
    /// The client's certificate, PEM
    pub certificate: PathBuf,
    /// What the client may do: read (calls that change nothing), receive (also invoices,
    /// addresses, links and receiving; never spends) or full (everything the TLS listener answers)
    #[arg(long, default_value = "read", value_parser = ["read", "receive", "full"])]
    pub role: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ApiClientNameArg {
    /// Name the client is listed under
    pub name: String,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
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
    Info(UpdateArg),
    /// Show the wallet's Epicbox address
    Address(QrArg),
    /// List the wallet's outputs, spent ones included
    Outputs(AccountArg),
    /// Change the wallet password
    #[command(after_help = CHANGE_PASSWORD_HELP)]
    Password,
    /// Copy the wallet's vault and database to a new folder, safe while the wallet is in use
    #[command(after_help = BACKUP_HELP)]
    Backup(BackupArgs),
    /// Scan the chain for the wallet's outputs and bring the wallet in line with it
    #[command(after_help = WALLET_SCAN_HELP)]
    Scan(WalletScanArgs),
    /// Import the transaction history of the epic-wallet wallet this one was made from
    #[command(after_help = IMPORT_HISTORY_HELP)]
    ImportHistory(ImportHistoryArgs),
    /// Spend the wallet's outputs to itself as fewer outputs
    #[command(after_help = CONSOLIDATE_HELP)]
    Consolidate(ConsolidateArgs),
    /// Make a new, empty wallet database where a damaged one was set aside, and scan the chain
    #[command(after_help = START_OVER_HELP)]
    StartOver(StartOverArgs),
}

const START_OVER_HELP: &str = "\
For a wallet whose commands fail with damaged_database or damaged_database_kept. LEPIC moved the
damaged database aside in the data directory, as wallet.enc.sqlite3.damaged-<unix seconds> (or
wallet.sqlite3.damaged-<unix seconds> for a plain one), the path the error names, and opens
nothing until this runs. start-over makes a new, empty database from the vault and the password,
and leaves the damaged file where it is. The new database holds the accounts and nothing else:
transaction history, open payments, contacts, the outbox, the event log and the records of earlier
idempotency ids stay in the damaged file. Coins come back from a restore scan from genesis, which
runs now unless --no-scan; then run `lepic wallet scan` before sending or receiving. A database
that opens is opened as it is.";

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct StartOverArgs {
    #[command(flatten)]
    pub scan: ScanArgs,
}

const CONSOLIDATE_HELP: &str = "\
Without --input it spends the smallest spendable outputs of the account, at most --max-inputs of
them, to the wallet itself as --outputs outputs of nearly equal value. Locked outputs, outputs
with fewer confirmations than --min-confirmations and coinbase outputs not yet mature are left
alone. With --input it spends exactly the outputs named, and fails, storing nothing, when one of
them cannot be spent. The fee is the usual fee for the transaction's size. A consolidation links
its inputs to each other on chain. --dry-run shows what it would spend and stores nothing. A run
under a --slate-id that a consolidation of the account already used reports that consolidation
and spends nothing, whatever the other flags say.";

/// Outputs a consolidation spends at most when it names none.
pub const DEFAULT_MAX_INPUTS: u64 = 500;

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ConsolidateArgs {
    /// Most outputs spent, the smallest first
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = DEFAULT_MAX_INPUTS,
        value_parser = clap::value_parser!(u64).range(1..),
        conflicts_with = "inputs"
    )]
    pub max_inputs: u64,
    /// Commitment of an output to spend, in hex; repeat it for each output
    #[arg(long = "input", value_name = "COMMITMENT")]
    pub inputs: Vec<String>,
    /// Outputs made, from 1 to 10
    #[arg(long, value_name = "COUNT", default_value_t = 1)]
    pub outputs: u64,
    /// Show what it would spend and the fee, and store nothing
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub account: AccountArg,
    /// Confirmations an output needs before it is spent
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = lepic_wallet::selection::SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS
    )]
    pub min_confirmations: u64,
    #[command(flatten)]
    pub slate_id: SendSlateIdArg,
}

const CHANGE_PASSWORD_HELP: &str = "\
The current password comes as for any command that opens the wallet. The new password comes from
the file LEPIC_NEW_PASSWORD_FILE names (owner-only), else LEPIC_NEW_PASSWORD, else a hidden prompt
asked twice, else one line of standard input after the current password's. It cannot be empty.
The recovery phrase and the wallet database do not change.";

const BACKUP_HELP: &str = "\
Writes DIR, a new folder (it must not exist; its parent must), with three files:
  wallet.vault               the recovery phrase, encrypted under the wallet password
  wallet.enc.sqlite3         the wallet database: transactions, outputs, contacts, settings
  wallet.enc.sqlite3.check   the check that the key opens the database
The database is copied as one consistent snapshot through a read-only connection, so it is safe
while `lepic serve` or another command has the wallet open, and it changes nothing there (it
takes the data directory lock when it is free, and never waits for it). Both
files stay encrypted under the wallet password, which this command asks for as any command that
opens the wallet does; the password and the recovery phrase are never written in the clear.
Files are readable by the owner only. A wallet whose database is not encrypted yet (one made by
an older lepic, never opened since) is refused: run `lepic wallet info` once first.
To restore, copy the files into an empty folder (mode 700) and use it as the data directory:
`lepic --data-dir DIR wallet info`. The backup does not hold the Epicbox or Tor state, the
settings file or the API clients; the recovery phrase and the password restore the wallet
without them. Keep the backup where the wallet's own folder is not.";

const IMPORT_HISTORY_HELP: &str = "\
DIR is the old wallet's folder (the one holding wallet_data) or its wallet_data folder. Its
database is copied and read from the copy; nothing in DIR is changed. Run it after
`wallet import-seed` or `wallet restore` with the same seed, before or after the scan. Funds
and balances still come from the scan.";

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ImportHistoryArgs {
    /// The old wallet's folder
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
}

const WALLET_SCAN_HELP: &str = "\
Without options the scan starts shortly before the last completed scan, or at genesis when no
scan has completed or a restore scan is still pending. It ends at the node's tip. Ctrl-C stops
it and keeps what it found; the next scan with the same options continues from there.";

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InitArgs {
    /// Words in the recovery phrase
    #[arg(long, value_name = "COUNT", default_value = "24")]
    pub words: WordsArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct RestoreArgs {
    /// Start the restore scan at this block height instead of genesis; outputs below it are
    /// not found
    #[arg(long, value_name = "HEIGHT")]
    pub from_height: Option<u64>,
    #[command(flatten)]
    pub scan: ScanArgs,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct BackupArgs {
    /// The new folder to write; it must not exist
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ImportSeedArgs {
    /// The wallet.seed file to read
    #[arg(value_name = "FILE")]
    pub seed_file: PathBuf,
    #[command(flatten)]
    pub scan: ScanArgs,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ScanArgs {
    /// Do not scan the chain after restoring
    #[arg(long)]
    pub no_scan: bool,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum TxCommand {
    /// Create a transaction and deliver its first slate
    #[command(after_help = SEND_RECIPIENTS_HELP)]
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
    #[command(after_help = "\
A transaction filed on an epicbox relay that cancels transactions (epicbox 3.1.0) is cancelled
there first: the relay refuses further slates of it and tells the other party, whose wallet
cancels it too. The relay's answer is printed, and the transaction is then cancelled in this
wallet whatever the relay said. --local-only cancels it in this wallet only.")]
    Cancel(CancelArgs),
    /// Spend the inputs of a send back to this wallet, as a last resort
    #[command(after_help = "\
For a send that is finalized, posted, cancelled or expired and whose inputs are still held for
it. The node is asked first: the recovery is refused while its pool or its chain holds the send.
The recovery is a send to this wallet that spends all of the send's inputs into one output, so
the send can never be mined once it is. Its fee is 0.004 EPIC for one input, 0.001 EPIC less for
each further input, and at least 0.001 EPIC; a send whose inputs total less cannot be recovered.
The node must accept the recovery. A send still open ends cancelled once the recovery has its
confirmations; pay again only after that.")]
    Recover(TxIdArgs),
    /// List the transactions of an account
    List(ListArgs),
    /// Show one transaction
    Show(TxShowArgs),
}

const SEND_RECIPIENTS_HELP: &str = "\
To an epic1 address or an `epic:epic1…` link the send is the payment `lepic epic1 pay` makes,
with its checks and its report. AMOUNT may be left out when the link asks an amount; an amount
given is paid as given, also when it differs from the link's. The same holds for a classic
`epic:ADDRESS?amount=` link. --mailbox goes to such a payment only; --allow-plain-http, --tor-binary and
--fluff are refused there.

To an http(s):// address the wallet listening there, epic-wallet `listen -m http` or `lepic http
listen`, answers at once, and the transaction is finalized and posted in the same command. A
missing port is 3415 for http and 443 for https. Plain http goes only to this computer unless
--allow-plain-http is given, since the slate then travels unencrypted.

To an onion address, `<56 characters>.onion` with or without http://, the wallet's own tor is
started from --tor-binary for the send and stopped after it, and the other wallet, `lepic tor
listen` or any wallet receiving over Tor, answers at once. Reaching an onion that is not online
takes up to about two and a half minutes before the send fails.

With --slate-id, a send made again under the same id, after a crash or a lost reply, sends
nothing: it reports the first send with repeated: true and whether it was delivered (exit 0),
or fails with code 7 when the account, amount, destination or transport differ. An undelivered
first send is delivered with `lepic tx resend`. `lepic tx show --slate-id` finds the send.

To a contact, --to-contact <ID> from `lepic contact list`, the slate is sealed to the contact and
queued in its mailbox, then posted at once when the mailbox answers; `lepic contact collect` posts
what is still queued and takes the answer. A send the contact cannot take locks nothing, and one
that cannot be queued is cancelled.";

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct SendArgs {
    /// Amount in EPIC, for example 1.5; a send to an epic1 link that asks an amount may leave
    /// it out
    #[arg(value_name = "AMOUNT", required_unless_present = "to")]
    pub amount: Option<String>,
    #[command(flatten)]
    pub destination: SendDestinationArgs,
    /// What the slate is for
    #[arg(long, value_enum, conflicts_with_all = ["to", "to_file"])]
    pub purpose: Option<PurposeArg>,
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
    #[command(flatten)]
    pub slate_id: SendSlateIdArg,
    /// For a payment to an epic1 address or link only
    #[command(flatten)]
    pub mailboxes: PayMailboxesArg,
    /// Which computers an HTTP send may reach; set by the API, never on the command line.
    #[arg(skip)]
    pub reach: HttpReach,
}

/// Which computers an HTTP send may connect to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpReach {
    /// Any computer, this one included.
    #[default]
    Any,
    /// Only other computers: every address the receiver's name resolves to that belongs to this
    /// computer is skipped when connecting.
    OtherComputers,
}

/// The slate id a caller gives a send or an invoice so that a repeat cannot make a second one.
#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct SendSlateIdArg {
    /// Slate id: a random version-4 UUID the caller stores before sending or issuing
    #[arg(long, value_name = "SLATE_ID")]
    pub slate_id: Option<String>,
}

pub const DEFAULT_CHANGE_OUTPUTS: usize = 1;

/// How a payment chooses and spends its inputs.
#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct SpendArgs {
    /// Confirmations an output needs before it is spent
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = lepic_wallet::selection::SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS
    )]
    pub min_confirmations: u64,
    /// Outputs the change is split into
    #[arg(long, value_name = "COUNT", default_value_t = DEFAULT_CHANGE_OUTPUTS)]
    pub change_outputs: usize,
    /// How inputs are chosen
    #[arg(long, value_name = "STRATEGY", default_value = "smallest")]
    pub selection: SelectionArg,
    /// Blocks after which the other party must refuse the slate
    ///
    /// A V2 slate (Epicbox, HTTP) cannot carry it: this wallet keeps the height and expires the
    /// send at refresh if it is unanswered by then. A send that names none waits the
    /// send_ttl_blocks setting, 10080 blocks (7 days) unless set.
    #[arg(long, value_name = "BLOCKS")]
    pub ttl_blocks: Option<u64>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct PlainHttpArg {
    /// Allow an http:// address on another computer, so the slate travels unencrypted
    #[arg(long)]
    pub allow_plain_http: bool,
}

/// Where a send goes: the destinations of [`DestinationArgs`], or a paired contact.
#[derive(Debug, Clone, Args, Serialize, Deserialize)]
#[group(required = true, multiple = false)]
pub struct SendDestinationArgs {
    /// Epicbox address the slate goes to, or for a send the http(s):// or onion address of a
    /// listening wallet
    ///
    /// An epic1 address or link is paid as `lepic epic1 pay` pays it.
    #[arg(long, value_name = "ADDRESS")]
    pub to: Option<String>,
    /// Write the slate to this file, as V3 slate JSON
    #[arg(long, value_name = "FILE")]
    pub to_file: Option<PathBuf>,
    /// Pay a paired contact through its mailbox
    #[arg(long, value_name = "CONTACT_ID")]
    pub to_contact: Option<String>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum SelectionArg {
    /// Spend every eligible output, which locks the whole balance until the send confirms
    All,
    /// Spend the fewest small outputs that cover the amount, as `epic-wallet send` does by
    /// default
    Smallest,
}

/// `--qr` on a command that prints an address or a link to hand on. The shell draws the code
/// without it. Serve never sees it: the CLI draws the code from the report serve answers.
#[derive(Debug, Clone, Copy, Default, Args, Serialize, Deserialize)]
pub struct QrArg {
    /// Also draw it as a QR code, at a terminal wide enough (not with --output json)
    #[arg(long)]
    #[serde(skip)]
    pub qr: bool,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct AccountArg {
    /// Account label
    #[arg(
        short = 'a',
        long,
        value_name = "LABEL",
        default_value = lepic_wallet::DEFAULT_ACCOUNT_LABEL
    )]
    pub account: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct MessageArg {
    /// Message to the other party, signed with the slate
    #[arg(short = 'm', long, value_name = "TEXT")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct SlateFileArg {
    /// The slate file to read, V2 or V3 slate JSON
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ReplyFileArg {
    /// Where the reply goes, as V3 slate JSON [default: <FILE>.response]
    #[arg(long, value_name = "FILE")]
    pub reply_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct FinalizeArgs {
    #[command(flatten)]
    pub slate: SlateFileArg,
    #[command(flatten)]
    pub fluff: FluffArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct FluffArg {
    /// Broadcast to all peers at once instead of through the stem phase, when the transaction
    /// is posted
    #[arg(long)]
    pub fluff: bool,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct TxShowArgs {
    /// Local transaction id, as `tx list` shows it
    #[arg(value_name = "TX_ID", required_unless_present = "slate_id")]
    pub tx_id: Option<u32>,
    #[command(flatten)]
    pub slate_id: SendSlateIdArg,
    #[command(flatten)]
    pub refresh: RefreshArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct TxIdArgs {
    /// Local transaction id, as `tx list` shows it
    #[arg(value_name = "TX_ID")]
    pub tx_id: u32,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct CancelArgs {
    #[command(flatten)]
    pub tx: TxIdArgs,
    /// Cancel the transaction in this wallet only, without asking the epicbox relay to cancel
    /// it for the other party
    #[arg(long)]
    #[serde(default)]
    pub local_only: bool,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct PostArgs {
    #[command(flatten)]
    pub tx: TxIdArgs,
    #[command(flatten)]
    pub fluff: FluffArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ListArgs {
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub refresh: RefreshArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct RefreshArg {
    /// Refresh from the node first, as `wallet info` does, so confirmations and states are
    /// current; without it the listing reads what the last refresh stored
    #[arg(long)]
    pub refresh: bool,
    #[command(flatten)]
    pub update: UpdateArg,
}

#[derive(Debug, Clone, Default, Args, Serialize, Deserialize)]
pub struct UpdateArg {
    /// Refresh, then run the short update scan the app and `lepic serve` run, then read: an
    /// output another install of the recovery phrase received, or spent, is current. Implies
    /// --refresh. Without it nothing scans, so such an output shows once serve or the app
    /// has run the scan
    #[arg(long)]
    #[serde(default)]
    pub update: bool,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum InvoiceCommand {
    /// Ask a payer for an amount through a slate file
    #[command(after_help = "\
The invoice goes as a file given with --to-file. It is not sent to an address: --to is refused
and nothing is stored. Invoice a paired contact with `lepic contact invoice`.")]
    Issue(IssueArgs),
    /// Pay an invoice slate file
    #[command(after_help = "\
The payer types the amount again; an invoice for any other amount is refused. The amount and the
message are shown, and the invoice is paid only once you answer y. Without a terminal it is paid
only with --yes. The reply is written next to the file, and the issuer runs `lepic tx finalize`
on it.")]
    Pay(PayArgs),
    /// List invoices an earlier version parked from Epicbox addresses
    #[command(after_help = "\
A parked invoice cannot be paid or declined. It is deleted by the next drain or listen once
invoice_expiry_hours have passed since its arrival.")]
    List,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
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
    /// Blocks after which the other party must refuse the slate
    ///
    /// Unpaid by then, the invoice is expired at the next refresh.
    #[arg(long, value_name = "BLOCKS")]
    pub ttl_blocks: Option<u64>,
    #[command(flatten)]
    pub slate_id: SendSlateIdArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct PayArgs {
    /// Invoice slate file, V2 or V3 slate JSON
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
    /// Pay without asking first
    #[arg(long)]
    #[serde(default)]
    pub yes: bool,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum EpicboxCommand {
    /// Stay connected and handle slates as they arrive, until interrupted
    #[command(after_help = "\
Payments of invoices you issued are finalized and posted as they arrive. Every few minutes,
and once at the start, invoices left unpaid for invoice_expiry_hours are expired.")]
    Listen,
    /// Handle every pending slate once, then disconnect
    #[command(after_help = "\
With --listing, the slates waiting at that listing address are handled instead, on a connection
of their own: payments are answered from the listing address and recorded with the listing, a
payment that asks for a payment proof is refused, and the wallet's own address is not touched.")]
    Drain(ListingArgs),
    /// Show the Epicbox relay, the address and the deliveries still pending
    Status(ListingArgs),
}

/// A listing address of this wallet, for a name service.
#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ListingArgs {
    /// The service key of a listing, a compressed secp256k1 key in hex: act on that listing's
    /// address instead of the wallet's own
    #[arg(long, value_name = "SERVICE_KEY")]
    pub listing: Option<String>,
    /// The generation of the listing, raised after each leave
    #[arg(long, default_value_t = 0, requires = "listing")]
    pub generation: u32,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum HttpCommand {
    /// Answer payments sent to this wallet over HTTP, until interrupted
    #[command(after_help = "\
Serves the wallet foreign API at /v2/foreign, as epic-wallet `listen -m http` does: senders
using `send -m http` or `lepic tx send --to http://...` are paid at once. Only payments are
answered, never invoices. Without --internet it listens on 127.0.0.1 only. With --internet it
listens on every interface, for a port forwarded from the internet: anyone who reaches the port
can send the wallet payments. A request may take up to a minute; at most 16 connections are
served at once and 30 payments a minute are taken.

With --coinbase it also answers build_coinbase for a node on this computer, so the node pays its
block rewards to this wallet's default account: set wallet_listener_url in the node's
[server.stratum_mining_config] to http://127.0.0.1:<port>. A node elsewhere can reach it through
a tunnel. With --coinbase-remote and --internet it answers every caller: anyone who reaches the
port gets a reward built, up to the listener's limits.")]
    Listen(HttpListenArgs),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct HttpListenArgs {
    /// Port to listen on, else the configured listen port; 0 lets the system pick one
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,
    /// Listen on every network interface instead of this computer only
    #[arg(long)]
    pub internet: bool,
    /// Also build block rewards for a mining node on this computer
    ///
    /// Behind a local reverse proxy every caller is loopback, so --coinbase then serves every
    /// caller the proxy forwards.
    #[arg(long)]
    pub coinbase: bool,
    /// Build block rewards for a mining node on another computer too
    #[arg(long, requires = "coinbase", requires = "internet")]
    pub coinbase_remote: bool,
}

/// The tor binary the wallet runs for Tor.
#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct TorBinaryArgs {
    /// The tor binary to run, as the Tor Expert Bundle ships it
    #[arg(long, value_name = "PATH")]
    pub tor_binary: Option<PathBuf>,
    /// Directory of the libraries the tor binary needs, put on the library path
    #[arg(long, value_name = "DIR", requires = "tor_binary")]
    pub lib_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum TorCommand {
    /// Show the wallet's onion address, which tor listen publishes
    #[command(after_help = "\
The onion address has its own key from the recovery phrase, so it stays the same after a restore.
It is not the payment-proof address: a payment proof asked for over the onion is signed with the
onion's key, and the onion's address is the receiver address. With --previous, shows the onion
LEPIC 0.3.1 and earlier published, which is the payment-proof address in onion form, as
epic-wallet `address` prints it.")]
    Address(TorAddressArgs),
    /// Answer payments sent to the wallet's onion address over Tor, until interrupted
    #[command(after_help = "\
Runs the tor binary given with --tor-binary for this wallet, with its files in tor/ inside the
data directory, and publishes the wallet's onion address. Payments reach the wallet foreign API
on a listener on 127.0.0.1, which tor forwards the onion to; only payments are answered, never
invoices. The onion address is printed once others can reach it. With --previous-onion, the
onion of LEPIC 0.3.1 and earlier is published too, on its own listener, for senders that still
have it; proofs asked for there are signed with the payment-proof key.")]
    Listen(TorListenArgs),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct TorAddressArgs {
    /// Show the previous onion address, the payment-proof address in onion form
    #[arg(long)]
    pub previous: bool,
    #[command(flatten)]
    #[serde(skip)]
    pub qr: QrArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct TorListenArgs {
    #[command(flatten)]
    pub tor: TorBinaryArgs,
    /// Publish the previous onion address as well
    #[arg(long)]
    pub previous_onion: bool,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum NodeCommand {
    /// Show the node's version and chain tip
    Status,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ProfileCommand {
    /// Show the profile this wallet tells its contacts
    Show,
    /// Tell every paired contact a new profile now
    #[command(after_help = "\
Sends one contact update to each paired contact; `lepic contact collect` takes their answers. \
Set `profile` in the config file too, or later updates tell the configured value again.")]
    Set(ProfileSetArgs),
    /// Show, write or attach the proof of this wallet's domain
    Domain(DomainArgs),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct DomainArgs {
    #[command(subcommand)]
    pub command: DomainCommand,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum DomainCommand {
    /// Show the configured domain and this wallet's domain key
    Show,
    /// Write the well-known file the domain must serve
    #[command(after_help = "\
Serve the file at https://<domain>/.well-known/epic-wallet.json over HTTPS, with no redirect, \
and keep it under 4 KiB. The key comes from the recovery phrase, so a restored wallet keeps it.")]
    File(DomainFileArgs),
    /// Tell paired contacts the configured domain now
    #[command(after_help = "\
Needs the `domain` setting. Pairings made while `domain` is set carry the claim by themselves; \
`attach` is for pairings made before. `lepic contact collect` takes the answers.")]
    Attach,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct DomainFileArgs {
    /// Where to write the file [default: ./epic-wallet.json]
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// A mailbox the file names, as HOST:PORT; repeat for more
    #[arg(long, value_name = "HOST:PORT")]
    pub relay: Vec<String>,
    /// Replace the file when it exists
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ProfileSetArgs {
    /// Bit names: no-payments, automated; "" (an empty value, given explicitly) clears the profile
    #[arg(
        value_name = "NAMES",
        required_unless_present = "bits",
        conflicts_with = "bits"
    )]
    pub names: Option<String>,
    /// The profile as a number 0 to 65535 or 0x hex
    #[arg(long, value_name = "N")]
    pub bits: Option<String>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactArgs {
    #[command(subcommand)]
    pub command: ContactCommand,
    /// Reach no mailbox at all: pairing by hand or in person and sealed files still work
    #[arg(long, global = true)]
    pub offline: bool,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonArgs {
    #[command(subcommand)]
    pub command: InPersonCommand,
    /// Reach no mailbox at all: pairing by hand or in person and sealed files still work
    #[arg(long, global = true)]
    pub offline: bool,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum InPersonCommand {
    /// Make an invoice code to show, for one scan; its answer comes to this wallet's mailbox
    #[command(after_help = "\
The code names no payment proof and is refused after its TTL. Online, `lepic contact collect` \
takes the answers; offline, the code names no mailbox and the payer shows the answer back for \
`lepic in-person take`. Nothing is finalized until `lepic in-person finalize`.")]
    Invoice(InPersonInvoiceArgs),
    /// Make a send code to show, for one scan; its answer comes to this wallet's mailbox
    #[command(after_help = "\
The code names no payment proof and is refused after its TTL. Its inputs stay locked until an \
answer is finalized, the TTL passes or the send is cancelled. Answers are taken and finalized \
as for `lepic in-person invoice`.")]
    Send(InPersonSendArgs),
    /// Show what a scanned code asks, and where its answer goes, before paying or receiving it
    Read(InPersonReadArgs),
    /// Pay a scanned invoice code; the sealed answer is printed and stored for posting
    #[command(after_help = "\
The inputs stay locked until the code's TTL passes or the payment is cancelled. Post the answer \
with `lepic in-person post`, or show it to the payee to take by hand.")]
    Pay(InPersonPayArgs),
    /// Receive a scanned send code; the sealed answer is printed and stored for posting
    #[command(after_help = "\
Post the answer with `lepic in-person post`, or show it to the sender to take by hand. The \
sender finalizes the answer whose check code both screens show.")]
    Receive(InPersonReceiveArgs),
    /// Post the answer to a paid code to the mailbox the code names
    #[command(after_help = "\
Prints the answer's check code once it is posted: show it to the other party, who finalizes the \
answer whose check code both screens show.")]
    Post(InPersonSlateArg),
    /// Take an answer shown back by hand, for a code this wallet showed
    #[command(after_help = "\
An answer is its sealed bytes as hex, its armoured BEGINEPICTX. text, or its UR parts in any \
order.")]
    Take(InPersonTakeArgs),
    /// List the answers to a code this wallet showed, with their check codes
    Answers(InPersonSlateArg),
    /// Finalize one answer to a code this wallet showed and post the transaction
    #[command(after_help = "\
Pick the answer whose check code the other screen shows. A later answer with the same check \
code is flagged by `lepic in-person answers`.")]
    Finalize(InPersonFinalizeArgs),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonInvoiceArgs {
    /// Amount to ask for, in EPIC; the payer adds the fee
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    /// Blocks after which the other party must refuse the slate
    #[arg(long, value_name = "BLOCKS")]
    pub ttl_blocks: Option<u64>,
    #[command(flatten)]
    pub out: OutFileArg,
}

/// A scanned code: its raw bytes as hex, or a file holding them.
#[derive(Debug, Clone, Args, Serialize, Deserialize)]
#[command(group(clap::ArgGroup::new("bytes").required(true).args(["hex", "file"])))]
pub struct InPersonCodeArg {
    /// The payload as hex digits
    #[arg(long, value_name = "HEX")]
    pub hex: Option<String>,
    /// A file whose bytes are the payload
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}

/// A scanned code or an invoice link: the code's raw bytes as hex, a file holding them, or the
/// `epiccash://invoice/1/` link that carries them.
#[derive(Debug, Clone, Args, Serialize, Deserialize)]
#[command(group(clap::ArgGroup::new("bytes").required(true).args(["hex", "file", "link"])))]
pub struct InPersonScanArg {
    /// The payload as hex digits
    #[arg(long, value_name = "HEX")]
    pub hex: Option<String>,
    /// A file whose bytes are the payload
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
    /// An invoice link, epiccash://invoice/1/...
    #[arg(long, value_name = "URL")]
    pub link: Option<String>,
    /// The well-known file of the domain the code is signed for, as fetched, to check the
    /// domain against
    #[arg(long, value_name = "PATH")]
    pub domain_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonReadArgs {
    #[command(flatten)]
    pub code: InPersonScanArg,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub spend: SpendArgs,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonSendArgs {
    /// Amount to send, in EPIC; the fee is added
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub spend: SpendArgs,
    #[command(flatten)]
    pub out: OutFileArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonReceiveArgs {
    #[command(flatten)]
    pub code: InPersonCodeArg,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub out: OutFileArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonPayArgs {
    /// The amount the invoice asks for, in EPIC
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub code: InPersonScanArg,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub spend: SpendArgs,
    #[command(flatten)]
    pub out: OutFileArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonSlateArg {
    /// Slate id of the code, as `in-person invoice`, `send`, `pay` or `receive` printed it
    #[arg(value_name = "SLATE_ID")]
    pub slate_id: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
#[command(group(clap::ArgGroup::new("answer").required(true).args(["input", "file"])))]
pub struct InPersonTakeArgs {
    /// The answer: hex digits, armoured text, or its UR parts
    #[arg(value_name = "ANSWER", num_args = 1..)]
    pub input: Vec<String>,
    /// A file whose bytes are the payload
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct InPersonFinalizeArgs {
    #[command(flatten)]
    pub slate: InPersonSlateArg,
    /// The answer's number, as `in-person answers` lists it
    #[arg(value_name = "ANSWER")]
    pub answer: u32,
    #[command(flatten)]
    pub fluff: FluffArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct Epic1Args {
    #[command(subcommand)]
    pub command: Epic1Command,
    /// Reach no mailbox at all: pairing by hand or in person and sealed files still work
    #[arg(long, global = true)]
    pub offline: bool,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum Epic1Command {
    /// Show the epic1 address of an account
    Address(Epic1AddressArgs),
    /// Make a link: the account's epic1 address, with an amount and a message
    #[command(after_help = "\
The wallet stores nothing for a link, and the same fields give the same link. A payer posts to \
the address's slot on every mailbox of its own list, or to the link's --http-host and --tor hosts \
when it names any. `lepic contact collect` takes the payments and answers them.")]
    Link(Epic1LinkArgs),
    /// Show what an epic1 link asks, and the host of its first `http` or `tor` entry
    Read(Epic1LinkArg),
    /// Pay an epic1 link; `lepic contact collect` finalizes the answer
    #[command(after_help = "\
A link without entries is paid to the address's slot on every mailbox of the wallet's list, \
or on the --mailbox hosts when given. A list without any shipped mailbox is refused with code \
14: the payee reads the shipped ones, so payer and payee need one in common, or the payee's \
given with --mailbox. A link with `http` or `tor` entries is paid on its first entry, and on \
the next when a post fails; it never falls back to the mailbox. The payment carries the link's \
amount and message unless AMOUNT or --message gives others; --message \"\" sends none.")]
    Pay(Epic1PayArgs),
    /// Post a payment again, the same bytes, to the next entry of its link
    PostNext(Epic1PostNextArgs),
    /// List the answers this wallet made for payments taken at its links
    Answers,
    /// After a restore from the phrase, read the slot of each account's address on each mailbox once
    Restore,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct Epic1AddressArgs {
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    #[serde(skip)]
    pub qr: QrArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct Epic1LinkArgs {
    #[command(flatten)]
    pub account: AccountArg,
    /// Amount to ask for, in EPIC [default: the payer chooses]
    #[arg(value_name = "AMOUNT")]
    pub amount: Option<String>,
    #[command(flatten)]
    pub message: MessageArg,
    /// An http host the payment is posted to, `host[:port]`; with --tor, up to three
    #[arg(long = "http-host", value_name = "HOST")]
    pub http: Vec<String>,
    /// An onion the payment is posted to, `name.onion[:port]`; with --http-host, up to three
    #[arg(long, value_name = "ONION")]
    pub tor: Vec<String>,
    #[command(flatten)]
    #[serde(skip)]
    pub qr: QrArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct Epic1LinkArg {
    /// The link, `epic:epic1…`
    #[arg(value_name = "LINK")]
    pub link: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct Epic1PayArgs {
    #[command(flatten)]
    pub link: Epic1LinkArg,
    /// Amount to pay, in EPIC [default: the amount the link asks]
    #[arg(value_name = "AMOUNT")]
    pub amount: Option<String>,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub spend: SpendArgs,
    #[command(flatten)]
    pub slate_id: SendSlateIdArg,
    #[command(flatten)]
    pub mailboxes: PayMailboxesArg,
}

/// The mailboxes one epic1 payment goes through in place of the wallet's list.
#[derive(Debug, Clone, Default, Args, Serialize, Deserialize)]
pub struct PayMailboxesArg {
    /// A mailbox the payment goes through in place of the wallet's list, `host[:port]`, such
    /// as the payee's; repeat for more
    #[arg(long = "mailbox", value_name = "HOST")]
    pub mailboxes: Vec<String>,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum MailboxCommand {
    /// List the mailboxes, where each comes from, and how its sessions last went
    #[command(after_help = "\
The command connects nowhere: health is what this process saw. Run on its own it shows not tried \
for every mailbox; while `lepic serve` runs it shows what serve's sessions saw.")]
    List,
    /// Test a mailbox, then add it to the list
    #[command(after_help = "\
A mailbox whose test fails is not added unless --anyway is given. A shipped mailbox that was \
removed comes back as shipped.")]
    Add(MailboxAddArgs),
    /// Remove a mailbox from the list; the last one stays
    Remove(MailboxHostArg),
    /// Test a mailbox: its TLS, its greeting and whether it offers push; changes nothing
    #[command(after_help = "\
The report is printed either way. The exit code is 10 when a step failed, 0 when all passed.")]
    Probe(MailboxHostArg),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct MailboxHostArg {
    /// The mailbox, `host` or `host:port`
    #[arg(value_name = "HOST")]
    pub host: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct MailboxAddArgs {
    #[command(flatten)]
    pub host: MailboxHostArg,
    /// Add the mailbox even when its test fails
    #[arg(long)]
    pub anyway: bool,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct Epic1PostNextArgs {
    /// Slate id of the payment, as `epic1 pay` printed it
    #[arg(value_name = "SLATE_ID")]
    pub slate_id: String,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum EpictxCommand {
    /// Open an .epictx file with this wallet's keys and print its slate as JSON; nothing is
    /// stored
    #[command(after_help = "\
A lepic.v1 slate is shown field by field, with its network, kernel features, header version and \
tail; any other slate as its V3 JSON.")]
    Open(EpictxOpenArgs),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct EpictxOpenArgs {
    /// The .epictx file, or - to read the text from standard input
    #[arg(value_name = "FILE|-")]
    pub input: String,
    /// The file's text, read instead of `input`; set by the API, never on the command line.
    #[arg(skip)]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ContactCommand {
    /// Make an invite to pair with a contact, as a link to share
    #[command(after_help = "\
The invite's slots live on this wallet's mailbox. `lepic contact collect` takes the answer.")]
    Invite(ContactInviteArgs),
    /// Show what an invite link says, before answering it
    Open(ContactLinkArg),
    /// Answer an invite; the reply goes to the inviter's mailbox unless --by-hand
    Accept(ContactAcceptArgs),
    /// Take a pair-reply or pair-confirm link that was sent by hand
    Enter(ContactEnterArgs),
    /// Fetch pairing and contact messages from the home mailboxes once, and send what waits
    Collect,
    /// Record the check of the four SAS words against the other screen
    Sas(ContactSasArgs),
    /// List the paired contacts
    List,
    /// Remove a pairing; the contact is not told
    Remove(ContactIdArg),
    /// Give a contact your own name for it
    Label(ContactLabelArgs),
    /// Move to the mailbox a contact asked for; `contact list` shows the request
    Move(ContactMoveArgs),
    /// Move your own home mailbox for every paired contact; each is told once, and the old
    /// slots are read for `--drain-days`
    MoveHome(ContactMoveHomeArgs),
    /// Ask a paired contact to answer with its current card; `contact collect` takes the answer
    Check(ContactIdArg),
    /// Allow or stop invoices from a verified contact
    AllowInvoices(ContactSwitchArgs),
    /// Invoice a paired contact through its mailbox
    Invoice(ContactInvoiceArgs),
    /// List the invoices parked from contacts
    Invoices,
    /// Pay an invoice parked from a contact
    PayInvoice(ContactPayArgs),
    /// Decline an invoice parked from a contact; the contact is told
    Decline(ContactSlateIdArg),
    /// Write the pairing records to a file, for a backup
    Export(ContactExportArgs),
    /// Restore pairing records from a backup file
    Import(ContactImportArgs),
    /// Ask whether a new pairing's contact still holds the keys of an older pairing
    #[command(after_help = "\
For a contact paired again, for example after a restore. `lepic contact collect` takes the \
answer: the keys are back and the new pairing goes, or the new pairing shows keys-changed.")]
    KeyCheck(ContactKeyCheckArgs),
    /// Keep the old keys or use the new ones for a pairing in keys-changed
    Keys(ContactKeysArgs),
    /// Seal a transaction's slate to a paired contact, as text for a file or a paste
    Seal(ContactSealArgs),
    /// Open sealed text and act on its slate: receive an S1, pay an I1 with --amount, or
    /// finalize an S2 or I2; the answer is sealed back on the same channel
    OpenSealed(ContactOpenSealedArgs),
    /// Send a transaction's slate sealed through the contact's mailbox, for example a withdrawal
    SendSlate(ContactSendSlateArgs),
    /// Send, list and acknowledge the host app's payloads to and from paired contacts
    #[command(after_help = "\
LEPIC never reads the bytes. `lepic contact collect`, or `lepic serve` on its own, takes arriving \
payloads; they wait in `contact payload list` until acknowledged.")]
    Payload(ContactPayloadArgs),
    /// List the contact messages kept in quarantine; the host app retries and discards them
    Quarantine,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactPayloadArgs {
    #[command(subcommand)]
    pub command: ContactPayloadCommand,
}

#[derive(Debug, Clone, Subcommand, Serialize, Deserialize)]
pub enum ContactPayloadCommand {
    /// Send bytes to a paired contact through its mailbox; prints the payload's id
    Post(ContactPayloadPostArgs),
    /// List the payloads that arrived and are not acknowledged, oldest first
    List,
    /// Forget payloads once their bytes are kept elsewhere; prints how many were forgotten
    Ack(ContactPayloadAckArgs),
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
#[command(group(clap::ArgGroup::new("bytes").required(true).args(["hex", "file"])))]
pub struct ContactPayloadPostArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    /// The payload as hex digits
    #[arg(long, value_name = "HEX")]
    pub hex: Option<String>,
    /// A file whose bytes are the payload
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactPayloadAckArgs {
    /// Payload ids, as `contact payload list` shows them
    #[arg(value_name = "ID", required = true, num_args = 1..)]
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum InviteExpiryArg {
    #[value(name = "1h")]
    #[serde(rename = "1h")]
    Hour,
    #[default]
    #[value(name = "24h")]
    #[serde(rename = "24h")]
    Day,
    #[value(name = "7d")]
    #[serde(rename = "7d")]
    Week,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ContactKindArg {
    Person,
    Shop,
    Exchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SasArg {
    Match,
    Mismatch,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeysArg {
    /// Keep the old pairing; the new one is deleted
    KeepOld,
    /// Use the new pairing, not verified; the old one is deleted
    UseNew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum OnOffArg {
    On,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum PurposeArg {
    Payment,
    Deposit,
    Withdrawal,
    Refund,
    Request,
}

/// The name a wallet gives itself in its card and its invites.
pub const DEFAULT_CONTACT_NAME: &str = "LEPIC";

/// The most days `contact move-home` keeps reading the old mailboxes.
pub const MAX_DRAIN_DAYS: i64 = 365;

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactNameArg {
    /// The name this wallet gives itself in its card
    #[arg(long, value_name = "NAME", default_value = DEFAULT_CONTACT_NAME)]
    pub name: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactInviteArgs {
    #[command(flatten)]
    pub name: ContactNameArg,
    /// How long the invite may be answered
    #[arg(long, value_enum, default_value_t)]
    pub expiry: InviteExpiryArg,
    /// Deprecated and ignored: new pairings write person
    #[arg(long, value_enum, hide = true)]
    pub kind: Option<ContactKindArg>,
    #[command(flatten)]
    #[serde(skip)]
    pub qr: QrArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactLinkArg {
    /// The epiccash:// link
    #[arg(value_name = "LINK")]
    pub link: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactEnterArgs {
    /// The epiccash:// link
    #[arg(value_name = "LINK")]
    pub input: String,
    #[command(flatten)]
    #[serde(skip)]
    pub qr: QrArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactKeyCheckArgs {
    /// The new pairing's id, as `contact list` shows it
    #[arg(value_name = "NEW")]
    pub new: String,
    /// The older pairing with the same contact
    #[arg(value_name = "OLD")]
    pub old: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactKeysArgs {
    /// The new pairing's id, in keys-changed
    #[arg(value_name = "NEW")]
    pub new: String,
    #[arg(value_enum, value_name = "CHOICE")]
    pub choice: KeysArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct OutFileArg {
    /// Write to this file instead of printing
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactSendSlateArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    #[command(flatten)]
    pub tx: TxIdArgs,
    /// What the slate is for
    #[arg(long, value_enum)]
    pub purpose: Option<PurposeArg>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactSealArgs {
    #[command(flatten)]
    pub slate: ContactSendSlateArgs,
    #[command(flatten)]
    pub out: OutFileArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactOpenSealedArgs {
    /// The sealed file, or - to read the text from standard input
    #[arg(value_name = "FILE|-")]
    pub input: String,
    /// The amount an invoice asks for, in EPIC; given, the invoice is paid
    #[arg(long, value_name = "AMOUNT")]
    pub amount: Option<String>,
    /// Where the answer goes [default: <FILE>.response; printed for -]
    #[arg(long, value_name = "FILE")]
    pub answer_file: Option<PathBuf>,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub spend: SpendArgs,
    #[command(flatten)]
    pub fluff: FluffArg,
    /// Pay without asking first
    #[arg(long)]
    #[serde(default)]
    pub yes: bool,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactAcceptArgs {
    #[command(flatten)]
    pub link: ContactLinkArg,
    #[command(flatten)]
    pub name: ContactNameArg,
    /// Print the reply link to send by hand instead of posting it
    #[arg(long)]
    pub by_hand: bool,
    #[command(flatten)]
    #[serde(skip)]
    pub qr: QrArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactIdArg {
    /// The contact's id, as `contact list` shows it
    #[arg(value_name = "CONTACT")]
    pub contact: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactLabelArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    /// Your name for the contact
    #[arg(value_name = "LABEL")]
    pub label: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactMoveArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    /// The mailbox host the contact asked for, as `contact list` shows it
    #[arg(long = "apply", value_name = "HOST")]
    pub apply: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactMoveHomeArgs {
    /// The mailbox to move to, `domain[:port]`; set it as the wallet's Epicbox relay too
    #[arg(value_name = "HOST")]
    pub host: String,
    /// Days to keep reading the old mailboxes, 0 to 365; a check there is answered with the
    /// new mailbox
    #[arg(
        long = "drain-days",
        value_name = "N",
        default_value_t = 0,
        value_parser = clap::value_parser!(u16).range(0..=MAX_DRAIN_DAYS)
    )]
    pub drain_days: u16,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactSasArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    #[arg(value_enum, value_name = "RESULT")]
    pub result: SasArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactSwitchArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    #[arg(value_enum, value_name = "STATE")]
    pub state: OnOffArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactInvoiceArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    /// The amount to ask for, in EPIC
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    /// What the slate is for
    #[arg(long, value_enum, default_value_t = PurposeArg::Request)]
    pub purpose: PurposeArg,
    /// A reference the contact sees with the invoice
    #[arg(long, value_name = "TEXT")]
    pub reference: Option<String>,
    #[command(flatten)]
    pub message: MessageArg,
    /// Blocks after which the other party must refuse the slate
    ///
    /// Unpaid by then, the invoice is expired at the next refresh.
    #[arg(long, value_name = "BLOCKS")]
    pub ttl_blocks: Option<u64>,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub slate_id: SendSlateIdArg,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactPayArgs {
    /// Slate id of the invoice, as `contact invoices` shows it
    #[arg(value_name = "SLATE_ID")]
    pub slate_id: String,
    /// The amount the invoice asks for, in EPIC
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
    #[command(flatten)]
    pub account: AccountArg,
    #[command(flatten)]
    pub message: MessageArg,
    #[command(flatten)]
    pub spend: SpendArgs,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactSlateIdArg {
    /// Slate id of the invoice, as `contact invoices` shows it
    #[arg(value_name = "SLATE_ID")]
    pub slate_id: String,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactExportArgs {
    /// The file to write
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct ContactImportArgs {
    /// A file `contact export` wrote
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}
