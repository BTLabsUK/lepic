// SPDX-License-Identifier: Apache-2.0
//! The command tree. Nouns, then verbs. Global options are the only options shared by every
//! command; an option name keeps one meaning wherever it appears (`tests/command_tree.rs`).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// Chain the wallet is on [env: LEPIC_NETWORK] [default: mainnet]
    #[arg(long, global = true, value_name = "NETWORK")]
    pub network: Option<NetworkArg>,
    /// Config file [env: LEPIC_CONFIG] [default: ~/.lepic/config.toml when it exists]
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Settings file with the servers [env: LEPIC_SETTINGS] [default: ~/.lepic/settings.toml,
    /// written on first use]
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
    /// Run the command on the `lepic serve` process listening at SOCKET [default: lepic.sock in
    /// the data directory]
    #[arg(
        long,
        global = true,
        value_name = "SOCKET",
        num_args = 0..=1,
        require_equals = true
    )]
    pub service: Option<Option<PathBuf>>,
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
    /// Pair with contacts, and exchange invoices and slates with them through their mailboxes
    Contact(ContactArgs),
    /// Hold the wallet open and answer commands sent with --service
    #[command(after_help = SERVE_HELP)]
    Serve(ServeArgs),
}

const SERVE_HELP: &str = "\
Opens the wallet once, as other commands do, and holds the data directory until it stops. It
listens on Epicbox, expires unpaid invoices, collects contact mailboxes and refreshes the wallet
while it runs, and answers other lepic commands on a local socket: run them with `lepic
--service=SOCKET <command>`, or `lepic --service <command>` for the default socket. Only the
user that runs it can use the socket. Ctrl-C or SIGTERM stops it.";

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ServeArgs {
    #[command(subcommand)]
    pub command: Option<ServeCommand>,
    /// Unix socket to listen on [default: lepic.sock in the data directory]
    #[arg(long, value_name = "SOCKET")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ServeCommand {
    /// Show how the running serve's refreshes and contact collects went
    #[command(after_help = "\
Answers only through a running serve: `lepic --service serve status`. For the wallet refresh and
the contact collect it shows the failures since the last success, the last error and when the
task last succeeded. serve only reports them; it keeps retrying every minute.")]
    Status,
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
    /// Import the transaction history of the epic-wallet wallet this one was made from
    #[command(after_help = IMPORT_HISTORY_HELP)]
    ImportHistory(ImportHistoryArgs),
}

const IMPORT_HISTORY_HELP: &str = "\
DIR is the old wallet's folder (the one holding wallet_data) or its wallet_data folder. Its
database is copied and read from the copy; nothing in DIR is changed. Run it after
`wallet import-seed` or `wallet restore` with the same seed, before or after the scan. Funds
and balances still come from the scan.";

#[derive(Debug, Args)]
pub struct ImportHistoryArgs {
    /// The old wallet's folder
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
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
    /// Start the restore scan at this block height instead of genesis; outputs below it are
    /// not found
    #[arg(long, value_name = "HEIGHT")]
    pub from_height: Option<u64>,
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
its change is back in the balance. Later, a refresh finds it by its change.")]
    Release(TxIdArgs),
    /// List the transactions of an account
    List(ListArgs),
    /// Show one transaction
    Show(TxShowArgs),
}

const SEND_HTTP_HELP: &str = "\
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
queued in its mailbox, then posted at once when the relay answers; `lepic contact collect` posts
what is still queued and takes the answer. A send the contact cannot take locks nothing, and one
that cannot be queued is cancelled.";

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Amount in EPIC, for example 1.5
    #[arg(value_name = "AMOUNT")]
    pub amount: String,
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
}

/// The slate id a caller gives a send so that sending again cannot pay twice.
#[derive(Debug, Args)]
pub struct SendSlateIdArg {
    /// Slate id of the send: a random version-4 UUID the caller stores before sending
    #[arg(long, value_name = "SLATE_ID")]
    pub slate_id: Option<String>,
}

/// How a payment chooses and spends its inputs.
#[derive(Debug, Args)]
pub struct SpendArgs {
    /// Confirmations an output needs before it is spent
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = lepic_wallet::selection::SelectionOptions::DEFAULT_MINIMUM_CONFIRMATIONS
    )]
    pub min_confirmations: u64,
    /// Outputs the change is split into
    #[arg(long, value_name = "COUNT", default_value_t = 1)]
    pub change_outputs: usize,
    /// How inputs are chosen
    #[arg(long, value_name = "STRATEGY", default_value = "smallest")]
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

/// Where a send goes: the destinations of [`DestinationArgs`], or a paired contact.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct SendDestinationArgs {
    /// Epicbox address the slate goes to, or for a send the http(s):// or onion address of a
    /// listening wallet
    #[arg(long, value_name = "ADDRESS")]
    pub to: Option<String>,
    /// Write the slate to this file, as V3 slate JSON
    #[arg(long, value_name = "FILE")]
    pub to_file: Option<PathBuf>,
    /// Pay a paired contact through its mailbox
    #[arg(long, value_name = "CONTACT_ID")]
    pub to_contact: Option<String>,
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
    /// Spend every eligible output, which locks the whole balance until the send confirms
    All,
    /// Spend the fewest small outputs that cover the amount, as `epic-wallet send` does by
    /// default
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
pub struct TxShowArgs {
    /// Local transaction id, as `tx list` shows it
    #[arg(value_name = "TX_ID", required_unless_present = "slate_id")]
    pub tx_id: Option<u32>,
    #[command(flatten)]
    pub slate_id: SendSlateIdArg,
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
    /// Ask a payer for an amount over Epicbox or through a slate file
    #[command(after_help = "\
Over Epicbox a LEPIC payer takes invoices only from a paired contact that it allowed to send
them: invoice such a contact with `lepic contact invoice`. An invoice sent here to an Epicbox
address goes to the payer's payments address, where other wallets send it back unpaid. A
payment comes back to your address, and `lepic epicbox listen` or `lepic epicbox drain`
finalizes and posts it. An invoice left unpaid for invoice_expiry_hours is cancelled by the
next listen or drain.")]
    Issue(IssueArgs),
    /// Pay a parked invoice, or an invoice slate file
    #[command(after_help = "\
The payer types the amount again; an invoice for any other amount is refused. A parked invoice
is paid over Epicbox to its sender. For a slate file the reply is
written next to it, and the issuer runs `lepic tx finalize` on it. A file whose name is a slate
id is given with a directory, as in ./<SLATE_ID>.")]
    Pay(PayArgs),
    /// List the parked invoices, waiting to be paid or declined
    #[command(after_help = "\
An invoice not paid within invoice_expiry_hours of its arrival is deleted by the next drain or
listen.")]
    List,
    /// Decline a parked invoice, so it is never paid
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
and once at the start, invoices left unpaid for invoice_expiry_hours are expired.")]
    Listen,
    /// Handle every pending slate once, then disconnect
    #[command(after_help = "\
With --listing, the slates waiting at that listing address are handled instead, on a connection
of their own: payments are answered from the listing address and recorded with the listing, a
payment that asks for a payment proof is refused, and the wallet's own address is not touched.")]
    Drain(ListingArgs),
    /// Show the relay, the address and the deliveries still pending
    Status(ListingArgs),
    /// Show whether a peer is known to pay invoices
    #[command(after_help = "\
What this wallet learned from the peer's own messages over Epicbox, matched on the key: lepic
while its last payment or notice carried the LEPIC marker, no_invoices once a slate came
without it or an invoice came back unpaid, unknown before either. Nothing is sent.")]
    Peer(PeerArgs),
}

/// A listing address of this wallet, for a directory.
#[derive(Debug, Args)]
pub struct ListingArgs {
    /// The directory key of a listing, a compressed secp256k1 key in hex: act on that listing's
    /// address instead of the wallet's own
    #[arg(long, value_name = "DKEY")]
    pub listing: Option<String>,
    /// The generation of the listing, raised after each leave
    #[arg(long, default_value_t = 0, requires = "listing")]
    pub generation: u32,
}

#[derive(Debug, Args)]
pub struct PeerArgs {
    /// Full Epicbox address of the peer
    #[arg(value_name = "ADDRESS")]
    pub address: String,
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
    /// Port to listen on, else the configured listen port; 0 lets the system pick one
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,
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
on a listener on 127.0.0.1, which tor forwards the onion to; only payments are answered, never
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

#[derive(Debug, Args)]
pub struct ContactArgs {
    #[command(subcommand)]
    pub command: ContactCommand,
    /// Reach no relay at all: pairing by hand or in person and sealed files still work
    #[arg(long, global = true)]
    pub offline: bool,
    /// Treat Epicbox as switched off: no relay connections, contact mailboxes pause
    #[arg(long, global = true, conflicts_with = "offline")]
    pub epicbox_off: bool,
}

#[derive(Debug, Subcommand)]
pub enum ContactCommand {
    /// Make an invite to pair with a contact, as a link to share
    #[command(after_help = "\
The invite's mailboxes live on this wallet's relay. `lepic contact collect` takes the answer.")]
    Invite(ContactInviteArgs),
    /// Ask a wallet that paid or was paid lately to pair, at its payments address
    #[command(after_help = "\
Sent only to a key that ran LEPIC within 30 days, answered nothing without the marker since and \
claims pair requests. `lepic contact collect` takes the answer.")]
    Request(ContactRequestArgs),
    /// Show what an invite link says, before answering it
    Open(ContactLinkArg),
    /// Answer an invite; the reply goes to the inviter's relay unless --by-hand
    Accept(ContactAcceptArgs),
    /// Take a pair-reply or pair-confirm link that was sent by hand, or find an invite by its
    /// five pairing words
    #[command(after_help = "\
Words are typed by name, or pasted as emoji. The invite they find is printed as a link to answer \
with `lepic contact accept`.")]
    Enter(ContactEnterArgs),
    /// Fetch pairing and contact messages from the home relays once, and send what waits
    Collect,
    /// Record the check of the four SAS words against the other screen
    Sas(ContactSasArgs),
    /// Show a card to pair in person; the other phone scans it
    ShowCard(ContactCardArgs),
    /// Pair in person with the card the other phone shows
    ScanCard(ContactScanArgs),
    /// List the paired contacts
    List,
    /// Remove a pairing; the contact is not told
    Remove(ContactIdArg),
    /// Give a contact your own name for it
    Label(ContactLabelArgs),
    /// Move to the relay a contact asked for; `contact list` shows the request
    Move(ContactMoveArgs),
    /// Move your own home relay for every paired contact; each is told once and the old
    /// mailboxes are not read again
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
    /// Write a transaction's slate plain, for a contact that cannot open sealed text
    Plain(ContactPlainArgs),
    /// Send, list and acknowledge the host app's payloads to and from paired contacts
    #[command(after_help = "\
LEPIC never reads the bytes. `lepic contact collect`, or `lepic serve` on its own, takes arriving \
payloads; they wait in `contact payload list` until acknowledged.")]
    Payload(ContactPayloadArgs),
}

#[derive(Debug, Args)]
pub struct ContactPayloadArgs {
    #[command(subcommand)]
    pub command: ContactPayloadCommand,
}

#[derive(Debug, Subcommand)]
pub enum ContactPayloadCommand {
    /// Send bytes to a paired contact through its mailbox; prints the payload's id
    Post(ContactPayloadPostArgs),
    /// List the payloads that arrived and are not acknowledged, oldest first
    List,
    /// Forget payloads once their bytes are kept elsewhere; prints how many were forgotten
    Ack(ContactPayloadAckArgs),
}

#[derive(Debug, Args)]
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

#[derive(Debug, Args)]
pub struct ContactPayloadAckArgs {
    /// Payload ids, as `contact payload list` shows them
    #[arg(value_name = "ID", required = true, num_args = 1..)]
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InviteExpiryArg {
    #[value(name = "1h")]
    Hour,
    #[value(name = "24h")]
    Day,
    #[value(name = "7d")]
    Week,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ContactKindArg {
    Person,
    Shop,
    Exchange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SasArg {
    Match,
    Mismatch,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeysArg {
    /// Keep the old pairing; the new one is deleted
    KeepOld,
    /// Use the new pairing, not verified; the old one is deleted
    UseNew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OnOffArg {
    On,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PurposeArg {
    Payment,
    Deposit,
    Withdrawal,
    Refund,
    Request,
}

#[derive(Debug, Args)]
pub struct ContactNameArg {
    /// The name this wallet gives itself in its card
    #[arg(long, value_name = "NAME", default_value = "LEPIC")]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct ContactInviteArgs {
    #[command(flatten)]
    pub name: ContactNameArg,
    /// How long the invite may be answered
    #[arg(long, value_enum, default_value_t = InviteExpiryArg::Day)]
    pub expiry: InviteExpiryArg,
    /// What this wallet is to the contact
    #[arg(long, value_enum, default_value_t = ContactKindArg::Person)]
    pub kind: ContactKindArg,
    /// Also offer five pairing words that find the invite
    #[arg(long)]
    pub pairing_words: bool,
}

#[derive(Debug, Args)]
pub struct ContactRequestArgs {
    /// The wallet's Epicbox address
    #[arg(value_name = "ADDRESS")]
    pub address: String,
    #[command(flatten)]
    pub name: ContactNameArg,
}

#[derive(Debug, Args)]
pub struct ContactLinkArg {
    /// The epiccash:// link
    #[arg(value_name = "LINK")]
    pub link: String,
}

#[derive(Debug, Args)]
pub struct ContactEnterArgs {
    /// The epiccash:// link, or the five pairing words
    #[arg(value_name = "LINK|WORDS", required = true, num_args = 1..=5)]
    pub input: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ContactKeyCheckArgs {
    /// The new pairing's id, as `contact list` shows it
    #[arg(value_name = "NEW")]
    pub new: String,
    /// The older pairing with the same contact
    #[arg(value_name = "OLD")]
    pub old: String,
}

#[derive(Debug, Args)]
pub struct ContactKeysArgs {
    /// The new pairing's id, in keys-changed
    #[arg(value_name = "NEW")]
    pub new: String,
    #[arg(value_enum, value_name = "CHOICE")]
    pub choice: KeysArg,
}

#[derive(Debug, Args)]
pub struct OutFileArg {
    /// Write to this file instead of printing
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ContactSendSlateArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    #[command(flatten)]
    pub tx: TxIdArgs,
    /// What the slate is for
    #[arg(long, value_enum)]
    pub purpose: Option<PurposeArg>,
}

#[derive(Debug, Args)]
pub struct ContactSealArgs {
    #[command(flatten)]
    pub slate: ContactSendSlateArgs,
    #[command(flatten)]
    pub out: OutFileArg,
}

#[derive(Debug, Args)]
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
}

#[derive(Debug, Args)]
pub struct ContactPlainArgs {
    #[command(flatten)]
    pub tx: TxIdArgs,
    #[command(flatten)]
    pub out: OutFileArg,
}

#[derive(Debug, Args)]
pub struct ContactAcceptArgs {
    #[command(flatten)]
    pub link: ContactLinkArg,
    #[command(flatten)]
    pub name: ContactNameArg,
    /// Print the reply link to send by hand instead of posting it
    #[arg(long)]
    pub by_hand: bool,
}

#[derive(Debug, Args)]
pub struct ContactIdArg {
    /// The contact's id, as `contact list` shows it
    #[arg(value_name = "CONTACT")]
    pub contact: String,
}

#[derive(Debug, Args)]
pub struct ContactLabelArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    /// Your name for the contact
    #[arg(value_name = "LABEL")]
    pub label: String,
}

#[derive(Debug, Args)]
pub struct ContactMoveArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    /// The relay host the contact asked for, as `contact list` shows it
    #[arg(long = "apply", value_name = "HOST")]
    pub apply: String,
}

#[derive(Debug, Args)]
pub struct ContactMoveHomeArgs {
    /// The relay to move to, `domain[:port]`; set it as the wallet's Epicbox relay too
    #[arg(value_name = "HOST")]
    pub host: String,
}

#[derive(Debug, Args)]
pub struct ContactSasArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    #[arg(value_enum, value_name = "RESULT")]
    pub result: SasArg,
}

#[derive(Debug, Args)]
pub struct ContactCardArgs {
    #[command(flatten)]
    pub name: ContactNameArg,
    /// What this wallet is to the contact
    #[arg(long, value_enum, default_value_t = ContactKindArg::Person)]
    pub kind: ContactKindArg,
}

#[derive(Debug, Args)]
pub struct ContactScanArgs {
    /// The id `contact show-card` printed on this wallet
    #[command(flatten)]
    pub contact: ContactIdArg,
    /// The other phone's epiccash://contact/ link
    #[arg(value_name = "LINK")]
    pub link: String,
}

#[derive(Debug, Args)]
pub struct ContactSwitchArgs {
    #[command(flatten)]
    pub contact: ContactIdArg,
    #[arg(value_enum, value_name = "STATE")]
    pub state: OnOffArg,
}

#[derive(Debug, Args)]
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
    pub account: AccountArg,
}

#[derive(Debug, Args)]
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

#[derive(Debug, Args)]
pub struct ContactSlateIdArg {
    /// Slate id of the invoice, as `contact invoices` shows it
    #[arg(value_name = "SLATE_ID")]
    pub slate_id: String,
}

#[derive(Debug, Args)]
pub struct ContactExportArgs {
    /// The file to write
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

#[derive(Debug, Args)]
pub struct ContactImportArgs {
    /// A file `contact export` wrote
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}
