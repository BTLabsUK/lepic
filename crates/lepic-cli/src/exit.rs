// SPDX-License-Identifier: Apache-2.0
//! Typed command failures and the exit codes they map to. The codes are part of the CLI's
//! interface: scripts branch on them, so a code never changes meaning.

use lepic_node::NodeError;
use lepic_store::StoreError;
use lepic_telemetry::TelemetryError;
use lepic_transport::error::TransportError;
use lepic_wallet::error_text::display_error_chain;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::refresh::RefreshError;
use lepic_wallet::scan::ScanError;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::self_send::SelfSendError;
use lepic_wallet::send::SendError;
use lepic_wallet::{AccountError, ReceiveError, WalletError};
use lepic_wallet_contacts::{ContactEncodeError, ContactError, Epic1Refusal, InPersonRefusal};
use thiserror::Error;

use crate::amount::AmountError;
use crate::secret::SecretError;
use crate::settings::SettingsError;

/// What kind of failure ended a command. [`ErrorKind::exit_code`] is the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Internal,
    Usage,
    Config,
    WrongPassword,
    WalletState,
    NotFound,
    Rejected,
    InsufficientFunds,
    Node,
    Transport,
    Incomplete,
    Interrupted,
    SlateTooLarge,
    NoSharedMailbox,
    NotDelivered,
    EarlierAddress,
}

impl ErrorKind {
    pub const ALL: [Self; 16] = [
        Self::Internal,
        Self::Usage,
        Self::Config,
        Self::WrongPassword,
        Self::WalletState,
        Self::NotFound,
        Self::Rejected,
        Self::InsufficientFunds,
        Self::Node,
        Self::Transport,
        Self::Incomplete,
        Self::Interrupted,
        Self::SlateTooLarge,
        Self::NoSharedMailbox,
        Self::NotDelivered,
        Self::EarlierAddress,
    ];

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Internal => 1,
            Self::Usage => 2,
            Self::Config => 3,
            Self::WrongPassword => 4,
            Self::WalletState => 5,
            Self::NotFound => 6,
            Self::Rejected => 7,
            Self::InsufficientFunds => 8,
            Self::Node => 9,
            Self::Transport => 10,
            Self::Incomplete => 11,
            Self::Interrupted => 12,
            Self::SlateTooLarge => 13,
            Self::NoSharedMailbox => 14,
            Self::NotDelivered => 15,
            Self::EarlierAddress => 16,
        }
    }

    /// The kind whose [`ErrorKind::name`] is `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// The `kind` field of a JSON error.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Usage => "usage",
            Self::Config => "config",
            Self::WrongPassword => "wrong_password",
            Self::WalletState => "wallet_state",
            Self::NotFound => "not_found",
            Self::Rejected => "rejected",
            Self::InsufficientFunds => "insufficient_funds",
            Self::Node => "node",
            Self::Transport => "transport",
            Self::Incomplete => "incomplete",
            Self::Interrupted => "interrupted",
            Self::SlateTooLarge => "slate_too_large",
            Self::NoSharedMailbox => "no_shared_mailbox",
            Self::NotDelivered => "not_delivered",
            Self::EarlierAddress => "earlier_address",
        }
    }
}

/// `lepic --help` lists the codes; `exit_codes_help_lists_every_kind` keeps it complete.
pub const EXIT_CODES_HELP: &str = "\
Exit codes:
   0  success
   1  internal: an unexpected failure, see the log
   2  usage: invalid arguments or missing input
   3  config: invalid settings or config file
   4  wrong_password: the password did not unlock the wallet
   5  wallet_state: no wallet, a wallet already exists, it is in use, or it belongs elsewhere
   6  not_found: no such transaction, slate or account
   7  rejected: the slate or request was refused; nothing was stored
   8  insufficient_funds: not enough spendable funds
   9  node: the node could not be reached or answered badly
  10  transport: the slate file, the mailbox or the http listener failed, or a mailbox failed its probe
  11  incomplete: stored, but not delivered or not posted; retry
  12  interrupted: stopped before it finished
  13  slate_too_large: the slate holds more inputs and outputs than the mailbox takes; nothing was stored
  14  no_shared_mailbox: the wallet's mailboxes hold none the payee reads; nothing was sent
  15  not_delivered: the payment is stored, but no mailbox took it yet; the outbox keeps trying
  16  earlier_address: an epic1 address or link of an earlier release, which this version cannot read";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CliError {
    /// The command line did not parse; the text is clap's own message.
    #[error("{0}")]
    Arguments(String),
    #[error("settings are invalid")]
    Settings(#[from] SettingsError),
    #[error("secret input failed")]
    Secret(#[from] SecretError),
    #[error("amount rejected")]
    Amount(#[from] AmountError),
    #[error("{what} must be at least 1")]
    Zero { what: &'static str },
    #[error(transparent)]
    MailboxChange(#[from] crate::settings_file::MailboxChangeError),
    /// `mailbox add` tested the mailbox and a step failed.
    #[error("mailbox {host} failed its test; `--anyway` adds it all the same\n{probe}")]
    MailboxUntested { host: String, probe: String },
    #[error("logging could not be set up")]
    Telemetry(#[from] TelemetryError),
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("send failed")]
    Send(#[from] SendError),
    #[error("receive failed")]
    Receive(#[from] ReceiveError),
    #[error("finalize failed")]
    Finalize(#[from] FinalizeError),
    /// A failure of a send to the wallet itself that is none of a send's, receive's or
    /// finalize's.
    #[error("self-send failed")]
    SelfSend(#[source] SelfSendError),
    #[error("invoice failed")]
    Invoice(#[from] InvoiceError),
    #[error("epicbox failed")]
    Inbox(#[from] InboxError),
    #[error("refresh failed")]
    Refresh(#[from] RefreshError),
    #[error("scan failed")]
    Scan(#[from] ScanError),
    #[error("node request failed")]
    Node(#[from] NodeError),
    #[error("slate file failed")]
    Transport(#[from] TransportError),
    #[error("slate file {}", path.display())]
    SlateFile {
        path: std::path::PathBuf,
        #[source]
        source: TransportError,
    },
    #[error("wallet database failed")]
    Store(#[from] StoreError),
    #[error("give --to or --to-file")]
    NoDestination,
    #[error("the link asks no amount: give the amount to pay")]
    Epic1Amount,
    #[error("slate id is not of the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")]
    SlateId,
    #[error("--slate-id must be a random version-4 uuid, made for this send")]
    NotRandomSlateId,
    #[error(
        "slate id belongs to transaction {tx_id}, sent with another account, amount, \
         destination or transport"
    )]
    SlateIdReused { tx_id: u32 },
    /// The receiver declined the send made under this slate id. The send was erased, so no
    /// transaction is left to show; this is the only trace.
    #[error(
        "the payee declined the send with slate id {slate_id} at {declined_at}; it was erased and nothing was paid"
    )]
    PaymentDeclined {
        slate_id: String,
        declined_at: String,
    },
    /// The shell's send costs other than its review showed: the wallet's outputs or the fee
    /// changed between the two. Nothing is stored.
    #[error(
        "the send would now take {} EPIC in total, not the {} EPIC reviewed: nothing was sent",
        crate::amount::format_units(*total),
        crate::amount::format_units(*reviewed)
    )]
    ReviewChanged { reviewed: u64, total: u64 },
    #[error("no send of this wallet has that slate id")]
    NoSendWithSlate,
    /// The recovery of a send ended failed, with the reason it stored: the node refused it, or
    /// the chain took the send first. The recovery's two entries are cancelled.
    #[error("the recovery of transaction {tx_id} failed: {error}")]
    RecoveryFailed { tx_id: u32, error: String },
    /// A cancel of a send the node took: only a recovery spends its inputs again.
    #[error("transaction {tx_id} is posted, so it is not cancelled")]
    PostedSend { tx_id: u32 },
    #[error("start height {start} is above the node's tip {tip}")]
    StartAboveTip { start: u64, tip: u64 },
    #[error("epicbox address rejected")]
    Address(#[source] lepic_epicbox::AddressError),
    #[error("transport registration failed")]
    Registry(#[from] lepic_methods::registry::RegistryError),
    #[error("could not {what}")]
    Io {
        what: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("stopped before it finished")]
    Interrupted,
    #[error(
        "stopped after transaction {tx_id} was stored, before its delivery was known: \
         run `lepic tx show {tx_id}`"
    )]
    SendInterrupted { tx_id: u32 },
    #[error("other users can access the data directory")]
    SharedDataDir,
    #[error("another lepic process is using the data directory")]
    DataDirInUse,
    /// `lepic serve` holds the wallet, and the command has no route in its API (ADR 0053).
    #[error(
        "lepic serve is running on this wallet (socket {}) and this command does not go through \
         its API",
        socket.display()
    )]
    ServeHoldsWallet { socket: std::path::PathBuf },
    /// The error the running `lepic serve` answered for a command it ran (ADR 0053): the kind,
    /// message, causes, transaction, recovery commands and hint the command reports when it runs on
    /// its own.
    #[error("{message}")]
    Served {
        kind: ErrorKind,
        message: String,
        #[source]
        causes: Option<Box<ServedCause>>,
        tx_id: Option<u32>,
        recovery: Box<[String]>,
        /// The hint serve computed for a request for text.
        hint: Option<String>,
        /// The wait a mailbox asked for, in seconds, when serve named one.
        retry_after_secs: Option<u64>,
        /// The mailbox, `host[:port]`, the refusal came from or the old link named, when serve
        /// named one.
        mailbox: Option<String>,
    },
    /// The running `lepic serve` took a command and gave no answer, or one that is not the API's.
    #[error("lepic serve on {} did not answer the command", socket.display())]
    ServeUnanswered {
        socket: std::path::PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The running `lepic serve` refused a command and runs another version of `lepic`, one
    /// that names no version when `serve` says "an older version".
    #[error("lepic serve on {} runs {serve}, and this lepic is version {cli}", socket.display())]
    ServeVersion {
        socket: std::path::PathBuf,
        serve: String,
        cli: &'static str,
    },
    /// The running `lepic serve` took a payment and gave no answer, or one that is not the
    /// API's: the payment may have been made under `slate_id`.
    #[error(
        "lepic serve on {} did not answer the payment {slate_id}; it may have been made",
        socket.display()
    )]
    PaymentUnanswered {
        socket: std::path::PathBuf,
        slate_id: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("http address rejected")]
    HttpUrl(#[source] lepic_methods::http::UrlError),
    #[error(
        "an invoice is not sent to an address: write it to a file with --to-file, or send it \
         to a paired contact with lepic contact invoice"
    )]
    InvoiceToAddress,
    /// `invoice pay` or `contact open-sealed --amount` had no terminal to ask at and no
    /// `--yes`.
    #[error(
        "the invoice was not paid: {command} asks first at a terminal; give --yes to pay \
         without asking"
    )]
    InvoicePayUnasked { command: &'static str },
    /// The answer to `invoice pay`'s question was not `y`.
    #[error("the invoice was not paid")]
    InvoicePayDeclined,
    #[error("the http listener could not start")]
    HttpListen(#[from] lepic_methods::http::ListenError),
    #[error("the answer of transaction {tx_id} was not kept")]
    HttpReplyLost { tx_id: u32 },
    #[error("onion address rejected")]
    OnionAddress(#[source] lepic_methods::tor::OnionError),
    /// The command needs a connection and the connection mode allows none.
    #[error("{reason}: this command needs the network")]
    Offline {
        reason: crate::settings::OfflineReason,
    },
    /// Tor is expected and the route would connect directly (ADR 0021); `http_direct`
    /// allows it.
    #[error("tor is expected and {route} would connect directly")]
    TorExpected { route: &'static str },
    #[error("give --tor-binary to use tor")]
    TorBinaryNeeded,
    #[error("tor is not working")]
    Tor(#[from] lepic_methods::tor::TorFailure),
    #[error("contact failed")]
    Contact(#[from] ContactError),
    #[error("a pairing's sas is not in the sas table")]
    SasTable,
    #[error("contact id is not 32 hex digits")]
    ContactId,
    #[error("the domain is not configured: set `domain`, --domain or LEPIC_DOMAIN")]
    DomainNotConfigured,
    #[error("the domain file would be over 4 KiB: name fewer relays")]
    DomainFileTooLarge,
    #[error("invoice link rejected")]
    InvoiceLink(#[source] lepic_wallet_contacts::InvoiceLinkError),
    /// The scanned code claims a domain its well-known file does not prove: it is not paid.
    #[error("the code claims {domain}, which its file does not prove ({reason}): nothing was paid")]
    RequestDomainRefused {
        domain: String,
        reason: &'static str,
    },
    #[error(
        "transaction {tx_id} has no payment proof; only an answered payment to an epic1 address has one"
    )]
    NoPaymentProof { tx_id: u32 },
    #[error("the payment proof does not verify: {reason}")]
    ProofRefused { reason: String },
    #[error("{} exists; --force replaces it", path.display())]
    FileExists { path: std::path::PathBuf },
    #[error("{} exists; a backup goes to a path that does not exist yet", path.display())]
    BackupExists { path: std::path::PathBuf },
    #[error("the wallet database cannot be backed up yet: {reason}")]
    BackupNotReady { reason: &'static str },
    #[error("payload id is not 32 hex digits")]
    PayloadId,
    #[error("--hex is not an even number of hex digits")]
    PayloadHex,
    #[error("the socket path {} is too long for a unix socket", path.display())]
    SocketPathTooLong { path: std::path::PathBuf },
    #[error("{} exists and is not a socket", path.display())]
    SocketPathTaken { path: std::path::PathBuf },
    #[error("another lepic serve answers on {}", path.display())]
    SocketInUse { path: std::path::PathBuf },
    #[error("lepic serve needs unix sockets, which this system does not offer")]
    ServiceUnsupported,
    #[error("serve --owner-tls needs an address: set `[api] owner_tls` in settings.toml")]
    OwnerTlsNotConfigured,
    #[error("the owner TLS listener could not start on {address}")]
    OwnerTlsListen {
        address: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("the owner TLS certificate could not be made")]
    OwnerTlsCertificate(#[source] rcgen::Error),
    #[error("the owner TLS configuration was refused")]
    OwnerTlsConfig(#[source] rustls::Error),
    #[error("a client name is 1 to 64 letters, digits, '.', '-' or '_'")]
    ApiClientName,
    #[error("{} is not a PEM certificate with an Ed25519 key", path.display())]
    ApiClientCertificate { path: std::path::PathBuf },
    #[error("client {name} is listed with this name or key already")]
    ApiClientListed { name: String },
    #[error("no client is named {name}")]
    ApiClientNotFound { name: String },
    #[error("{} line {line} is not `<name> <sha256 hex>`", path.display())]
    ApiClientsInvalid {
        path: std::path::PathBuf,
        line: usize,
    },
    #[error("{} line {line} lists a fingerprint an earlier line lists", path.display())]
    ApiClientsDuplicate {
        path: std::path::PathBuf,
        line: usize,
    },
    #[error("{} is over 64 KiB", path.display())]
    ApiClientsTooLarge { path: std::path::PathBuf },
    #[error(
        "{} is in a saved_txs directory, which another Epic wallet keeps: write elsewhere",
        path.display()
    )]
    SavedTxsDir { path: std::path::PathBuf },
}

impl From<SelfSendError> for CliError {
    fn from(error: SelfSendError) -> Self {
        match error {
            SelfSendError::Send(error) => Self::Send(error),
            SelfSendError::Receive(error) => Self::Receive(error),
            SelfSendError::Finalize(error) => Self::Finalize(error),
            other => Self::SelfSend(other),
        }
    }
}

impl CliError {
    pub fn io(what: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { what, source }
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Settings(_)
            | Self::Telemetry(_)
            | Self::SharedDataDir
            | Self::OwnerTlsNotConfigured
            | Self::ApiClientsInvalid { .. }
            | Self::ApiClientsDuplicate { .. }
            | Self::ApiClientsTooLarge { .. }
            | Self::Secret(
                SecretError::PasswordFileOpen { .. }
                | SecretError::PasswordFileEmpty { .. }
                | SecretError::PasswordFile { .. },
            ) => ErrorKind::Config,
            Self::Secret(SecretError::Mismatch | SecretError::EmptyNew) => ErrorKind::Rejected,
            Self::Secret(SecretError::Cancelled { .. }) => ErrorKind::Interrupted,
            Self::Arguments(_)
            | Self::Secret(_)
            | Self::Amount(_)
            | Self::Zero { .. }
            | Self::NoDestination
            | Self::Epic1Amount
            | Self::SlateId
            | Self::NotRandomSlateId
            | Self::StartAboveTip { .. }
            | Self::Address(_)
            | Self::HttpUrl(_)
            | Self::InvoiceToAddress
            | Self::InvoicePayUnasked { .. }
            | Self::OnionAddress(_)
            | Self::ContactId
            | Self::PayloadId
            | Self::PayloadHex
            | Self::DomainNotConfigured
            | Self::FileExists { .. }
            | Self::BackupExists { .. }
            | Self::BackupNotReady { .. }
            | Self::DomainFileTooLarge
            | Self::InvoiceLink(_)
            | Self::SocketPathTooLong { .. }
            | Self::SocketPathTaken { .. }
            | Self::SocketInUse { .. }
            | Self::ServiceUnsupported
            | Self::ApiClientName
            | Self::ApiClientCertificate { .. }
            | Self::ApiClientListed { .. }
            | Self::SavedTxsDir { .. }
            | Self::TorBinaryNeeded => ErrorKind::Usage,
            Self::Contact(error) => contact_kind(error),
            Self::Tor(failure) if failure.kind == lepic_methods::tor::FailureKind::Missing => {
                ErrorKind::Config
            }
            Self::Tor(_) => ErrorKind::Transport,
            Self::MailboxChange(error) => mailbox_change_kind(error),
            Self::MailboxUntested { .. } => ErrorKind::Transport,
            Self::HttpListen(_) | Self::OwnerTlsListen { .. } => ErrorKind::Transport,
            Self::ApiClientNotFound { .. } | Self::NoPaymentProof { .. } => ErrorKind::NotFound,
            Self::HttpReplyLost { .. } => ErrorKind::Incomplete,
            Self::Wallet(error) => wallet_kind(error),
            Self::Store(StoreError::SchemaTooNew { .. } | StoreError::DamagedKept { .. }) => {
                ErrorKind::WalletState
            }
            Self::Store(_) => ErrorKind::Internal,
            Self::DataDirInUse | Self::ServeHoldsWallet { .. } => ErrorKind::WalletState,
            Self::Served { kind, .. } => *kind,
            Self::ServeUnanswered { .. } => ErrorKind::Transport,
            Self::ServeVersion { .. } => ErrorKind::Config,
            Self::Offline { .. } | Self::TorExpected { .. } => ErrorKind::Config,
            Self::PaymentUnanswered { .. } => ErrorKind::Incomplete,
            Self::SlateIdReused { .. }
            | Self::ReviewChanged { .. }
            | Self::RecoveryFailed { .. }
            | Self::PostedSend { .. }
            | Self::RequestDomainRefused { .. }
            | Self::ProofRefused { .. } => ErrorKind::Rejected,
            Self::NoSendWithSlate | Self::PaymentDeclined { .. } => ErrorKind::NotFound,
            Self::Send(error) => send_kind(error),
            Self::Receive(error) => receive_kind(error),
            Self::Finalize(error) => finalize_kind(error),
            Self::Invoice(error) => invoice_kind(error),
            Self::Inbox(error) => inbox_kind(error),
            Self::Refresh(RefreshError::Wallet(error)) | Self::Scan(ScanError::Wallet(error)) => {
                wallet_kind(error)
            }
            Self::Refresh(RefreshError::Node(_) | RefreshError::Implausible(_))
            | Self::Scan(ScanError::Node(_) | ScanError::Implausible(_))
            | Self::Node(_) => ErrorKind::Node,
            Self::Scan(ScanError::Cancelled)
            | Self::Interrupted
            | Self::SendInterrupted { .. }
            | Self::InvoicePayDeclined => ErrorKind::Interrupted,
            Self::Transport(_) | Self::SlateFile { .. } => ErrorKind::Transport,
            Self::Refresh(_)
            | Self::Scan(_)
            | Self::Registry(_)
            | Self::SelfSend(_)
            | Self::SasTable
            | Self::OwnerTlsCertificate(_)
            | Self::OwnerTlsConfig(_)
            | Self::Io { .. } => ErrorKind::Internal,
        }
    }

    /// The message and every cause under it, outermost first, cleaned and bounded for a
    /// terminal. Repeated texts, as when a wrapper prints its source, appear once.
    pub fn chain(&self) -> Vec<String> {
        display_error_chain(self)
    }

    /// The seconds a mailbox or peer asked to wait before the post goes again, when the error
    /// is a refusal that named a wait: for a script to retry after it.
    pub fn retry_after_secs(&self) -> Option<u64> {
        if let Self::Served {
            retry_after_secs, ..
        } = self
        {
            return *retry_after_secs;
        }
        lepic_wallet_contacts::retry_after_of(self).map(|wait| wait.as_secs())
    }

    /// The mailbox, `host[:port]`, that refused the post, or that an epic1 link of an earlier
    /// release names, when the error says which.
    pub fn mailbox(&self) -> Option<String> {
        if let Self::Served { mailbox, .. } = self {
            return mailbox.clone();
        }
        lepic_wallet_contacts::mailbox_of(self)
    }

    /// A finer name than the kind for the one error that has it: `payment_declined`, the
    /// answer for a send the payee declined. Same name as the serve API's.
    pub const fn code(&self) -> Option<&'static str> {
        match self {
            Self::PaymentDeclined { .. } => Some("payment_declined"),
            _ => None,
        }
    }

    /// When the payee declined, for `payment_declined`.
    pub fn declined_at(&self) -> Option<&str> {
        match self {
            Self::PaymentDeclined { declined_at, .. } => Some(declined_at),
            _ => None,
        }
    }

    /// The stored transaction the error is about, for a script to resend, cancel or show.
    pub const fn tx_id(&self) -> Option<u32> {
        match self {
            Self::SendInterrupted { tx_id }
            | Self::SlateIdReused { tx_id }
            | Self::RecoveryFailed { tx_id, .. }
            | Self::PostedSend { tx_id }
            | Self::HttpReplyLost { tx_id } => Some(*tx_id),
            Self::Send(SendError::Undelivered { tx_id, .. })
            | Self::Finalize(
                FinalizeError::NotPosted { tx_id, .. } | FinalizeError::InputsReorged { tx_id, .. },
            )
            | Self::Invoice(
                InvoiceError::Undelivered { tx_id, .. }
                | InvoiceError::PaymentUndelivered { tx_id, .. }
                | InvoiceError::NotPosted { tx_id, .. }
                | InvoiceError::InputsReorged { tx_id, .. },
            )
            | Self::Contact(
                ContactError::Send(SendError::Undelivered { tx_id, .. })
                | ContactError::Finalize(
                    FinalizeError::NotPosted { tx_id, .. }
                    | FinalizeError::InputsReorged { tx_id, .. },
                )
                | ContactError::Invoice(
                    InvoiceError::Undelivered { tx_id, .. }
                    | InvoiceError::PaymentUndelivered { tx_id, .. }
                    | InvoiceError::NotPosted { tx_id, .. }
                    | InvoiceError::InputsReorged { tx_id, .. },
                ),
            ) => Some(tx_id.0),
            Self::Served { tx_id, .. } => *tx_id,
            _ => None,
        }
    }
}

/// One cause of an error `lepic serve` answered, with the causes below it.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ServedCause {
    message: String,
    #[source]
    next: Option<Box<Self>>,
}

impl ServedCause {
    /// The chain of `causes`, outermost first; `None` when there are none.
    pub fn chain(causes: Vec<String>) -> Option<Box<Self>> {
        causes
            .into_iter()
            .rev()
            .fold(None, |next, message| Some(Box::new(Self { message, next })))
    }
}

fn wallet_kind(error: &WalletError) -> ErrorKind {
    match error {
        WalletError::Config(_) => ErrorKind::Config,
        WalletError::WrongPassword => ErrorKind::WrongPassword,
        WalletError::WalletExists
        | WalletError::NoWallet
        | WalletError::Locked
        | WalletError::AlreadyOpen
        | WalletError::NetworkMismatch { .. }
        | WalletError::ForeignDatabase
        | WalletError::Store(StoreError::SchemaTooNew { .. } | StoreError::DamagedKept { .. })
        | WalletError::RestoreScanRequired => ErrorKind::WalletState,
        WalletError::Node(_) | WalletError::Implausible(_) => ErrorKind::Node,
        WalletError::UnknownTransaction(_)
        | WalletError::Account(AccountError::UnknownLabel | AccountError::UnknownAccount(_)) => {
            ErrorKind::NotFound
        }
        WalletError::Mnemonic(_)
        | WalletError::WalletSeedFile(_)
        | WalletError::Account(_)
        | WalletError::Transition(_)
        | WalletError::PartnerPosted { .. }
        | WalletError::OnChain(_)
        | WalletError::InPool(_)
        | WalletError::RecoveryOpen(_)
        | WalletError::NotRecoverable(_)
        | WalletError::ChangedDuringCancel(_)
        | WalletError::InvalidListing => ErrorKind::Rejected,
        WalletError::MinimumConfirmationsOutOfRange { .. } => ErrorKind::Usage,
        _ => ErrorKind::Internal,
    }
}

fn send_kind(error: &SendError) -> ErrorKind {
    match error {
        SendError::Wallet(error) => wallet_kind(error),
        SendError::Node(_) => ErrorKind::Node,
        SendError::Selection(SelectionError::NotEnoughFunds { .. }) => ErrorKind::InsufficientFunds,
        SendError::Selection(_)
        | SendError::Unrepresentable(_)
        | SendError::ProofAddress(_)
        | SendError::NotResendable { .. }
        | SendError::PayeeMismatch { .. }
        | SendError::SlateIdTaken { .. }
        | SendError::FeeAboveMaximum { .. }
        | SendError::CancelledOnRelay { .. } => ErrorKind::Rejected,
        SendError::UnknownTransport { .. }
        | SendError::CannotDeliver { .. }
        | SendError::CannotExport { .. } => ErrorKind::Transport,
        SendError::Undelivered { .. } => ErrorKind::Incomplete,
        SendError::SlateTooLarge { .. } => ErrorKind::SlateTooLarge,
        _ => ErrorKind::Internal,
    }
}

fn mailbox_change_kind(error: &crate::settings_file::MailboxChangeError) -> ErrorKind {
    use crate::settings_file::MailboxChangeError as E;
    match error {
        E::List(_) | E::Local => ErrorKind::Usage,
        E::NoFile | E::Settings(_) | E::Form { .. } => ErrorKind::Config,
        E::Write { .. } => ErrorKind::Internal,
    }
}

fn contact_kind(error: &ContactError) -> ErrorKind {
    match error {
        ContactError::Wallet(error) => wallet_kind(error),
        ContactError::Invoice(error) => invoice_kind(error),
        ContactError::Receive(error) => receive_kind(error),
        ContactError::Finalize(error) => finalize_kind(error),
        ContactError::Send(error) => send_kind(error),
        ContactError::Offline | ContactError::NetworkMismatch => ErrorKind::Config,
        ContactError::Decode(_)
        | ContactError::Name(_)
        | ContactError::RelayAddress
        | ContactError::Mailboxes(_)
        | ContactError::Domain(_)
        | ContactError::NoDomainConfigured
        | ContactError::TooLarge { .. }
        | ContactError::SavedTransaction
        | ContactError::NotPaymentFile
        | ContactError::WrongClass => ErrorKind::Usage,
        ContactError::UnknownContact
        | ContactError::UnknownPairing
        | ContactError::UnknownTransaction
        | ContactError::WordsNotFound => ErrorKind::NotFound,
        ContactError::Relay(_) | ContactError::RelayNotRead(_) => ErrorKind::Transport,
        ContactError::NoSharedMailbox { .. } => ErrorKind::NoSharedMailbox,
        ContactError::InviteExpired
        | ContactError::AlreadyPaired
        | ContactError::NotVerified
        | ContactError::SealOff
        | ContactError::DoesNotPayInvoices
        | ContactError::NotForThisInstall
        | ContactError::CannotOpen
        | ContactError::NotASlate
        | ContactError::Stage(_)
        | ContactError::KeyCheckRefused
        | ContactError::PairingInProgress
        | ContactError::Crossed
        | ContactError::Ended
        | ContactError::Waiting
        | ContactError::OtherAddress
        | ContactError::KindDiffers
        | ContactError::AddressProofMissing
        | ContactError::NoDomainClaim
        | ContactError::RelayMoveNotRequested => ErrorKind::Rejected,
        ContactError::Native(_) => ErrorKind::Usage,
        ContactError::InPerson(InPersonRefusal::NoCode | InPersonRefusal::NoAnswer) => {
            ErrorKind::NotFound
        }
        ContactError::InPerson(
            InPersonRefusal::TtlTooShort { .. }
            | InPersonRefusal::DirectRoute
            | InPersonRefusal::RepeatDiffers,
        ) => ErrorKind::Usage,
        ContactError::InPerson(_) => ErrorKind::Rejected,
        ContactError::Epic1Link(link) if link.is_earlier_address() => ErrorKind::EarlierAddress,
        ContactError::Epic1Link(_) => ErrorKind::Usage,
        ContactError::Epic1(Epic1Refusal::NoPayment) => ErrorKind::NotFound,
        ContactError::Epic1(_) => ErrorKind::Rejected,
        ContactError::NotCancelled { cause, .. } => contact_kind(cause),
        ContactError::Encode(error) => contact_encode_kind(*error),
        _ => ErrorKind::Internal,
    }
}

/// What a card or envelope that could not be built says of the input. Every variant is named,
/// so a new one is mapped where it is added.
const fn contact_encode_kind(error: ContactEncodeError) -> ErrorKind {
    use ContactEncodeError as E;
    match error {
        E::FieldTooLong { .. } | E::BodyTooLarge { .. } | E::Oversized { .. } | E::WrongClass => {
            ErrorKind::Usage
        }
        E::WrongNetwork => ErrorKind::Config,
        E::ReplyRoute | E::SigningKeyMismatch | E::Encapsulation | E::Encryption => {
            ErrorKind::Internal
        }
    }
}

fn receive_kind(error: &ReceiveError) -> ErrorKind {
    match error {
        ReceiveError::Wallet(error) => wallet_kind(error),
        ReceiveError::UnknownTransport { .. } => ErrorKind::Transport,
        ReceiveError::Node(_) => ErrorKind::Node,
        ReceiveError::OpenReceipts(_) => ErrorKind::WalletState,
        ReceiveError::Decode(_)
        | ReceiveError::WrongStage { .. }
        | ReceiveError::AlreadyReceived { .. }
        | ReceiveError::Expired { .. }
        | ReceiveError::AheadOfTip { .. }
        | ReceiveError::FeeBelowMinimum { .. }
        | ReceiveError::FeeOverflow
        | ReceiveError::MessageSignature { .. }
        | ReceiveError::ForeignProofAddress
        | ReceiveError::ZeroAmount
        | ReceiveError::AboveSupply { .. }
        | ReceiveError::Refused => ErrorKind::Rejected,
        _ => ErrorKind::Internal,
    }
}

fn finalize_kind(error: &FinalizeError) -> ErrorKind {
    match error {
        FinalizeError::Wallet(error) => wallet_kind(error),
        FinalizeError::UnknownTransport { .. } => ErrorKind::Transport,
        FinalizeError::Node(_) => ErrorKind::Node,
        FinalizeError::NotPosted { .. } | FinalizeError::InputsReorged { .. } => {
            ErrorKind::Incomplete
        }
        FinalizeError::UnknownSlate { .. } => ErrorKind::NotFound,
        FinalizeError::Decode(_)
        | FinalizeError::WrongStage { .. }
        | FinalizeError::AlreadyFinalized { .. }
        | FinalizeError::NotFinalizable { .. }
        | FinalizeError::Expired { .. }
        | FinalizeError::Mismatch { .. }
        | FinalizeError::MissingPaymentProof
        | FinalizeError::ForeignSenderAddress
        | FinalizeError::UnexpectedAnswerer { .. }
        | FinalizeError::PaymentProofSignature
        | FinalizeError::MessageSignature(_)
        | FinalizeError::ReceiverSignature(_)
        | FinalizeError::FeeBelowMinimum { .. }
        | FinalizeError::FeeOverflow
        | FinalizeError::InvalidTransaction(_)
        | FinalizeError::NotPostable { .. }
        | FinalizeError::InputsSpentElsewhere { .. }
        | FinalizeError::InputsSpentByOwnTransaction { .. }
        | FinalizeError::PeerInputsSpent { .. } => ErrorKind::Rejected,
        _ => ErrorKind::Internal,
    }
}

fn invoice_kind(error: &InvoiceError) -> ErrorKind {
    match error {
        InvoiceError::Wallet(error) => wallet_kind(error),
        InvoiceError::Node(_) => ErrorKind::Node,
        InvoiceError::Selection(SelectionError::NotEnoughFunds { .. }) => {
            ErrorKind::InsufficientFunds
        }
        InvoiceError::ToAddress => ErrorKind::Usage,
        InvoiceError::UnknownTransport { .. } | InvoiceError::CannotExport { .. } => {
            ErrorKind::Transport
        }
        InvoiceError::Undelivered { .. }
        | InvoiceError::PaymentUndelivered { .. }
        | InvoiceError::NotPosted { .. }
        | InvoiceError::InputsReorged { .. } => ErrorKind::Incomplete,
        InvoiceError::UnknownSlate { .. } | InvoiceError::NotParked { .. } => ErrorKind::NotFound,
        InvoiceError::SlateIdTaken { .. } => ErrorKind::Rejected,
        InvoiceError::Decode(_)
        | InvoiceError::WrongStage { .. }
        | InvoiceError::Selection(_)
        | InvoiceError::AmountMismatch { .. }
        | InvoiceError::AlreadyPaid { .. }
        | InvoiceError::Expired { .. }
        | InvoiceError::LockedUntil { .. }
        | InvoiceError::AheadOfTip { .. }
        | InvoiceError::TtlTooFarAhead { .. }
        | InvoiceError::TtlTooFarBehind { .. }
        | InvoiceError::MessageSignature { .. }
        | InvoiceError::Mismatch { .. }
        | InvoiceError::PayerSignature(_)
        | InvoiceError::FeeBelowMinimum { .. }
        | InvoiceError::FeeOverflow
        | InvoiceError::InvalidTransaction(_)
        | InvoiceError::Unrepresentable(_)
        | InvoiceError::AlreadyFinalized { .. }
        | InvoiceError::NotFinalizable { .. }
        | InvoiceError::InputsSpentElsewhere { .. }
        | InvoiceError::InputsSpentByOwnTransaction { .. }
        | InvoiceError::PeerInputsSpent { .. }
        | InvoiceError::AnswerInputsSpent { .. } => ErrorKind::Rejected,
        _ => ErrorKind::Internal,
    }
}

fn inbox_kind(error: &InboxError) -> ErrorKind {
    match error {
        InboxError::Wallet(error) => wallet_kind(error),
        InboxError::UnknownTransport { .. } | InboxError::NetworkMismatch => ErrorKind::Config,
        InboxError::Subscription(_) | InboxError::Transport(_) => ErrorKind::Transport,
        InboxError::Address(_) => ErrorKind::Usage,
        InboxError::InvoiceExpiry => ErrorKind::Config,
        _ => ErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use lepic_primitives::amount::Height;
    use lepic_wallet::chain::ImplausibleNodeData;

    use super::*;

    #[test]
    fn exit_codes_help_lists_every_kind() {
        for kind in ErrorKind::ALL {
            let line = format!("{:>4}  {}:", kind.exit_code(), kind.name());
            assert!(EXIT_CODES_HELP.contains(&line), "{line}");
        }
    }

    #[test]
    fn exit_codes_are_distinct_and_never_zero() {
        let mut codes: Vec<u8> = ErrorKind::ALL.iter().map(|kind| kind.exit_code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), ErrorKind::ALL.len());
        assert!(!codes.contains(&0));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
    fn engine_errors_map_to_their_exit_codes() {
        let cases: Vec<(CliError, ErrorKind)> = vec![
            (WalletError::WrongPassword.into(), ErrorKind::WrongPassword),
            (WalletError::NoWallet.into(), ErrorKind::WalletState),
            (
                WalletError::Store(StoreError::SchemaTooNew {
                    found: 17,
                    supported: 16,
                })
                .into(),
                ErrorKind::WalletState,
            ),
            (
                WalletError::Store(StoreError::DamagedKept {
                    set_aside: "wallet.enc.sqlite3.damaged-1".into(),
                })
                .into(),
                ErrorKind::WalletState,
            ),
            (
                WalletError::UnknownTransaction(lepic_store::TxId(4)).into(),
                ErrorKind::NotFound,
            ),
            (
                SendError::Selection(SelectionError::NotEnoughFunds {
                    available: lepic_primitives::amount::Amount::new(1),
                    needed: lepic_primitives::amount::Amount::new(2),
                })
                .into(),
                ErrorKind::InsufficientFunds,
            ),
            (
                SendError::Wallet(WalletError::Locked).into(),
                ErrorKind::WalletState,
            ),
            (NodeError::Timeout.into(), ErrorKind::Node),
            (
                FinalizeError::NotPosted {
                    tx_id: lepic_store::TxId(1),
                    source: NodeError::Timeout,
                }
                .into(),
                ErrorKind::Incomplete,
            ),
            (
                FinalizeError::InputsSpentByOwnTransaction {
                    tx_id: lepic_store::TxId(3),
                    by: lepic_store::TxId(2),
                    source: NodeError::Timeout,
                }
                .into(),
                ErrorKind::Rejected,
            ),
            (
                FinalizeError::InputsSpentElsewhere {
                    tx_id: lepic_store::TxId(3),
                    source: NodeError::Timeout,
                }
                .into(),
                ErrorKind::Rejected,
            ),
            (
                InvoiceError::PeerInputsSpent {
                    tx_id: lepic_store::TxId(3),
                    source: NodeError::Timeout,
                }
                .into(),
                ErrorKind::Rejected,
            ),
            (
                FinalizeError::InputsReorged {
                    tx_id: lepic_store::TxId(3),
                    source: NodeError::Timeout,
                }
                .into(),
                ErrorKind::Incomplete,
            ),
            (
                InvoiceError::InputsReorged {
                    tx_id: lepic_store::TxId(3),
                    source: NodeError::Timeout,
                }
                .into(),
                ErrorKind::Incomplete,
            ),
            (ReceiveError::FeeOverflow.into(), ErrorKind::Rejected),
            (
                ReceiveError::OpenReceipts(None).into(),
                ErrorKind::WalletState,
            ),
            (
                InvoiceError::AmountMismatch {
                    invoiced: lepic_primitives::amount::Amount::new(2),
                    approved: lepic_primitives::amount::Amount::new(1),
                }
                .into(),
                ErrorKind::Rejected,
            ),
            (AmountError::Syntax.into(), ErrorKind::Usage),
            (CliError::Interrupted, ErrorKind::Interrupted),
            (
                SecretError::Cancelled { what: "password" }.into(),
                ErrorKind::Interrupted,
            ),
            (
                CliError::SendInterrupted { tx_id: 2 },
                ErrorKind::Interrupted,
            ),
            (
                RefreshError::Implausible(ImplausibleNodeData::TipTooHigh {
                    tip: Height::new(2),
                    limit: Height::new(1),
                })
                .into(),
                ErrorKind::Node,
            ),
            (
                ScanError::Implausible(ImplausibleNodeData::TipTooHigh {
                    tip: Height::new(2),
                    limit: Height::new(1),
                })
                .into(),
                ErrorKind::Node,
            ),
            (
                WalletError::OnChain(lepic_store::TxId(5)).into(),
                ErrorKind::Rejected,
            ),
            (
                WalletError::RestoreScanRequired.into(),
                ErrorKind::WalletState,
            ),
            (
                WalletError::Node(NodeError::Timeout).into(),
                ErrorKind::Node,
            ),
            (
                WalletError::Implausible(ImplausibleNodeData::TipTooHigh {
                    tip: Height::new(2),
                    limit: Height::new(1),
                })
                .into(),
                ErrorKind::Node,
            ),
            (
                WalletError::ChangedDuringCancel(lepic_store::TxId(6)).into(),
                ErrorKind::Rejected,
            ),
            (
                WalletError::InPool(lepic_store::TxId(7)).into(),
                ErrorKind::Rejected,
            ),
            (ReceiveError::ZeroAmount.into(), ErrorKind::Rejected),
            (CliError::DataDirInUse, ErrorKind::WalletState),
            (
                CliError::ServeHoldsWallet {
                    socket: "lepic.sock".into(),
                },
                ErrorKind::WalletState,
            ),
            (
                CliError::PaymentUnanswered {
                    socket: "lepic.sock".into(),
                    slate_id: "s1".to_owned(),
                    source: "closed".into(),
                },
                ErrorKind::Incomplete,
            ),
            (
                CliError::Served {
                    kind: ErrorKind::InsufficientFunds,
                    message: "not enough".to_owned(),
                    causes: None,
                    tx_id: None,
                    recovery: Box::default(),
                    hint: None,
                    retry_after_secs: None,
                    mailbox: None,
                },
                ErrorKind::InsufficientFunds,
            ),
            (
                InvoiceError::NotParked {
                    slate_id: lepic_wallet::event::SlateId::from_bytes([1; 16]),
                }
                .into(),
                ErrorKind::NotFound,
            ),
            (
                SendError::PayeeMismatch {
                    tx_id: lepic_store::TxId(9),
                }
                .into(),
                ErrorKind::Rejected,
            ),
            (
                SendError::SlateTooLarge {
                    bytes: 131_072,
                    limit: 131_071,
                    inputs: 600,
                }
                .into(),
                ErrorKind::SlateTooLarge,
            ),
            (CliError::SlateId, ErrorKind::Usage),
            (CliError::PayloadId, ErrorKind::Usage),
            (CliError::PayloadHex, ErrorKind::Usage),
            (CliError::DomainNotConfigured, ErrorKind::Usage),
            (
                CliError::InvoiceLink(lepic_wallet_contacts::InvoiceLinkError::Prefix),
                ErrorKind::Usage,
            ),
            (
                CliError::RequestDomainRefused {
                    domain: "shop.example".to_owned(),
                    reason: "key_not_listed",
                },
                ErrorKind::Rejected,
            ),
            (CliError::OwnerTlsNotConfigured, ErrorKind::Config),
            (
                CliError::ApiClientNotFound {
                    name: "laptop".to_owned(),
                },
                ErrorKind::NotFound,
            ),
            (CliError::NotRandomSlateId, ErrorKind::Usage),
            (CliError::SlateIdReused { tx_id: 1 }, ErrorKind::Rejected),
            (CliError::PostedSend { tx_id: 1 }, ErrorKind::Rejected),
            (CliError::NoSendWithSlate, ErrorKind::NotFound),
            (
                CliError::StartAboveTip { start: 9, tip: 8 },
                ErrorKind::Usage,
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(error.kind(), kind, "{error:?}");
        }
    }

    #[test]
    fn the_chain_lists_each_cause_once() {
        let error = CliError::Finalize(FinalizeError::NotPosted {
            tx_id: lepic_store::TxId(3),
            source: NodeError::Timeout,
        });
        assert_eq!(
            error.chain(),
            [
                "finalize failed",
                "transaction 3 is finalized but the node did not accept it",
                "node did not answer within the request timeout",
            ]
        );
    }

    /// Every wallet error the CLI shows, by the variant that made it.
    fn engine_samples() -> Vec<CliError> {
        use lepic_wallet_contacts::error_samples as samples;
        let mut errors: Vec<CliError> = Vec::new();
        errors.extend(samples::wallet_errors().into_iter().map(CliError::from));
        errors.extend(samples::send_errors().into_iter().map(CliError::from));
        errors.extend(samples::receive_errors().into_iter().map(CliError::from));
        errors.extend(samples::finalize_errors().into_iter().map(CliError::from));
        errors.extend(samples::invoice_errors().into_iter().map(CliError::from));
        errors.extend(samples::inbox_errors().into_iter().map(CliError::from));
        errors.extend(samples::contact_errors().into_iter().map(CliError::from));
        errors
    }

    /// Wallet errors that exit `internal`: a defect of the wallet, its storage or its keys,
    /// never the input, the node or the network. Each entry is the start of the error's debug
    /// text and names at least one sample.
    const INTERNAL: &[&str] = &[
        "Wallet(StoredSeed(",
        "Wallet(Keychain(",
        "Wallet(Identifier(",
        "Wallet(SecretVault(",
        "Wallet(SecretStore(",
        "Wallet(SecretName(",
        "Wallet(Store(WalUnavailable)",
        // The CLI reads no app data file.
        "Wallet(AppData(",
        "Wallet(Balance(",
        "Wallet(NoValidKey)",
        "Wallet(Task(",
        "Send(CodecNotRegistered",
        "Send(InputKeyMismatch)",
        "Send(KeyIdentifier(",
        "Send(Proof(",
        "Send(Crypto(",
        "Send(Slate(",
        "Send(Arithmetic(",
        "Send(StoredSlate(",
        "Send(MalformedContext)",
        "Send(Carried(",
        "Receive(Output(",
        "Receive(Signing(",
        "Receive(Excess(",
        "Receive(Slate(",
        "Receive(Codecs(",
        "Receive(Encode(",
        "Finalize(Signing(",
        "Finalize(Excess(",
        "Finalize(Slate(",
        "Finalize(Codecs(",
        "Finalize(Encode(",
        "Finalize(StoredSlate(",
        "Finalize(MissingContext",
        "Finalize(MalformedContext)",
        "Invoice(InputKeyMismatch)",
        "Invoice(KeyIdentifier(",
        "Invoice(Output(",
        "Invoice(Signing(",
        "Invoice(Excess(",
        "Invoice(Slate(",
        "Invoice(Arithmetic(",
        "Invoice(Codecs(",
        "Invoice(Encode(",
        "Invoice(StoredSlate(",
        "Invoice(MissingContext",
        "Invoice(MalformedContext)",
        "Inbox(Identity(",
        "Contact(Keys(",
        "Contact(StoredData(",
        "Contact(NoFreeSlot)",
        "Contact(Encode(ReplyRoute)",
        "Contact(Encode(SigningKeyMismatch)",
        "Contact(Encode(Encapsulation)",
        "Contact(Encode(Encryption)",
    ];

    #[test]
    fn only_a_defect_of_the_wallet_exits_internal() {
        let samples = engine_samples();
        for error in &samples {
            let shown = format!("{error:?}");
            let listed = INTERNAL.iter().any(|start| shown.starts_with(start));
            assert_eq!(error.kind() == ErrorKind::Internal, listed, "{shown}");
        }
        for start in INTERNAL {
            assert!(
                samples
                    .iter()
                    .any(|error| format!("{error:?}").starts_with(start)),
                "no sample starts with {start}"
            );
        }
    }

    #[test]
    fn mapping_fixes_hold() {
        use lepic_wallet_contacts::ContactEncodeError as EncodeError;
        let cases: Vec<(CliError, ErrorKind)> = vec![
            (ContactError::WrongClass.into(), ErrorKind::Usage),
            (
                ContactError::Encode(EncodeError::WrongClass).into(),
                ErrorKind::Usage,
            ),
            (
                ContactError::Encode(EncodeError::BodyTooLarge { limit: 1, found: 2 }).into(),
                ErrorKind::Usage,
            ),
            (
                ContactError::Encode(EncodeError::WrongNetwork).into(),
                ErrorKind::Config,
            ),
            (
                WalletError::MinimumConfirmationsOutOfRange { count: 0 }.into(),
                ErrorKind::Usage,
            ),
            (
                ContactError::Epic1(Epic1Refusal::NoPayment).into(),
                ErrorKind::NotFound,
            ),
            (
                ContactError::NoSharedMailbox {
                    shipped: vec!["mailbox.example".to_owned()],
                }
                .into(),
                ErrorKind::NoSharedMailbox,
            ),
            (
                ContactError::Epic1Link(lepic_wallet_contacts::LinkError::EarlierAddress {
                    mailbox: None,
                })
                .into(),
                ErrorKind::EarlierAddress,
            ),
            (
                ContactError::Epic1Link(lepic_wallet_contacts::LinkError::Address(
                    lepic_wallet_contacts::Epic1Error::EarlierAddress,
                ))
                .into(),
                ErrorKind::EarlierAddress,
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(error.kind(), kind, "{error:?}");
        }
    }
}
