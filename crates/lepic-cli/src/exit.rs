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
use lepic_wallet::send::SendError;
use lepic_wallet::{AccountError, ReceiveError, WalletError};
use lepic_wallet_contacts::ContactError;
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
}

impl ErrorKind {
    pub const ALL: [Self; 12] = [
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
        }
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
  10  transport: the slate file, the relay or the http listener failed
  11  incomplete: stored, but not delivered or not posted; retry
  12  interrupted: stopped before it finished";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CliError {
    #[error("settings are invalid")]
    Settings(#[from] SettingsError),
    #[error("secret input failed")]
    Secret(#[from] SecretError),
    #[error("amount rejected")]
    Amount(#[from] AmountError),
    #[error("{what} must be at least 1")]
    Zero { what: &'static str },
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
    #[error("slate id is not of the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")]
    SlateId,
    #[error("--slate-id must be a random version-4 uuid, made for this send")]
    NotRandomSlateId,
    #[error(
        "slate id belongs to transaction {tx_id}, sent with another account, amount, \
         destination or transport"
    )]
    SlateIdReused { tx_id: u32 },
    #[error("no send of this wallet has that slate id")]
    NoSendWithSlate,
    #[error("--reply-file applies to an invoice slate file, not to a parked invoice")]
    ReplyFileForParked,
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
    #[error("http address rejected")]
    HttpUrl(#[source] lepic_foreign::UrlError),
    #[error("invoices go over epicbox or through a slate file, not over http")]
    InvoiceOverHttp,
    #[error("the http listener could not start")]
    HttpListen(#[from] lepic_foreign::ListenError),
    #[error("the answer of transaction {tx_id} was not kept")]
    HttpReplyLost { tx_id: u32 },
    #[error("onion address rejected")]
    OnionAddress(#[source] lepic_tor::OnionError),
    #[error("give --tor-binary to use tor")]
    TorBinaryNeeded,
    #[error("tor is not working")]
    Tor(#[from] lepic_tor::TorFailure),
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
    #[error("{} exists; --force replaces it", path.display())]
    FileExists { path: std::path::PathBuf },
    #[error("payload id is not 32 hex digits")]
    PayloadId,
    #[error("--hex is not an even number of hex digits")]
    PayloadHex,
    #[error("the socket path {} is too long for a unix socket", path.display())]
    SocketPathTooLong { path: std::path::PathBuf },
    #[error("{} exists and is not a socket", path.display())]
    SocketPathTaken { path: std::path::PathBuf },
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
    #[error("{} is over 64 KiB", path.display())]
    ApiClientsTooLarge { path: std::path::PathBuf },
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
            | Self::ApiClientsTooLarge { .. }
            | Self::Secret(
                SecretError::PasswordFileOpen { .. }
                | SecretError::PasswordFileEmpty { .. }
                | SecretError::PasswordFile { .. },
            ) => ErrorKind::Config,
            Self::Secret(SecretError::Mismatch | SecretError::EmptyNew) => ErrorKind::Rejected,
            Self::Secret(_)
            | Self::Amount(_)
            | Self::Zero { .. }
            | Self::NoDestination
            | Self::SlateId
            | Self::NotRandomSlateId
            | Self::ReplyFileForParked
            | Self::StartAboveTip { .. }
            | Self::Address(_)
            | Self::HttpUrl(_)
            | Self::InvoiceOverHttp
            | Self::OnionAddress(_)
            | Self::ContactId
            | Self::PayloadId
            | Self::PayloadHex
            | Self::DomainNotConfigured
            | Self::FileExists { .. }
            | Self::DomainFileTooLarge
            | Self::SocketPathTooLong { .. }
            | Self::SocketPathTaken { .. }
            | Self::ServiceUnsupported
            | Self::ApiClientName
            | Self::ApiClientCertificate { .. }
            | Self::ApiClientListed { .. }
            | Self::TorBinaryNeeded => ErrorKind::Usage,
            Self::Contact(error) => contact_kind(error),
            Self::Tor(failure) if failure.kind == lepic_tor::FailureKind::Missing => {
                ErrorKind::Config
            }
            Self::Tor(_) => ErrorKind::Transport,
            Self::HttpListen(_) | Self::OwnerTlsListen { .. } => ErrorKind::Transport,
            Self::ApiClientNotFound { .. } => ErrorKind::NotFound,
            Self::HttpReplyLost { .. } => ErrorKind::Incomplete,
            Self::Wallet(error) => wallet_kind(error),
            Self::DataDirInUse => ErrorKind::WalletState,
            Self::SlateIdReused { .. } => ErrorKind::Rejected,
            Self::NoSendWithSlate => ErrorKind::NotFound,
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
            Self::Scan(ScanError::Cancelled) | Self::Interrupted | Self::SendInterrupted { .. } => {
                ErrorKind::Interrupted
            }
            Self::Transport(_) | Self::SlateFile { .. } => ErrorKind::Transport,
            Self::Refresh(_)
            | Self::Scan(_)
            | Self::Store(_)
            | Self::Registry(_)
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

    /// The stored transaction the error is about, for a script to resend, cancel or show.
    pub const fn tx_id(&self) -> Option<u32> {
        match self {
            Self::SendInterrupted { tx_id }
            | Self::SlateIdReused { tx_id }
            | Self::HttpReplyLost { tx_id } => Some(*tx_id),
            _ => None,
        }
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
        | WalletError::NotReleasable { .. }
        | WalletError::ChangedDuringCancel(_)
        | WalletError::InvalidListing => ErrorKind::Rejected,
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
        | SendError::SlateIdTaken { .. } => ErrorKind::Rejected,
        SendError::UnknownTransport { .. }
        | SendError::CannotDeliver { .. }
        | SendError::CannotExport { .. } => ErrorKind::Transport,
        SendError::Undelivered { .. } => ErrorKind::Incomplete,
        _ => ErrorKind::Internal,
    }
}

fn contact_kind(error: &ContactError) -> ErrorKind {
    match error {
        ContactError::Wallet(error) => wallet_kind(error),
        ContactError::Invoice(error) => invoice_kind(error),
        ContactError::Receive(error) => receive_kind(error),
        ContactError::Finalize(error) => finalize_kind(error),
        ContactError::Send(error) => send_kind(error),
        ContactError::Offline | ContactError::EpicboxOff | ContactError::NetworkMismatch => {
            ErrorKind::Config
        }
        ContactError::Decode(_)
        | ContactError::Name(_)
        | ContactError::RelayAddress
        | ContactError::WordsUnavailable
        | ContactError::Words(_)
        | ContactError::Domain(_)
        | ContactError::NoDomainConfigured
        | ContactError::TooLarge { .. } => ErrorKind::Usage,
        ContactError::UnknownContact
        | ContactError::UnknownPairing
        | ContactError::UnknownTransaction
        | ContactError::WordsNotFound => ErrorKind::NotFound,
        ContactError::Relay(_) => ErrorKind::Transport,
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
        | ContactError::PeerNotProven
        | ContactError::PairingInProgress
        | ContactError::Crossed
        | ContactError::InviteDismissed
        | ContactError::Ended
        | ContactError::Waiting
        | ContactError::OtherAddress
        | ContactError::KindDiffers
        | ContactError::AddressProofMissing
        | ContactError::NoDomainClaim
        | ContactError::RelayMoveNotRequested => ErrorKind::Rejected,
        ContactError::Post(_) => ErrorKind::Transport,
        ContactError::NotCancelled { cause, .. } => contact_kind(cause),
        _ => ErrorKind::Internal,
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
        | ReceiveError::Refused => ErrorKind::Rejected,
        _ => ErrorKind::Internal,
    }
}

fn finalize_kind(error: &FinalizeError) -> ErrorKind {
    match error {
        FinalizeError::Wallet(error) => wallet_kind(error),
        FinalizeError::UnknownTransport { .. } => ErrorKind::Transport,
        FinalizeError::Node(_) => ErrorKind::Node,
        FinalizeError::NotPosted { .. } => ErrorKind::Incomplete,
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
        InvoiceError::UnknownTransport { .. }
        | InvoiceError::CannotDeliver { .. }
        | InvoiceError::CannotExport { .. } => ErrorKind::Transport,
        InvoiceError::Undelivered { .. }
        | InvoiceError::PaymentUndelivered { .. }
        | InvoiceError::NotPosted { .. } => ErrorKind::Incomplete,
        InvoiceError::UnknownSlate { .. } | InvoiceError::NotParked { .. } => ErrorKind::NotFound,
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
        | InvoiceError::PeerInputsSpent { .. } => ErrorKind::Rejected,
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
            (
                WalletError::NotReleasable {
                    tx_id: lepic_store::TxId(8),
                    reason: lepic_wallet::release::ReleaseRefusal::TooEarly {
                        from: Height::new(1_444),
                    },
                }
                .into(),
                ErrorKind::Rejected,
            ),
            (ReceiveError::ZeroAmount.into(), ErrorKind::Rejected),
            (CliError::DataDirInUse, ErrorKind::WalletState),
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
            (CliError::SlateId, ErrorKind::Usage),
            (CliError::PayloadId, ErrorKind::Usage),
            (CliError::PayloadHex, ErrorKind::Usage),
            (CliError::DomainNotConfigured, ErrorKind::Usage),
            (CliError::OwnerTlsNotConfigured, ErrorKind::Config),
            (
                CliError::ApiClientNotFound {
                    name: "laptop".to_owned(),
                },
                ErrorKind::NotFound,
            ),
            (CliError::NotRandomSlateId, ErrorKind::Usage),
            (CliError::SlateIdReused { tx_id: 1 }, ErrorKind::Rejected),
            (CliError::NoSendWithSlate, ErrorKind::NotFound),
            (CliError::ReplyFileForParked, ErrorKind::Usage),
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
}
