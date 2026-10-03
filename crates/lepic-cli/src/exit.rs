//! Typed command failures and the exit codes they map to. The codes are part of the CLI's
//! interface: scripts branch on them, so a code never changes meaning.

use std::error::Error as StdError;

use lepic_node::NodeError;
use lepic_store::StoreError;
use lepic_telemetry::TelemetryError;
use lepic_transport::error::TransportError;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::refresh::RefreshError;
use lepic_wallet::scan::ScanError;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::send::SendError;
use lepic_wallet::{AccountError, ReceiveError, WalletError};
use thiserror::Error;

use crate::amount::AmountError;
use crate::secret::SecretError;
use crate::settings::SettingsError;

/// What kind of failure ended a command. The discriminant is the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorKind {
    Internal = 1,
    Usage = 2,
    Config = 3,
    WrongPassword = 4,
    WalletState = 5,
    NotFound = 6,
    Rejected = 7,
    InsufficientFunds = 8,
    Node = 9,
    Transport = 10,
    Incomplete = 11,
    Interrupted = 12,
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
        self as u8
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
   5  wallet_state: no wallet, a wallet already exists, or it belongs elsewhere
   6  not_found: no such transaction, slate or account
   7  rejected: the slate or request was refused; nothing was stored
   8  insufficient_funds: not enough spendable funds
   9  node: the node could not be reached or answered badly
  10  transport: the slate file or relay failed
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
    #[error("wallet database failed")]
    Store(#[from] StoreError),
    #[error("give --to or --to-file")]
    NoDestination,
    #[error("transport registration failed")]
    Registry(#[from] lepic_transport::error::RegistryError),
    #[error("could not {what}")]
    Io {
        what: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("stopped before it finished")]
    Interrupted,
    #[error("other users can access the data directory")]
    SharedDataDir,
}

impl CliError {
    pub fn io(what: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { what, source }
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Settings(_) | Self::Telemetry(_) | Self::SharedDataDir => ErrorKind::Config,
            Self::Secret(SecretError::Mismatch) => ErrorKind::Rejected,
            Self::Secret(_) | Self::Amount(_) | Self::Zero { .. } | Self::NoDestination => {
                ErrorKind::Usage
            }
            Self::Wallet(error) => wallet_kind(error),
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
            Self::Scan(ScanError::Cancelled) | Self::Interrupted => ErrorKind::Interrupted,
            Self::Transport(_) => ErrorKind::Transport,
            Self::Refresh(_)
            | Self::Scan(_)
            | Self::Store(_)
            | Self::Registry(_)
            | Self::Io { .. } => ErrorKind::Internal,
        }
    }

    /// The message and every cause under it, outermost first. Repeated texts, as when a
    /// wrapper prints its source, appear once.
    pub fn chain(&self) -> Vec<String> {
        let mut messages: Vec<String> = Vec::new();
        let mut next: Option<&dyn StdError> = Some(self);
        while let Some(error) = next {
            let text = error.to_string();
            if messages.last() != Some(&text) {
                messages.push(text);
            }
            next = error.source();
        }
        messages
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
        | WalletError::OnChain(_)
        | WalletError::ChangedDuringCancel(_) => ErrorKind::Rejected,
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
        | SendError::NotResendable { .. } => ErrorKind::Rejected,
        SendError::UnknownTransport { .. }
        | SendError::CannotDeliver { .. }
        | SendError::CannotExport { .. } => ErrorKind::Transport,
        SendError::Undelivered { .. } => ErrorKind::Incomplete,
        _ => ErrorKind::Internal,
    }
}

fn receive_kind(error: &ReceiveError) -> ErrorKind {
    match error {
        ReceiveError::Wallet(error) => wallet_kind(error),
        ReceiveError::UnknownTransport { .. } => ErrorKind::Transport,
        ReceiveError::Node(_) => ErrorKind::Node,
        ReceiveError::Decode(_)
        | ReceiveError::WrongStage { .. }
        | ReceiveError::AlreadyReceived { .. }
        | ReceiveError::Expired { .. }
        | ReceiveError::FeeBelowMinimum { .. }
        | ReceiveError::FeeOverflow
        | ReceiveError::MessageSignature { .. }
        | ReceiveError::ForeignProofAddress
        | ReceiveError::ZeroAmount => ErrorKind::Rejected,
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
        | FinalizeError::PaymentProofSignature
        | FinalizeError::MessageSignature(_)
        | FinalizeError::ReceiverSignature(_)
        | FinalizeError::FeeBelowMinimum { .. }
        | FinalizeError::FeeOverflow
        | FinalizeError::InvalidTransaction(_)
        | FinalizeError::NotPostable { .. } => ErrorKind::Rejected,
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
        InvoiceError::Undelivered { .. } | InvoiceError::NotPosted { .. } => ErrorKind::Incomplete,
        InvoiceError::UnknownSlate { .. } => ErrorKind::NotFound,
        InvoiceError::Decode(_)
        | InvoiceError::WrongStage { .. }
        | InvoiceError::Selection(_)
        | InvoiceError::AmountMismatch { .. }
        | InvoiceError::AlreadyPaid { .. }
        | InvoiceError::Expired { .. }
        | InvoiceError::MessageSignature { .. }
        | InvoiceError::Mismatch { .. }
        | InvoiceError::PayerSignature(_)
        | InvoiceError::FeeBelowMinimum { .. }
        | InvoiceError::FeeOverflow
        | InvoiceError::InvalidTransaction(_)
        | InvoiceError::Unrepresentable(_)
        | InvoiceError::AlreadyFinalized { .. }
        | InvoiceError::NotFinalizable { .. } => ErrorKind::Rejected,
        _ => ErrorKind::Internal,
    }
}

fn inbox_kind(error: &InboxError) -> ErrorKind {
    match error {
        InboxError::Wallet(error) => wallet_kind(error),
        InboxError::UnknownTransport { .. } | InboxError::NetworkMismatch => ErrorKind::Config,
        InboxError::Subscription(_) | InboxError::Transport(_) => ErrorKind::Transport,
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
            (ReceiveError::FeeOverflow.into(), ErrorKind::Rejected),
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
            (ReceiveError::ZeroAmount.into(), ErrorKind::Rejected),
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
