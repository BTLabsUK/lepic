//! The one error every call returns. Dart receives it as a thrown [`WalletError`] and branches on
//! [`WalletError::kind`] or the stable [`WalletError::code`], never on the message.

use lepic_keychain::AppDataError;
use lepic_telemetry::ErrorChain;
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::refresh::RefreshError;
use lepic_wallet::scan::ScanError;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::self_send::SelfSendError;
use lepic_wallet::send::SendError;
use lepic_wallet::{FinalizeError, ReceiveError};

/// What went wrong, in terms the app can act on. The numbers in [`WalletErrorKind::code`] are
/// part of the API and never change meaning; `bindings/flutter/README.md` lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletErrorKind {
    InvalidMnemonic,
    WrongPassword,
    WalletAlreadyExists,
    WalletNotFound,
    NodeUnreachable,
    NotEnoughFunds,
    InvalidSlate,
    InvalidArgument,
    /// The Epicbox relay could not be reached, refused, or the slate file could not be written
    /// or read.
    TransportFailed,
    /// Kept so code written for the earlier binding still compiles. LEPIC keeps no per-process
    /// chain, so it is never returned.
    ChainBusy,
    /// The wallet is already open, in this runtime or another one or another process, or open
    /// while it is being deleted.
    WalletBusy,
    /// The slate's time to live passed. Nothing was signed or posted.
    PaymentExpired,
    Io,
    Other,
    /// The wallet handle is locked; open it again.
    Locked,
    /// The data directory holds the database of another wallet or another network.
    ForeignWallet,
    /// The app's [`crate::api::secret_store::AppSecretStore`] failed or returned damaged data.
    SecretStore,
    /// The transaction was finalized and stored, but the node did not accept it. Post it again
    /// with `repost_transaction`.
    NotPosted,
    Cancelled,
    /// The operation is not available in this build or for this configuration.
    Unsupported,
    /// A defect inside LEPIC. The operation was abandoned; the wallet stays usable.
    Panic,
    /// The wallet was restored from its recovery phrase and no full scan has completed since,
    /// so it cannot create outputs yet. Run `scan` to the end, then try again.
    RestoreScanRequired,
    /// Another operation, for example the Epicbox listener finalizing it, changed the
    /// transaction while it was being cancelled. Nothing was cancelled; cancelling again
    /// decides from the new state.
    ChangedDuringCancel,
    /// The node already holds the transaction's kernel, so it can no longer be cancelled or
    /// released. The next refresh confirms it.
    OnChain,
    /// The app data file is intact but belongs to a wallet with another seed.
    ForeignAppData,
    /// The app data file belongs to this wallet but was changed or cut short.
    DamagedAppData,
    /// The node's transaction pool holds the transaction, so it may still be mined and is not
    /// released. Refresh later.
    InPool,
    /// The transaction is not a finalized or posted send, or no refresh has yet missed its
    /// kernel at `TransactionDetails.releasable_from` or above. The message says which.
    NotReleasable,
    /// No invoice with that slate id waits on the invoice address to be paid or declined: it
    /// was paid, declined, deleted by a sweep, or never arrived.
    InvoiceNotFound,
    /// The invoice asks for another amount than the one the user typed. Nothing was paid.
    AmountMismatch,
    /// The invoice or its payment is stored, but the relay did not take it. Deliver a payment
    /// again with `resend_invoice_payment`, or cancel either with `cancel_transaction`.
    NotDelivered,
    /// The wallet database was damaged. LEPIC renamed it, with its log files, to
    /// `wallet.sqlite3.damaged-<unix seconds>` in the data directory and kept it. Opening the
    /// wallet again rebuilds the database from the vault, as for a restore: run `scan` to the
    /// end before sending or receiving. Transaction history, labels and messages are not in the
    /// new database.
    DamagedDatabase,
    /// The address of the other wallet is not an `http(s)://host[:port][/path]` URL, or names
    /// a `.onion` host. Nothing was stored.
    HttpUrlInvalid,
    /// The address uses plain `http` to another computer, and the user did not agree to send
    /// unencrypted. Nothing was stored; ask, then pass `allow_plain_http`, or use `https`.
    PlainHttpNotAllowed,
    /// The address given to a Tor send is not an onion v3 address, or has a typo. Nothing was
    /// stored.
    OnionAddressInvalid,
    /// The wallet's tor is not running or not yet connected to the Tor network. Start it with
    /// `start_tor` and wait for `Bootstrapped`. A send that failed with it before anything was
    /// sent stored nothing; one whose tor stopped during the delivery is stored as sent.
    TorNotRunning,
    /// The other wallet is not online with Tor on, or could not be reached in time. The send
    /// is stored as sent with its inputs locked: resend it later or cancel it.
    OnionUnreachable,
    /// The change is too small to split into the change outputs asked for: fewer base units
    /// than outputs. Nothing was stored; ask for fewer change outputs.
    ChangeTooSmall,
    /// The transaction would spend more inputs or make more outputs than a transaction may
    /// hold. Nothing was stored; send a smaller amount, or consolidate first.
    TooHeavy,
    /// `consolidate_outputs` found fewer than two spendable outputs, so there is nothing to
    /// merge. Nothing was stored.
    NothingToConsolidate,
}

impl WalletErrorKind {
    /// The stable number of this kind.
    pub const fn code(self) -> u32 {
        match self {
            Self::InvalidMnemonic => 1,
            Self::WrongPassword => 2,
            Self::WalletAlreadyExists => 3,
            Self::WalletNotFound => 4,
            Self::NodeUnreachable => 5,
            Self::NotEnoughFunds => 6,
            Self::InvalidSlate => 7,
            Self::InvalidArgument => 8,
            Self::TransportFailed => 9,
            Self::ChainBusy => 10,
            Self::WalletBusy => 11,
            Self::PaymentExpired => 12,
            Self::Io => 13,
            Self::Other => 14,
            Self::Locked => 15,
            Self::ForeignWallet => 16,
            Self::SecretStore => 17,
            Self::NotPosted => 18,
            Self::Cancelled => 19,
            Self::Unsupported => 20,
            Self::Panic => 21,
            Self::RestoreScanRequired => 22,
            Self::ChangedDuringCancel => 23,
            Self::OnChain => 24,
            Self::ForeignAppData => 25,
            Self::DamagedAppData => 26,
            Self::InPool => 27,
            Self::NotReleasable => 28,
            Self::InvoiceNotFound => 29,
            Self::AmountMismatch => 30,
            Self::NotDelivered => 31,
            Self::DamagedDatabase => 37,
            Self::HttpUrlInvalid => 40,
            Self::PlainHttpNotAllowed => 41,
            Self::OnionAddressInvalid => 42,
            Self::TorNotRunning => 43,
            Self::OnionUnreachable => 44,
            Self::ChangeTooSmall => 45,
            Self::TooHeavy => 46,
            Self::NothingToConsolidate => 47,
        }
    }
}

/// The error of every fallible call. `message` is English for logs and bug reports; it never
/// holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletError {
    pub kind: WalletErrorKind,
    /// `kind.code()`, for apps that store or transmit the error.
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({}): {}", self.kind, self.code, self.message)
    }
}

impl std::error::Error for WalletError {}

impl WalletError {
    pub(crate) fn new(kind: WalletErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: kind.code(),
            message: message.into(),
        }
    }

    fn chained(kind: WalletErrorKind, error: &(dyn std::error::Error + 'static)) -> Self {
        Self::new(kind, ErrorChain(error).to_string())
    }
}

impl From<lepic_wallet::WalletError> for WalletError {
    fn from(error: lepic_wallet::WalletError) -> Self {
        Self::chained(engine_kind(&error), &error)
    }
}

fn engine_kind(error: &lepic_wallet::WalletError) -> WalletErrorKind {
    use lepic_wallet::WalletError as E;
    match error {
        E::Config(_)
        | E::WalletSeedFile(_)
        | E::Account(_)
        | E::UnknownTransaction(_)
        | E::Transition(_) => WalletErrorKind::InvalidArgument,
        E::WalletExists => WalletErrorKind::WalletAlreadyExists,
        E::NoWallet => WalletErrorKind::WalletNotFound,
        E::WrongPassword => WalletErrorKind::WrongPassword,
        E::Locked => WalletErrorKind::Locked,
        E::AlreadyOpen => WalletErrorKind::WalletBusy,
        E::NetworkMismatch { .. } | E::ForeignDatabase => WalletErrorKind::ForeignWallet,
        E::Mnemonic(_) => WalletErrorKind::InvalidMnemonic,
        E::Store(lepic_store::StoreError::DamagedSetAside) => WalletErrorKind::DamagedDatabase,
        E::Store(_) => WalletErrorKind::Io,
        E::SecretVault(_) | E::SecretStore(_) => WalletErrorKind::SecretStore,
        // The node reported a chain position the wallet does not believe.
        E::Implausible(_) | E::Node(_) => WalletErrorKind::NodeUnreachable,
        E::RestoreScanRequired => WalletErrorKind::RestoreScanRequired,
        E::ChangedDuringCancel(_) => WalletErrorKind::ChangedDuringCancel,
        E::OnChain(_) => WalletErrorKind::OnChain,
        E::InPool(_) => WalletErrorKind::InPool,
        E::NotReleasable { .. } => WalletErrorKind::NotReleasable,
        E::AppData(error) => app_data_kind(error),
        _ => WalletErrorKind::Other,
    }
}

fn app_data_kind(error: &AppDataError) -> WalletErrorKind {
    match error {
        AppDataError::ForeignWallet => WalletErrorKind::ForeignAppData,
        AppDataError::Damaged => WalletErrorKind::DamagedAppData,
        AppDataError::UnsupportedVersion { .. } => WalletErrorKind::Unsupported,
        AppDataError::NotAppData | AppDataError::TooLong { .. } => WalletErrorKind::InvalidArgument,
        _ => WalletErrorKind::Other,
    }
}

impl From<SendError> for WalletError {
    fn from(error: SendError) -> Self {
        let kind = match &error {
            SendError::Wallet(inner) => return Self::from_inner(inner, &error),
            SendError::Node(_) => WalletErrorKind::NodeUnreachable,
            SendError::Selection(SelectionError::NotEnoughFunds { .. }) => {
                WalletErrorKind::NotEnoughFunds
            }
            SendError::Selection(SelectionError::ChangeTooSmall { .. }) => {
                WalletErrorKind::ChangeTooSmall
            }
            SendError::Selection(SelectionError::TooHeavy { .. }) => WalletErrorKind::TooHeavy,
            SendError::Selection(SelectionError::NothingToConsolidate { .. }) => {
                WalletErrorKind::NothingToConsolidate
            }
            SendError::Selection(_)
            | SendError::NotResendable { .. }
            | SendError::PayeeMismatch { .. }
            | SendError::UnknownTransport { .. }
            | SendError::CannotDeliver { .. }
            | SendError::CannotExport { .. } => WalletErrorKind::InvalidArgument,
            SendError::Undelivered { .. } => WalletErrorKind::TransportFailed,
            SendError::Unrepresentable(_) => WalletErrorKind::InvalidSlate,
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<ReceiveError> for WalletError {
    fn from(error: ReceiveError) -> Self {
        let kind = match &error {
            ReceiveError::Wallet(inner) => return Self::from_inner(inner, &error),
            ReceiveError::Decode(_)
            | ReceiveError::WrongStage { .. }
            | ReceiveError::AlreadyReceived { .. }
            | ReceiveError::AheadOfTip { .. }
            | ReceiveError::FeeBelowMinimum { .. }
            | ReceiveError::MessageSignature { .. }
            | ReceiveError::ForeignProofAddress
            | ReceiveError::Slate(_) => WalletErrorKind::InvalidSlate,
            ReceiveError::Expired { .. } => WalletErrorKind::PaymentExpired,
            ReceiveError::Node(_) => WalletErrorKind::NodeUnreachable,
            ReceiveError::UnknownTransport { .. } => WalletErrorKind::InvalidArgument,
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<SelfSendError> for WalletError {
    fn from(error: SelfSendError) -> Self {
        match error {
            SelfSendError::Send(error) => error.into(),
            SelfSendError::Receive(error) => error.into(),
            SelfSendError::Finalize(error) => error.into(),
            other => Self::chained(WalletErrorKind::Other, &other),
        }
    }
}

impl From<FinalizeError> for WalletError {
    fn from(error: FinalizeError) -> Self {
        use FinalizeError as E;
        let kind = match &error {
            E::Wallet(inner) => return Self::from_inner(inner, &error),
            E::Decode(_)
            | E::WrongStage { .. }
            | E::UnknownSlate { .. }
            | E::AlreadyFinalized { .. }
            | E::Mismatch { .. }
            | E::MissingPaymentProof
            | E::ForeignSenderAddress
            | E::PaymentProofSignature
            | E::MessageSignature(_)
            | E::ReceiverSignature(_)
            | E::FeeBelowMinimum { .. }
            | E::InvalidTransaction(_)
            | E::Slate(_) => WalletErrorKind::InvalidSlate,
            E::Expired { .. } => WalletErrorKind::PaymentExpired,
            E::Node(_) => WalletErrorKind::NodeUnreachable,
            E::NotPosted { .. } => WalletErrorKind::NotPosted,
            E::NotFinalizable { .. } | E::NotPostable { .. } | E::UnknownTransport { .. } => {
                WalletErrorKind::InvalidArgument
            }
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<ScanError> for WalletError {
    fn from(error: ScanError) -> Self {
        let kind = match &error {
            ScanError::Wallet(inner) => return Self::from_inner(inner, &error),
            ScanError::Node(_) => WalletErrorKind::NodeUnreachable,
            ScanError::Cancelled => WalletErrorKind::Cancelled,
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<RefreshError> for WalletError {
    fn from(error: RefreshError) -> Self {
        let kind = match &error {
            RefreshError::Wallet(inner) => return Self::from_inner(inner, &error),
            RefreshError::Node(_) => WalletErrorKind::NodeUnreachable,
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<InboxError> for WalletError {
    fn from(error: InboxError) -> Self {
        let kind = match &error {
            InboxError::Wallet(inner) => return Self::from_inner(inner, &error),
            InboxError::NetworkMismatch
            | InboxError::UnknownTransport { .. }
            | InboxError::Address(_)
            | InboxError::PaymentsAddressIndex
            | InboxError::InvoiceIndexExhausted
            | InboxError::InvoiceExpiry
            | InboxError::SenderLabel => WalletErrorKind::InvalidArgument,
            InboxError::Subscription(_) | InboxError::Transport(_) => {
                WalletErrorKind::TransportFailed
            }
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<InvoiceError> for WalletError {
    fn from(error: InvoiceError) -> Self {
        use InvoiceError as E;
        let kind = match &error {
            E::Wallet(inner) => return Self::from_inner(inner, &error),
            E::Node(_) => WalletErrorKind::NodeUnreachable,
            E::Selection(SelectionError::NotEnoughFunds { .. }) => WalletErrorKind::NotEnoughFunds,
            E::Selection(_)
            | E::UnknownTransport { .. }
            | E::CannotDeliver { .. }
            | E::CannotExport { .. }
            | E::NotFinalizable { .. } => WalletErrorKind::InvalidArgument,
            E::Decode(_)
            | E::WrongStage { .. }
            | E::AlreadyPaid { .. }
            | E::AlreadyFinalized { .. }
            | E::UnknownSlate { .. }
            | E::MessageSignature { .. }
            | E::Mismatch { .. }
            | E::PayerSignature(_)
            | E::FeeBelowMinimum { .. }
            | E::InvalidTransaction(_)
            | E::Slate(_)
            | E::Encode(_)
            | E::Unrepresentable(_)
            | E::LockedUntil { .. }
            | E::AheadOfTip { .. } => WalletErrorKind::InvalidSlate,
            E::AmountMismatch { .. } => WalletErrorKind::AmountMismatch,
            E::Expired { .. } => WalletErrorKind::PaymentExpired,
            E::NotParked { .. } => WalletErrorKind::InvoiceNotFound,
            E::Undelivered { .. } | E::PaymentUndelivered { .. } => WalletErrorKind::NotDelivered,
            E::NotPosted { .. } => WalletErrorKind::NotPosted,
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl WalletError {
    /// The kind of the engine error inside `outer`, with the message of the whole chain.
    fn from_inner(
        inner: &lepic_wallet::WalletError,
        outer: &(dyn std::error::Error + 'static),
    ) -> Self {
        Self::chained(engine_kind(inner), outer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The codes are API: `bindings/flutter/README.md` lists them and apps store them.
    #[test]
    fn error_codes_are_stable_and_unique() {
        use WalletErrorKind as K;
        let expected = [
            (K::InvalidMnemonic, 1),
            (K::WrongPassword, 2),
            (K::WalletAlreadyExists, 3),
            (K::WalletNotFound, 4),
            (K::NodeUnreachable, 5),
            (K::NotEnoughFunds, 6),
            (K::InvalidSlate, 7),
            (K::InvalidArgument, 8),
            (K::TransportFailed, 9),
            (K::ChainBusy, 10),
            (K::WalletBusy, 11),
            (K::PaymentExpired, 12),
            (K::Io, 13),
            (K::Other, 14),
            (K::Locked, 15),
            (K::ForeignWallet, 16),
            (K::SecretStore, 17),
            (K::NotPosted, 18),
            (K::Cancelled, 19),
            (K::Unsupported, 20),
            (K::Panic, 21),
            (K::RestoreScanRequired, 22),
            (K::ChangedDuringCancel, 23),
            (K::OnChain, 24),
            (K::ForeignAppData, 25),
            (K::DamagedAppData, 26),
            (K::InPool, 27),
            (K::NotReleasable, 28),
            (K::InvoiceNotFound, 29),
            (K::AmountMismatch, 30),
            (K::NotDelivered, 31),
            (K::DamagedDatabase, 37),
            (K::HttpUrlInvalid, 40),
            (K::PlainHttpNotAllowed, 41),
            (K::OnionAddressInvalid, 42),
            (K::TorNotRunning, 43),
            (K::OnionUnreachable, 44),
            (K::ChangeTooSmall, 45),
            (K::TooHeavy, 46),
            (K::NothingToConsolidate, 47),
        ];
        for (kind, code) in expected {
            assert_eq!(kind.code(), code, "{kind:?}");
            assert_eq!(WalletError::new(kind, "x").code, code);
        }
    }

    #[test]
    fn selection_refusals_that_are_about_funds_have_their_own_kinds() {
        use lepic_primitives::amount::Amount;
        let cases = [
            (
                SelectionError::ChangeTooSmall {
                    change: Amount::new(2),
                    outputs: 3,
                },
                WalletErrorKind::ChangeTooSmall,
            ),
            (
                SelectionError::TooHeavy {
                    inputs: 900,
                    outputs: 2,
                },
                WalletErrorKind::TooHeavy,
            ),
            (
                SelectionError::NotEnoughFunds {
                    available: Amount::new(1),
                    needed: Amount::new(2),
                },
                WalletErrorKind::NotEnoughFunds,
            ),
            (
                SelectionError::NothingToConsolidate { outputs: 1 },
                WalletErrorKind::NothingToConsolidate,
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(WalletError::from(SendError::Selection(error)).kind, kind);
        }
    }

    #[test]
    fn engine_errors_keep_their_kind_inside_operation_errors() {
        let locked = WalletError::from(SendError::Wallet(lepic_wallet::WalletError::Locked));
        assert_eq!(locked.kind, WalletErrorKind::Locked);
        let wrong = WalletError::from(lepic_wallet::WalletError::WrongPassword);
        assert_eq!(wrong.kind, WalletErrorKind::WrongPassword);
        assert_eq!(
            WalletError::from(ScanError::Cancelled).kind,
            WalletErrorKind::Cancelled
        );
    }

    #[test]
    fn restore_scan_and_cancel_refusals_have_their_own_kinds() {
        use lepic_wallet::WalletError as E;
        let tx = lepic_store::TxId(4);
        let cases = [
            (E::RestoreScanRequired, WalletErrorKind::RestoreScanRequired),
            (
                E::ChangedDuringCancel(tx),
                WalletErrorKind::ChangedDuringCancel,
            ),
            (E::OnChain(tx), WalletErrorKind::OnChain),
            (E::InPool(tx), WalletErrorKind::InPool),
            (
                E::Node(lepic_node::NodeError::Timeout),
                WalletErrorKind::NodeUnreachable,
            ),
            (
                E::NotReleasable {
                    tx_id: tx,
                    reason: lepic_wallet::release::ReleaseRefusal::KernelUnknown,
                },
                WalletErrorKind::NotReleasable,
            ),
        ];
        for (engine, kind) in cases {
            assert_eq!(WalletError::from(engine).kind, kind);
        }
        let receive = WalletError::from(ReceiveError::Wallet(E::RestoreScanRequired));
        assert_eq!(receive.kind, WalletErrorKind::RestoreScanRequired);
    }

    #[test]
    fn invoice_refusals_have_their_own_kinds() {
        use lepic_primitives::amount::Amount;
        use lepic_wallet::event::SlateId;
        let slate_id = SlateId::from_bytes([7; 16]);
        let tx_id = lepic_store::TxId(2);
        let undelivered = || lepic_transport::error::TransportError::UnknownDestination {
            transport: lepic_epicbox::TRANSPORT_ID,
        };
        let cases = [
            (
                InvoiceError::NotParked { slate_id },
                WalletErrorKind::InvoiceNotFound,
            ),
            (
                InvoiceError::AmountMismatch {
                    invoiced: Amount::new(2),
                    approved: Amount::new(1),
                },
                WalletErrorKind::AmountMismatch,
            ),
            (
                InvoiceError::PaymentUndelivered {
                    tx_id,
                    slate_id,
                    source: undelivered(),
                },
                WalletErrorKind::NotDelivered,
            ),
            (
                InvoiceError::Undelivered {
                    tx_id,
                    slate_id,
                    source: undelivered(),
                },
                WalletErrorKind::NotDelivered,
            ),
            (
                InvoiceError::Wallet(lepic_wallet::WalletError::Locked),
                WalletErrorKind::Locked,
            ),
            (
                InvoiceError::LockedUntil {
                    lock_height: lepic_primitives::amount::Height::new(9),
                    tip: lepic_primitives::amount::Height::new(4),
                },
                WalletErrorKind::InvalidSlate,
            ),
            (
                InvoiceError::AheadOfTip {
                    height: lepic_primitives::amount::Height::new(99),
                    limit: lepic_primitives::amount::Height::new(4),
                },
                WalletErrorKind::InvalidSlate,
            ),
            (
                InvoiceError::Selection(SelectionError::NotEnoughFunds {
                    needed: Amount::new(2),
                    available: Amount::new(1),
                }),
                WalletErrorKind::NotEnoughFunds,
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(WalletError::from(error).kind, kind);
        }
        for error in [
            InboxError::PaymentsAddressIndex,
            InboxError::InvoiceExpiry,
            InboxError::SenderLabel,
            InboxError::InvoiceIndexExhausted,
        ] {
            assert_eq!(
                WalletError::from(error).kind,
                WalletErrorKind::InvalidArgument
            );
        }
    }

    #[test]
    fn app_data_errors_map_to_their_kinds() {
        let kind = |error| WalletError::from(lepic_wallet::WalletError::AppData(error)).kind;
        assert_eq!(
            kind(AppDataError::ForeignWallet),
            WalletErrorKind::ForeignAppData
        );
        assert_eq!(kind(AppDataError::Damaged), WalletErrorKind::DamagedAppData);
        assert_eq!(
            kind(AppDataError::UnsupportedVersion { version: 2, kdf: 1 }),
            WalletErrorKind::Unsupported
        );
        assert_eq!(
            kind(AppDataError::NotAppData),
            WalletErrorKind::InvalidArgument
        );
        assert_eq!(
            kind(AppDataError::TooLong { actual: 2, max: 1 }),
            WalletErrorKind::InvalidArgument
        );
    }
}
