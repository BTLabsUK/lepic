//! The one error every call returns. Dart receives it as a thrown [`WalletError`] and branches on
//! [`WalletError::kind`] or the stable [`WalletError::code`], never on the message.

use lepic_keychain::AppDataError;
use lepic_wallet::error_text::{display_error_chain, display_error_message};
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::refresh::RefreshError;
use lepic_wallet::scan::ScanError;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::self_send::SelfSendError;
use lepic_wallet::send::SendError;
use lepic_wallet::{FinalizeError, ReceiveError};
use lepic_wallet_contacts::{ContactError, InPersonRefusal};

/// What went wrong, in terms the app can act on. The numbers in [`WalletErrorKind::code`] are
/// part of the API and never change meaning; the binding's README lists them.
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
    /// No invoice with that slate id waits to be paid or declined: it was paid, declined,
    /// deleted by a sweep, or never arrived.
    InvoiceNotFound,
    /// The invoice asks for another amount than the one the user typed. Nothing was paid.
    AmountMismatch,
    /// The invoice or its payment is stored, but the relay did not take it. Cancel it with
    /// `cancel_transaction`.
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
    /// `send_to_self` found fewer than two spendable outputs, so there is nothing to
    /// merge. Nothing was stored.
    NothingToConsolidate,
    /// The invoice was already paid: this wallet holds its payment, or finalized it. Nothing
    /// was signed or posted again.
    InvoiceAlreadyPaid,
    /// The invoice's lock height is above the chain tip, so its transaction cannot be mined
    /// yet. Nothing was signed; pay or finalize it once the chain reaches that height.
    InvoiceLockedAboveTip,
    /// The payer's answer changed a field of the invoice this wallet issued: the amount, the
    /// lock height, the offset, the issuer's outputs or its data. Nothing was finalized or posted.
    InvoiceChanged,
    /// The scanned QR code is not a slate code at all, for example an address or a web link.
    /// Drop that scan and keep the parts scanned before it.
    NotUrCode,
    /// The scanned QR code is a uniform resource of another type, such as another wallet's
    /// transaction code. Drop that scan and keep the parts scanned before it.
    ForeignUrCode,
    /// The scanned parts belong to two different slate codes. Start over with the newest scan.
    MixedUrCodes,
    /// A slate code is damaged or of a newer version than this LEPIC reads.
    InvalidUrCode,
    /// The slate is too large to show as QR codes, or scanned parts exceed what one code
    /// holds. Use a file instead.
    UrCodeTooLarge,
    /// The user chose Offline, so the contact call reached no relay. Nothing was sent or
    /// fetched; whatever was stored stays.
    ContactsOffline,
    /// Epicbox is switched off, so the contact call reached no relay. Nothing was sent or
    /// fetched; whatever was stored stays.
    EpicboxOff,
    /// The link, card, reply or sealed text is damaged, is not one, or is for the other
    /// network. Nothing was stored.
    InvalidPairingText,
    /// The name cannot go in a contact card: empty, too long, or with characters a card
    /// refuses. Nothing was stored.
    InvalidContactName,
    /// The invite expired. Ask for a new one.
    InviteExpired,
    /// The invite, reply or card belongs to a contact this wallet is paired with already, or
    /// to this wallet itself. Nothing was stored.
    AlreadyPaired,
    /// No paired contact has that id, or it is not in the state the call needs, such as a
    /// card this wallet does not show or a contact whose keys changed.
    ContactNotFound,
    /// No pairing in progress has that id: it completed, failed or was cancelled.
    PairingNotFound,
    /// The contact's words were not checked, or its invoices are not allowed: invoices need
    /// a verified contact. Nothing was paid or changed.
    ContactNotVerified,
    /// Pairing words are offered only on LEPIC's built-in relays, and this wallet's relay is
    /// not one. Share the link instead.
    PairingWordsUnavailable,
    /// Sealing is off for the contact, or its wallet cannot open sealed text. Send the slate
    /// plain.
    SealingOff,
    /// The transaction has no slate this wallet can send, or the outbox holds no entry with
    /// that id.
    NoSlateToSend,
    /// The sealed text is for another wallet or another install of this one, or was signed
    /// by someone who is not the contact. Nothing was stored.
    SealedForAnotherWallet,
    /// The sealed text does not open: it was changed on the way. Nothing was stored.
    SealedUnopenable,
    /// A key check is allowed once per pairing and within a day of the new pairing; this one
    /// is not. Keep the new pairing as it is or remove it.
    KeyCheckRefused,
    /// No invite was found for these words: they are wrong, expired, or were used.
    PairingWordsNotFound,
    /// A word is not in the pairing words table, or there are not five.
    InvalidPairingWords,
    /// The contact's wallet says it does not pay invoices. Nothing was sent.
    ContactRefusesInvoices,
    /// The recovery phrase given to `reset_password` belongs to another wallet than the
    /// database in the wallet directory. Nothing was changed.
    PhraseMismatch,
    /// The invoice was made for another network, or its heights are wrong: its time to live
    /// ends further ahead than any issuer sets it, or it was made at a height the chain cannot
    /// have reached. Nothing was paid or stored.
    InvoiceNotForThisChain,
    /// The node refused the transaction because inputs of it are no longer unspent: another
    /// wallet on the same recovery phrase spent them. The send was cancelled, its other inputs
    /// released, and a refresh ran; the other wallet's spend shows as a transaction of origin
    /// `OtherWallet`.
    InputsSpentElsewhere,
    /// The invite, contact or call is of the other pairing class: a private invite answered as
    /// a contact or the other way round, words asked for a private pairing, or a slate or
    /// invoice for a private pairing. Nothing was stored or sent.
    WrongPairingClass,
    /// The wallet was opened offline (`WalletConfig.offline`), so the call reached no node or
    /// relay, or found no confirmed tip to work offline from. Nothing was sent; what was
    /// stored stays.
    Offline,
    /// The node refused the transaction because inputs of it are no longer unspent, and
    /// another transaction of this wallet whose kernel the chain holds spent them: a cancelled
    /// payment that was mined before the move of its coins back to the wallet, or that move
    /// mined before the payment's late post. The refused transaction was cancelled and stays
    /// watched, and a refresh ran; the other transaction shows as confirmed. Nothing was lost
    /// to another wallet.
    InputsSpentByOwnTransaction,
    /// The node refused the transaction because inputs the other party added are no longer
    /// unspent: the other party spent them elsewhere, as a payer does who cancelled an
    /// invoice payment and moved its coins, so the payment can never be mined. The
    /// transaction was cancelled and stays watched, so a refresh still confirms it if it is
    /// mined after all, and a refresh ran.
    PeerInputsSpent,
    /// The pairing proves another payments address than the one given. Nothing changed.
    OtherAddress,
    /// A payments address was given, and the pairing proves none. Nothing changed; try again
    /// after the contact's card with a proof arrives.
    AddressProofMissing,
    /// `pairing_request_send` to a key that did not run LEPIC lately, answered unmarked since,
    /// or never claimed pair requests. Nothing was sent; offer the invite instead.
    PeerNotProven,
    /// A request or answer toward a wallet that already has a pairing in progress here, one
    /// waiting for it, or a live request from it. Show that pairing or request.
    PairingInProgress,
    /// This wallet's own pairing with the same wallet wins under the lower-key rule: keep
    /// waiting for its answer. Nothing changed.
    PairingCrossed,
    /// The invite of a request this wallet dismissed. Ask for a new one.
    InviteDismissed,
    /// The pairing ended: nothing new goes through it. Offer to remove it.
    PairingEnded,
    /// The contact's wallet has not been heard in this pairing yet: no sealed send or invoice.
    PairingWaiting,
    /// A payment asked for a payment proof that this wallet does not sign: one for another
    /// key than its own, or any proof for a payment to a listing address. Nothing was signed
    /// or stored.
    ForeignProofAddress,
    /// The wallet's encrypted database does not open with the key its recovery phrase gives:
    /// its key check refuses it. Nothing was changed or moved. Recover with the phrase only
    /// if it is this wallet's; the database is kept.
    WrongKey,
    /// The inviter's card names another contact kind than its invite did. Nothing was stored;
    /// pair again.
    PairingKindDiffers,
    /// The relay given to `EpicWallet::contact_apply_relay_move` is not the one the contact
    /// asked to move to (`ContactView::requested_relay`), or the contact asked for no move.
    /// Nothing changed.
    RelayMoveNotRequested,
    /// This wallet holds no in-person code or answer for the slate, or no answer with that
    /// number was taken for the code.
    InPersonNotFound,
    /// `EpicWallet::in_person_post` was called without the user confirming the relay the
    /// answer goes to. Nothing was posted.
    RelayNotConfirmed,
    /// The in-person code named no reply mailbox: show the answer instead of posting it.
    InPersonNoMailbox,
    /// The QR parts scanned do not make a whole code yet: keep scanning and pass every part
    /// scanned so far.
    UrCodeIncomplete,
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
            Self::InvoiceAlreadyPaid => 48,
            Self::InvoiceLockedAboveTip => 49,
            Self::InvoiceChanged => 50,
            Self::NotUrCode => 51,
            Self::ForeignUrCode => 52,
            Self::MixedUrCodes => 53,
            Self::InvalidUrCode => 54,
            Self::UrCodeTooLarge => 55,
            Self::ContactsOffline => 56,
            Self::EpicboxOff => 57,
            Self::InvalidPairingText => 58,
            Self::InvalidContactName => 59,
            Self::InviteExpired => 60,
            Self::AlreadyPaired => 61,
            Self::ContactNotFound => 62,
            Self::PairingNotFound => 63,
            Self::ContactNotVerified => 64,
            Self::PairingWordsUnavailable => 65,
            Self::SealingOff => 66,
            Self::NoSlateToSend => 67,
            Self::SealedForAnotherWallet => 68,
            Self::SealedUnopenable => 69,
            Self::KeyCheckRefused => 70,
            Self::PairingWordsNotFound => 71,
            Self::InvalidPairingWords => 72,
            Self::ContactRefusesInvoices => 73,
            Self::PhraseMismatch => 74,
            Self::InvoiceNotForThisChain => 75,
            Self::InputsSpentElsewhere => 76,
            Self::WrongPairingClass => 77,
            Self::Offline => 78,
            Self::InputsSpentByOwnTransaction => 79,
            Self::PeerInputsSpent => 80,
            Self::OtherAddress => 81,
            Self::AddressProofMissing => 82,
            Self::PeerNotProven => 83,
            Self::PairingInProgress => 84,
            Self::PairingCrossed => 85,
            Self::InviteDismissed => 86,
            Self::PairingEnded => 87,
            Self::PairingWaiting => 88,
            // 83 to 88 belong to the pairing kinds.
            Self::ForeignProofAddress => 89,
            Self::WrongKey => 90,
            Self::PairingKindDiffers => 91,
            Self::RelayMoveNotRequested => 92,
            Self::InPersonNotFound => 93,
            Self::RelayNotConfirmed => 94,
            Self::InPersonNoMailbox => 95,
            Self::UrCodeIncomplete => 96,
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
    /// The transaction a failed call stored and left behind with its inputs locked, when a
    /// later step failed or the call's own clean-up cancel failed: cancel it with
    /// `cancel_transaction`, or try its step again. `None` when nothing was left behind.
    pub tx_id: Option<u32>,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ({}): {}", self.kind, self.code, self.message)
    }
}

impl std::error::Error for WalletError {}

impl WalletError {
    /// The message can quote a node, a peer or a file, so it is cleaned and bounded for display.
    pub(crate) fn new(kind: WalletErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: kind.code(),
            message: display_error_message(&message.into()),
            tx_id: None,
        }
    }

    /// This error, naming the transaction the call left stored with its inputs locked.
    pub(crate) fn with_tx(mut self, tx_id: u32) -> Self {
        self.tx_id = Some(tx_id);
        self
    }

    /// `error` and its sources as the message, each entry cleaned and bounded on its own.
    /// A chain that holds a refusal of an offline session's node or relay port is `Offline`,
    /// whatever `kind` the operation gives its other failures.
    pub(crate) fn chained(
        kind: WalletErrorKind,
        error: &(dyn std::error::Error + 'static),
    ) -> Self {
        let kind = if refused_offline(error) {
            WalletErrorKind::Offline
        } else {
            kind
        };
        Self::new(kind, display_error_chain(error).join(": "))
    }
}

/// Whether `error` or one of its sources is the refusal of an offline session's port.
fn refused_offline(error: &(dyn std::error::Error + 'static)) -> bool {
    std::iter::successors(Some(error), |error| error.source()).any(|error| {
        matches!(
            error.downcast_ref::<lepic_node::NodeError>(),
            Some(lepic_node::NodeError::Offline)
        ) || error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            .is_some_and(<dyn std::error::Error + Send + Sync>::is::<crate::session::RelayOffline>)
    })
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
        | E::Transition(_)
        | E::MinimumConfirmationsOutOfRange { .. }
        | E::PartnerPosted { .. } => WalletErrorKind::InvalidArgument,
        E::WalletExists => WalletErrorKind::WalletAlreadyExists,
        E::NoWallet => WalletErrorKind::WalletNotFound,
        E::WrongPassword => WalletErrorKind::WrongPassword,
        E::Locked => WalletErrorKind::Locked,
        E::AlreadyOpen => WalletErrorKind::WalletBusy,
        E::NetworkMismatch { .. } | E::ForeignDatabase => WalletErrorKind::ForeignWallet,
        E::Mnemonic(_) => WalletErrorKind::InvalidMnemonic,
        E::Store(lepic_store::StoreError::DamagedSetAside | lepic_store::StoreError::Damaged) => {
            WalletErrorKind::DamagedDatabase
        }
        E::Store(lepic_store::StoreError::WrongKey) => WalletErrorKind::WrongKey,
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
        // A slate stored but not delivered keeps its inputs locked until it is sent again or
        // cancelled, so the caller needs the transaction.
        let left_behind = match &error {
            SendError::Undelivered { tx_id, .. } => Some(tx_id.0),
            _ => None,
        };
        let mut wallet_error = Self::from_send(&error);
        wallet_error.tx_id = left_behind;
        wallet_error
    }
}

impl WalletError {
    fn from_send(error: &SendError) -> Self {
        let kind = match error {
            SendError::Wallet(inner) => return Self::from_inner(inner, error),
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
        Self::chained(kind, error)
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
            | ReceiveError::Slate(_) => WalletErrorKind::InvalidSlate,
            ReceiveError::ForeignProofAddress => WalletErrorKind::ForeignProofAddress,
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
            | E::UnexpectedAnswerer { .. }
            | E::PaymentProofSignature
            | E::MessageSignature(_)
            | E::ReceiverSignature(_)
            | E::FeeBelowMinimum { .. }
            | E::InvalidTransaction(_)
            | E::Slate(_) => WalletErrorKind::InvalidSlate,
            E::Expired { .. } => WalletErrorKind::PaymentExpired,
            E::Node(_) => WalletErrorKind::NodeUnreachable,
            E::NotPosted { .. } => WalletErrorKind::NotPosted,
            E::InputsSpentElsewhere { .. } => WalletErrorKind::InputsSpentElsewhere,
            E::InputsSpentByOwnTransaction { .. } => WalletErrorKind::InputsSpentByOwnTransaction,
            E::PeerInputsSpent { .. } => WalletErrorKind::PeerInputsSpent,
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
            | InboxError::InvoiceExpiry
            | InboxError::NotHostFeature => WalletErrorKind::InvalidArgument,
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
            | E::UnknownSlate { .. }
            | E::MessageSignature { .. }
            | E::PayerSignature(_)
            | E::FeeBelowMinimum { .. }
            | E::InvalidTransaction(_)
            | E::Slate(_)
            | E::Encode(_)
            | E::Unrepresentable(_) => WalletErrorKind::InvalidSlate,
            E::AheadOfTip { .. } | E::TtlTooFarAhead { .. } | E::TtlTooFarBehind { .. } => {
                WalletErrorKind::InvoiceNotForThisChain
            }
            E::AlreadyPaid { .. } | E::AlreadyFinalized { .. } => {
                WalletErrorKind::InvoiceAlreadyPaid
            }
            E::LockedUntil { .. } => WalletErrorKind::InvoiceLockedAboveTip,
            E::Mismatch { .. } => WalletErrorKind::InvoiceChanged,
            E::AmountMismatch { .. } => WalletErrorKind::AmountMismatch,
            E::Expired { .. } => WalletErrorKind::PaymentExpired,
            E::NotParked { .. } => WalletErrorKind::InvoiceNotFound,
            E::Undelivered { .. } | E::PaymentUndelivered { .. } => WalletErrorKind::NotDelivered,
            E::NotPosted { .. } => WalletErrorKind::NotPosted,
            E::InputsSpentElsewhere { .. } => WalletErrorKind::InputsSpentElsewhere,
            E::InputsSpentByOwnTransaction { .. } => WalletErrorKind::InputsSpentByOwnTransaction,
            E::PeerInputsSpent { .. } => WalletErrorKind::PeerInputsSpent,
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<ContactError> for WalletError {
    fn from(error: ContactError) -> Self {
        use ContactError as E;
        use WalletErrorKind as K;
        // What failed first names the kind; the transaction is the one left stored, and the
        // failed cancel is in the message.
        let error = match error {
            E::NotCancelled {
                tx_id,
                cause,
                cancel,
            } => {
                let mut mapped = Self::from(*cause);
                mapped.message = display_error_message(&format!(
                    "{}; transaction {tx_id} is still stored and could not be cancelled: {cancel}",
                    mapped.message
                ));
                return mapped.with_tx(tx_id.0);
            }
            other => other,
        };
        let kind = match error {
            E::Wallet(inner) => return inner.into(),
            E::Receive(inner) => return inner.into(),
            E::Invoice(inner) => return inner.into(),
            E::Finalize(inner) => return inner.into(),
            E::Send(inner) => return inner.into(),
            ref other => match other {
                E::Offline => K::ContactsOffline,
                E::EpicboxOff => K::EpicboxOff,
                E::NetworkMismatch | E::RelayAddress | E::TooLarge { .. } => K::InvalidArgument,
                // Text the user gave; data the wallet stored itself that fails to read is
                // StoredData, a defect, and maps to Other below.
                E::Decode(_) => K::InvalidPairingText,
                E::Name(_) => K::InvalidContactName,
                E::InviteExpired => K::InviteExpired,
                E::AlreadyPaired => K::AlreadyPaired,
                E::UnknownContact => K::ContactNotFound,
                E::UnknownPairing => K::PairingNotFound,
                E::NotVerified => K::ContactNotVerified,
                E::Relay(_) => K::TransportFailed,
                E::WordsUnavailable => K::PairingWordsUnavailable,
                E::SealOff => K::SealingOff,
                E::UnknownTransaction => K::NoSlateToSend,
                E::NotForThisInstall => K::SealedForAnotherWallet,
                E::CannotOpen => K::SealedUnopenable,
                E::NotASlate | E::Stage(_) => K::InvalidSlate,
                E::KeyCheckRefused => K::KeyCheckRefused,
                E::WordsNotFound => K::PairingWordsNotFound,
                E::Words(_) => K::InvalidPairingWords,
                E::DoesNotPayInvoices => K::ContactRefusesInvoices,
                E::WrongClass => K::WrongPairingClass,
                E::OtherAddress => K::OtherAddress,
                E::AddressProofMissing => K::AddressProofMissing,
                E::KindDiffers => K::PairingKindDiffers,
                E::PeerNotProven => K::PeerNotProven,
                E::PairingInProgress => K::PairingInProgress,
                E::Crossed => K::PairingCrossed,
                E::InviteDismissed => K::InviteDismissed,
                E::Ended => K::PairingEnded,
                E::Waiting => K::PairingWaiting,
                E::RelayMoveNotRequested => K::RelayMoveNotRequested,
                E::Domain(_) | E::NoDomainConfigured | E::NoDomainClaim => K::InvalidArgument,
                E::Post(_) => K::TransportFailed,
                E::Native(_) => K::InvalidSlate,
                E::InPerson(refusal) => in_person_kind(*refusal),
                _ => K::Other,
            },
        };
        Self::chained(kind, &error)
    }
}

/// The kind of an in-person refusal: a code or answer refused is an invalid slate.
const fn in_person_kind(refusal: InPersonRefusal) -> WalletErrorKind {
    use InPersonRefusal as R;
    use WalletErrorKind as K;
    match refusal {
        R::NoCode | R::NoAnswer => K::InPersonNotFound,
        R::RelayNotConfirmed => K::RelayNotConfirmed,
        R::NoMailbox => K::InPersonNoMailbox,
        R::UrIncomplete => K::UrCodeIncomplete,
        R::StoredAnswer => K::Other,
        _ => K::InvalidSlate,
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

    #[test]
    fn messages_are_cleaned_and_bounded() {
        let planted = format!("\u{1b}[2J\u{202E}\u{2066}{}\n", "x".repeat(50_000));
        let error = lepic_node::NodeError::Connect(Box::new(std::io::Error::other(planted)));
        let hidden = |c: char| {
            c.is_control()
                || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}'..='\u{200F}')
        };
        for wallet_error in [
            WalletError::chained(WalletErrorKind::NodeUnreachable, &error),
            WalletError::new(
                WalletErrorKind::InvalidSlate,
                error.to_string() + &"y".repeat(9_000),
            ),
        ] {
            let message = &wallet_error.message;
            assert!(!message.chars().any(hidden), "{message:?}");
            assert!(message.chars().count() <= 16 * 258, "{}", message.len());
        }
        let chained = WalletError::chained(WalletErrorKind::NodeUnreachable, &error);
        assert!(
            chained
                .message
                .split(": ")
                .all(|entry| entry.chars().count() <= 256)
        );
    }

    /// The codes are API: the binding's README lists them and apps store them.
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
            (K::InvoiceAlreadyPaid, 48),
            (K::InvoiceLockedAboveTip, 49),
            (K::InvoiceChanged, 50),
            (K::NotUrCode, 51),
            (K::ForeignUrCode, 52),
            (K::MixedUrCodes, 53),
            (K::InvalidUrCode, 54),
            (K::UrCodeTooLarge, 55),
            (K::ContactsOffline, 56),
            (K::EpicboxOff, 57),
            (K::InvalidPairingText, 58),
            (K::InvalidContactName, 59),
            (K::InviteExpired, 60),
            (K::AlreadyPaired, 61),
            (K::ContactNotFound, 62),
            (K::PairingNotFound, 63),
            (K::ContactNotVerified, 64),
            (K::PairingWordsUnavailable, 65),
            (K::SealingOff, 66),
            (K::NoSlateToSend, 67),
            (K::SealedForAnotherWallet, 68),
            (K::SealedUnopenable, 69),
            (K::KeyCheckRefused, 70),
            (K::PairingWordsNotFound, 71),
            (K::InvalidPairingWords, 72),
            (K::ContactRefusesInvoices, 73),
            (K::PhraseMismatch, 74),
            (K::InvoiceNotForThisChain, 75),
            (K::InputsSpentElsewhere, 76),
            (K::WrongPairingClass, 77),
            (K::Offline, 78),
            (K::InputsSpentByOwnTransaction, 79),
            (K::PeerInputsSpent, 80),
            (K::OtherAddress, 81),
            (K::AddressProofMissing, 82),
            (K::PeerNotProven, 83),
            (K::PairingInProgress, 84),
            (K::PairingCrossed, 85),
            (K::InviteDismissed, 86),
            (K::PairingEnded, 87),
            (K::PairingWaiting, 88),
            (K::ForeignProofAddress, 89),
            (K::WrongKey, 90),
            (K::PairingKindDiffers, 91),
            (K::RelayMoveNotRequested, 92),
            (K::InPersonNotFound, 93),
            (K::RelayNotConfirmed, 94),
            (K::InPersonNoMailbox, 95),
            (K::UrCodeIncomplete, 96),
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
        for error in [
            SelectionError::NoOutputsNamed,
            SelectionError::NamedOutputUnavailable { position: 2 },
        ] {
            assert_eq!(
                WalletError::from(SendError::Selection(error)).kind,
                WalletErrorKind::InvalidArgument
            );
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
    fn refused_posts_whose_inputs_were_spent_say_by_whom() {
        let tx_id = lepic_store::TxId(3);
        let by = lepic_store::TxId(2);
        let source = || lepic_node::NodeError::Timeout;
        let finalize = [
            (
                FinalizeError::NotPosted {
                    tx_id,
                    source: source(),
                },
                WalletErrorKind::NotPosted,
            ),
            (
                FinalizeError::InputsSpentElsewhere {
                    tx_id,
                    source: source(),
                },
                WalletErrorKind::InputsSpentElsewhere,
            ),
            (
                FinalizeError::InputsSpentByOwnTransaction {
                    tx_id,
                    by,
                    source: source(),
                },
                WalletErrorKind::InputsSpentByOwnTransaction,
            ),
            (
                FinalizeError::PeerInputsSpent {
                    tx_id,
                    source: source(),
                },
                WalletErrorKind::PeerInputsSpent,
            ),
        ];
        for (error, kind) in finalize {
            assert_eq!(WalletError::from(error).kind, kind);
        }
        let invoice = [
            (
                InvoiceError::InputsSpentByOwnTransaction {
                    tx_id,
                    by,
                    source: source(),
                },
                WalletErrorKind::InputsSpentByOwnTransaction,
            ),
            (
                InvoiceError::PeerInputsSpent {
                    tx_id,
                    source: source(),
                },
                WalletErrorKind::PeerInputsSpent,
            ),
        ];
        for (error, kind) in invoice {
            assert_eq!(WalletError::from(error).kind, kind);
        }
        let self_send = SelfSendError::Finalize(FinalizeError::InputsSpentByOwnTransaction {
            tx_id,
            by,
            source: source(),
        });
        assert_eq!(
            WalletError::from(self_send).kind,
            WalletErrorKind::InputsSpentByOwnTransaction
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
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
                WalletErrorKind::InvoiceLockedAboveTip,
            ),
            (
                InvoiceError::AheadOfTip {
                    height: lepic_primitives::amount::Height::new(99),
                    limit: lepic_primitives::amount::Height::new(4),
                },
                WalletErrorKind::InvoiceNotForThisChain,
            ),
            (
                InvoiceError::TtlTooFarAhead {
                    cutoff: lepic_primitives::amount::Height::new(3_771_440),
                    limit: lepic_primitives::amount::Height::new(2_884),
                },
                WalletErrorKind::InvoiceNotForThisChain,
            ),
            (
                InvoiceError::TtlTooFarBehind {
                    cutoff: lepic_primitives::amount::Height::new(2_240),
                    limit: lepic_primitives::amount::Height::new(3_244_400),
                },
                WalletErrorKind::InvoiceNotForThisChain,
            ),
            (
                InvoiceError::Expired {
                    cutoff: lepic_primitives::amount::Height::new(3_771_440),
                    tip: lepic_primitives::amount::Height::new(3_771_500),
                },
                WalletErrorKind::PaymentExpired,
            ),
            (
                InvoiceError::Selection(SelectionError::NotEnoughFunds {
                    needed: Amount::new(2),
                    available: Amount::new(1),
                }),
                WalletErrorKind::NotEnoughFunds,
            ),
            (
                InvoiceError::AlreadyPaid { slate_id, tx_id },
                WalletErrorKind::InvoiceAlreadyPaid,
            ),
            (
                InvoiceError::AlreadyFinalized { slate_id, tx_id },
                WalletErrorKind::InvoiceAlreadyPaid,
            ),
            (
                InvoiceError::Mismatch {
                    field: lepic_wallet::invoice::InvoiceField::Amount,
                },
                WalletErrorKind::InvoiceChanged,
            ),
            (
                InvoiceError::Mismatch {
                    field: lepic_wallet::invoice::InvoiceField::Outputs,
                },
                WalletErrorKind::InvoiceChanged,
            ),
        ];
        for (error, kind) in cases {
            let message = error.to_string();
            let mapped = WalletError::from(error);
            assert_eq!(mapped.kind, kind);
            assert_eq!(mapped.code, kind.code());
            assert!(mapped.message.contains(&message), "{}", mapped.message);
        }
        assert_eq!(
            WalletError::from(InboxError::InvoiceExpiry).kind,
            WalletErrorKind::InvalidArgument
        );
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

    #[test]
    fn pairing_refusals_have_their_own_kinds() {
        use ContactError as E;
        use WalletErrorKind as K;
        let cases = [
            (E::Offline, K::ContactsOffline),
            (E::EpicboxOff, K::EpicboxOff),
            (E::InviteExpired, K::InviteExpired),
            (E::AlreadyPaired, K::AlreadyPaired),
            (E::UnknownContact, K::ContactNotFound),
            (E::UnknownPairing, K::PairingNotFound),
            (E::NotVerified, K::ContactNotVerified),
            (E::WordsUnavailable, K::PairingWordsUnavailable),
            (E::SealOff, K::SealingOff),
            (E::UnknownTransaction, K::NoSlateToSend),
            (E::NotForThisInstall, K::SealedForAnotherWallet),
            (E::CannotOpen, K::SealedUnopenable),
            (E::NotASlate, K::InvalidSlate),
            (E::KeyCheckRefused, K::KeyCheckRefused),
            (E::WordsNotFound, K::PairingWordsNotFound),
            (E::DoesNotPayInvoices, K::ContactRefusesInvoices),
            (E::OtherAddress, K::OtherAddress),
            (E::AddressProofMissing, K::AddressProofMissing),
            (E::KindDiffers, K::PairingKindDiffers),
            (E::PeerNotProven, K::PeerNotProven),
            (E::PairingInProgress, K::PairingInProgress),
            (E::Crossed, K::PairingCrossed),
            (E::InviteDismissed, K::InviteDismissed),
            (E::Ended, K::PairingEnded),
            (E::Waiting, K::PairingWaiting),
            (E::RelayMoveNotRequested, K::RelayMoveNotRequested),
            (E::NoDomainConfigured, K::InvalidArgument),
            (E::NoDomainClaim, K::InvalidArgument),
            (E::NetworkMismatch, K::InvalidArgument),
            (E::TooLarge { max: 1 }, K::InvalidArgument),
            (E::InPerson(InPersonRefusal::NoCode), K::InPersonNotFound),
            (E::InPerson(InPersonRefusal::NoAnswer), K::InPersonNotFound),
            (
                E::InPerson(InPersonRefusal::RelayNotConfirmed),
                K::RelayNotConfirmed,
            ),
            (
                E::InPerson(InPersonRefusal::NoMailbox),
                K::InPersonNoMailbox,
            ),
            (
                E::InPerson(InPersonRefusal::UrIncomplete),
                K::UrCodeIncomplete,
            ),
            (E::InPerson(InPersonRefusal::Proof), K::InvalidSlate),
            (E::InPerson(InPersonRefusal::Loopback), K::InvalidSlate),
            (E::Wallet(lepic_wallet::WalletError::Locked), K::Locked),
            (
                E::Invoice(InvoiceError::NotParked {
                    slate_id: lepic_wallet::event::SlateId::from_bytes([1; 16]),
                }),
                K::InvoiceNotFound,
            ),
        ];
        for (error, kind) in cases {
            let mapped = WalletError::from(error);
            assert_eq!(mapped.kind, kind);
            assert_eq!(mapped.code, kind.code());
        }
    }
}
