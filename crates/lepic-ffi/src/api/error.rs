//! The one error every call returns. Dart receives it as a thrown [`WalletError`] and branches on
//! [`WalletError::kind`] or the stable [`WalletError::code`], never on the message.

use flutter_rust_bridge::frb;
use lepic_keychain::AppDataError;
use lepic_wallet::error_text::{display_error_chain, display_error_message};
use lepic_wallet::inbox::InboxError;
use lepic_wallet::invoice::InvoiceError;
use lepic_wallet::refresh::RefreshError;
use lepic_wallet::relay_cancel::RelayCancelError;
use lepic_wallet::scan::ScanError;
use lepic_wallet::selection::SelectionError;
use lepic_wallet::self_send::SelfSendError;
use lepic_wallet::send::SendError;
use lepic_wallet::{FinalizeError, ReceiveError};
use lepic_wallet_contacts::{
    ContactEncodeError, ContactError, Epic1Refusal, InPersonRefusal, MailboxListError,
};

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
    /// The transaction was finalized and stored, but the node did not accept it. A refresh
    /// pushes it again until it is mined or its cutoff passes; `repost_transaction` pushes it
    /// at once.
    NotPosted,
    /// The operation, or the transaction it was for, was cancelled.
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
    /// recovered. The next refresh confirms it.
    OnChain,
    /// The app data file is intact but belongs to a wallet with another seed.
    ForeignAppData,
    /// The app data file belongs to this wallet but was changed or cut short.
    DamagedAppData,
    /// The node's transaction pool holds the transaction, so it may still be mined and is not
    /// recovered. Refresh later.
    InPool,
    /// No invoice with that slate id waits to be paid or declined: it was paid, declined,
    /// deleted by a sweep, or never arrived.
    InvoiceNotFound,
    /// The invoice asks for another amount than the one the user typed. Nothing was paid.
    AmountMismatch,
    /// The invoice or its payment is stored, but the relay did not take it. Cancel it with
    /// `cancel_transaction`.
    NotDelivered,
    /// The wallet database was damaged. LEPIC renamed it, with its log files, to
    /// `wallet.sqlite3.damaged-<unix seconds>` in the data directory and kept it;
    /// [`WalletError::set_aside`] names the file. Nothing new was made: opening again fails
    /// with `DamagedKept`. Ask the user, then call `start_over` (or `start_over_with_pin`),
    /// which makes a new, empty database from the vault, as for a restore: run `scan` to the
    /// end before sending or receiving. Transaction history, labels and messages are not in
    /// the new database; they stay in the set-aside file.
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
    /// No longer produced; kept for its number.
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
    /// A request or answer toward a wallet that already has a pairing in progress here or one
    /// waiting for it. Show that pairing.
    PairingInProgress,
    /// This wallet's own pairing with the same wallet wins under the lower-key rule: keep
    /// waiting for its answer. Nothing changed.
    PairingCrossed,
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
    /// The in-person code named no reply mailbox: show the answer instead of posting it.
    InPersonNoMailbox,
    /// The QR parts scanned do not make a whole code yet: keep scanning and pass every part
    /// scanned so far.
    UrCodeIncomplete,
    /// The text is a record another Epic wallet keeps in its `saved_txs` directory, not a
    /// payment file.
    SavedTransaction,
    /// The epic1 link names no transport this wallet can use.
    Epic1CannotPay,
    /// The payment went to every transport of the link: none is left to try.
    Epic1NoMoreRelays,
    /// The wallet holds no epic1 payment or answer for the slate, or the address was never
    /// handed out by this wallet.
    Epic1NotFound,
    /// A link entry is not an `http` host or onion with an optional port, its host is on this
    /// device, or there are more than three.
    Epic1RelayInvalid,
    /// The message is longer than a link carries or holds control characters.
    Epic1MessageInvalid,
    /// The epic1 payment was finalized already.
    Epic1Finalized,
    /// The epic1 link or its slate is for another network than the wallet.
    Epic1WrongNetwork,
    /// The text is not an epic1 link.
    NotAnEpic1Link,
    /// The wallet's database was written by a newer LEPIC or app version than this one reads.
    /// Nothing was changed; update the app to open the wallet. Do not delete or restore it.
    WalletTooNew,
    /// The mailbox refused the slate because the other party cancelled the transaction there.
    /// Nothing changes in this wallet: the transaction (`tx_id`) keeps its inputs locked until
    /// it is cancelled here or expires.
    CancelledOnRelay,
    /// The transaction has a recovery that may still be mined or has not reached its
    /// confirmations: it cannot be recovered again or cancelled until that recovery ends.
    RecoveryOpen,
    /// The transaction cannot be recovered: it is not a send that is finalized, posted,
    /// cancelled or expired, its inputs are not all held for it, or they cannot pay the fee of
    /// the recovery. Nothing was stored.
    NotRecoverable,
    /// The payment spends so many outputs that its slate, or the receiver's answer to it, is
    /// longer than the Epicbox relay takes; `message` gives the size and the limit. Nothing was
    /// stored. Consolidate the wallet's outputs or pay a smaller amount.
    SlateTooLarge,
    /// The payer and the payee share no mailbox: the payer's list holds none of the shipped
    /// ones. `message` names them. Add one back, or pay with the payee's mailbox given in
    /// `mailboxes`. Nothing was stored.
    NoSharedMailbox,
    /// The mailbox is not a host name with an optional port other than 0.
    MailboxInvalid,
    /// The mailbox is on this device or a private network, which no other device reaches.
    MailboxNotPublic,
    /// The mailbox list holds 16 mailboxes, as many as it may.
    MailboxListFull,
    /// The mailbox is the last one of the list, which may not go.
    LastMailbox,
    /// The data directory holds no wallet database, and a damaged one that was set aside
    /// earlier is kept there; [`WalletError::set_aside`] names it. Nothing was made. Opening
    /// again gives this again; `start_over` (or `start_over_with_pin`) makes a new, empty
    /// database once the user asks for it. Unlike `DamagedDatabase`, retrying the open never
    /// helps.
    DamagedKept,
    /// The text is an epic1 address or link of LEPIC 0.5 or earlier. This version cannot read
    /// it, and nothing was stored. When the link names a mailbox, [`WalletError::mailbox`] has
    /// it. Ask the payee for their Epicbox address (the one with an `@`) or an epic1 address
    /// or link from an updated wallet.
    EarlierEpic1Address,
    /// The node refused the transaction because inputs of it are no longer unspent, and a
    /// chain reorganisation took them: the blocks that made them were replaced, and the
    /// transactions that made them are off chain for now. The transaction is finalized and
    /// stored, and stays open with its coins held; a refresh posts it again once they are
    /// mined again. Nothing was spent elsewhere. `repost_transaction` tries now, and a cancel
    /// gives up.
    InputsReorged,
}

impl WalletErrorKind {
    /// The stable number of this kind.
    #[allow(clippy::too_many_lines)] // One arm per kind.
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
            // 28 named a refused release, which was removed; it stays unused.
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
            // 57 named Epicbox switched off for contact calls, which go through mailboxes
            // whatever that switch says; it stays unused.
            Self::InvalidPairingText => 58,
            Self::InvalidContactName => 59,
            Self::InviteExpired => 60,
            Self::AlreadyPaired => 61,
            Self::ContactNotFound => 62,
            Self::PairingNotFound => 63,
            Self::ContactNotVerified => 64,
            // 65 named pairing words a relay outside the built-in ones could not offer; words
            // work on every mailbox now, so it stays unused.
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
            // No kind has 83 or 86, and neither number is given to another kind.
            Self::PairingInProgress => 84,
            Self::PairingCrossed => 85,
            Self::PairingEnded => 87,
            Self::PairingWaiting => 88,
            Self::ForeignProofAddress => 89,
            Self::WrongKey => 90,
            Self::PairingKindDiffers => 91,
            Self::RelayMoveNotRequested => 92,
            Self::InPersonNotFound => 93,
            // 94 was a refusal to post an in-person answer; it is not reused.
            Self::InPersonNoMailbox => 95,
            Self::UrCodeIncomplete => 96,
            // 97 to 101 were refusals of a native send over HTTP or Tor; they are not reused.
            Self::SavedTransaction => 102,
            Self::Epic1CannotPay => 103,
            Self::Epic1NoMoreRelays => 104,
            // 105 named an account holding as many open epic1 links as it may; an account has
            // one address and stores no links, so it stays unused.
            Self::Epic1NotFound => 106,
            // 107 named an own relay on this device; a payment names no own relay now, so it
            // stays unused.
            Self::Epic1RelayInvalid => 108,
            Self::Epic1MessageInvalid => 109,
            Self::Epic1Finalized => 110,
            Self::Epic1WrongNetwork => 111,
            Self::NotAnEpic1Link => 112,
            Self::WalletTooNew => 113,
            // No kind has 114, and the number is not given to another kind.
            Self::CancelledOnRelay => 115,
            Self::RecoveryOpen => 116,
            Self::NotRecoverable => 117,
            Self::SlateTooLarge => 118,
            Self::NoSharedMailbox => 119,
            Self::MailboxInvalid => 120,
            Self::MailboxNotPublic => 121,
            Self::MailboxListFull => 122,
            Self::LastMailbox => 123,
            Self::DamagedKept => 124,
            Self::EarlierEpic1Address => 125,
            Self::InputsReorged => 126,
        }
    }
}

/// The error of every fallible call. `message` is English for logs and bug reports; it never
/// holds a secret.
///
/// In Dart `toString` prints the kind, the code and the message, so a log line or an
/// unhandled exception names the failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[frb(dart_code = "@override String toString() => 'WalletError(${kind.name}, $code): $message';")]
pub struct WalletError {
    pub kind: WalletErrorKind,
    /// `kind.code()`, for apps that store or transmit the error.
    pub code: u32,
    pub message: String,
    /// The transaction a failed call stored and left behind with its inputs locked, when a
    /// later step failed or the call's own clean-up cancel failed: cancel it with
    /// `cancel_transaction`, or try its step again. `None` when nothing was left behind.
    pub tx_id: Option<u32>,
    /// The file a damaged database was moved to, for `DamagedDatabase` and `DamagedKept`.
    /// `None` for every other kind.
    pub set_aside: Option<String>,
    /// The seconds a mailbox or peer asked the wallet to wait before it posts again, when a
    /// refusal named a wait (a rate limit or a full slot): a send, a payment or a contact
    /// message can be tried again after it. A longer wait than `u32` holds reads as `u32::MAX`.
    pub retry_after_secs: Option<u32>,
    /// The mailbox, `host[:port]`, that refused a post (a rate limit, a full slot, a refusal),
    /// or that an epic1 link of an earlier release names (`EarlierEpic1Address`). `None` when
    /// the error names none, as for a bare address or a refusal of a native endpoint.
    pub mailbox: Option<String>,
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
            set_aside: None,
            retry_after_secs: None,
            mailbox: None,
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
        if kind == WalletErrorKind::WalletTooNew
            && let Some((found, supported)) = schema_too_new(error)
        {
            return Self::new(
                kind,
                format!(
                    "this wallet was saved by a newer version of the app (store version \
                     {found}; this version reads up to {supported}): update the app to open it"
                ),
            );
        }
        let mut mapped = Self::new(kind, display_error_chain(error).join(": "));
        mapped.retry_after_secs = lepic_wallet_contacts::retry_after_of(error)
            .map(|wait| u32::try_from(wait.as_secs()).unwrap_or(u32::MAX));
        mapped.mailbox = lepic_wallet_contacts::mailbox_of(error);
        mapped
    }
}

/// The versions of the store error `error` or one of its sources is.
fn schema_too_new(error: &(dyn std::error::Error + 'static)) -> Option<(u32, u32)> {
    std::iter::successors(Some(error), |error| error.source()).find_map(|error| {
        match error.downcast_ref::<lepic_store::StoreError>() {
            Some(lepic_store::StoreError::SchemaTooNew { found, supported }) => {
                Some((*found, *supported))
            }
            _ => None,
        }
    })
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
        let mut mapped = Self::chained(engine_kind(&error), &error);
        if let lepic_wallet::WalletError::Store(
            lepic_store::StoreError::DamagedSetAside { set_aside }
            | lepic_store::StoreError::DamagedKept { set_aside },
        ) = &error
        {
            mapped.set_aside = Some(set_aside.display().to_string());
        }
        mapped
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
        E::Store(
            lepic_store::StoreError::DamagedSetAside { .. } | lepic_store::StoreError::Damaged,
        ) => WalletErrorKind::DamagedDatabase,
        E::Store(lepic_store::StoreError::DamagedKept { .. }) => WalletErrorKind::DamagedKept,
        E::Store(lepic_store::StoreError::WrongKey) => WalletErrorKind::WrongKey,
        E::Store(lepic_store::StoreError::SchemaTooNew { .. }) => WalletErrorKind::WalletTooNew,
        E::Store(_) => WalletErrorKind::Io,
        E::SecretVault(_) | E::SecretStore(_) => WalletErrorKind::SecretStore,
        // The node reported a chain position the wallet does not believe.
        E::Implausible(_) | E::Node(_) => WalletErrorKind::NodeUnreachable,
        E::RestoreScanRequired => WalletErrorKind::RestoreScanRequired,
        E::ChangedDuringCancel(_) => WalletErrorKind::ChangedDuringCancel,
        E::OnChain(_) => WalletErrorKind::OnChain,
        E::InPool(_) => WalletErrorKind::InPool,
        E::RecoveryOpen(_) => WalletErrorKind::RecoveryOpen,
        E::NotRecoverable(_) => WalletErrorKind::NotRecoverable,
        E::AppData(error) => app_data_kind(error),
        E::InvalidListing => WalletErrorKind::InvalidArgument,
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

/// The kind of a change the mailbox list refused.
fn mailbox_kind(error: &MailboxListError) -> WalletErrorKind {
    match error {
        MailboxListError::NotAName => WalletErrorKind::MailboxInvalid,
        MailboxListError::NotPublic => WalletErrorKind::MailboxNotPublic,
        MailboxListError::Full => WalletErrorKind::MailboxListFull,
        MailboxListError::Last => WalletErrorKind::LastMailbox,
        _ => WalletErrorKind::InvalidArgument,
    }
}

impl From<MailboxListError> for WalletError {
    fn from(error: MailboxListError) -> Self {
        Self::new(mailbox_kind(&error), error.to_string())
    }
}

impl From<SendError> for WalletError {
    fn from(error: SendError) -> Self {
        // A slate stored but not delivered keeps its inputs locked until it is sent again or
        // cancelled, so the caller needs the transaction.
        let left_behind = match &error {
            SendError::Undelivered { tx_id, .. } | SendError::CancelledOnRelay { tx_id, .. } => {
                Some(tx_id.0)
            }
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
            | SendError::CannotExport { .. }
            | SendError::SlateIdTaken { .. }
            | SendError::FeeAboveMaximum { .. }
            | SendError::ProofAddress(_) => WalletErrorKind::InvalidArgument,
            SendError::Undelivered { .. } => WalletErrorKind::TransportFailed,
            SendError::CancelledOnRelay { .. } => WalletErrorKind::CancelledOnRelay,
            SendError::Unrepresentable(_) => WalletErrorKind::InvalidSlate,
            SendError::SlateTooLarge { .. } => WalletErrorKind::SlateTooLarge,
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
            | ReceiveError::ZeroAmount
            | ReceiveError::AboveSupply { .. }
            | ReceiveError::FeeOverflow
            | ReceiveError::Slate(_) => WalletErrorKind::InvalidSlate,
            ReceiveError::ForeignProofAddress => WalletErrorKind::ForeignProofAddress,
            ReceiveError::Expired { .. } => WalletErrorKind::PaymentExpired,
            ReceiveError::Node(_) => WalletErrorKind::NodeUnreachable,
            ReceiveError::UnknownTransport { .. } => WalletErrorKind::InvalidArgument,
            ReceiveError::OpenReceipts(_) => WalletErrorKind::WalletBusy,
            // The wallet's settings refuse payments nobody asked for.
            ReceiveError::Refused => WalletErrorKind::Unsupported,
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
            | E::FeeOverflow
            | E::Slate(_) => WalletErrorKind::InvalidSlate,
            E::Expired { .. } => WalletErrorKind::PaymentExpired,
            E::Node(_) => WalletErrorKind::NodeUnreachable,
            E::NotPosted { .. } => WalletErrorKind::NotPosted,
            E::InputsReorged { .. } => WalletErrorKind::InputsReorged,
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
            | InboxError::InvoiceExpiry => WalletErrorKind::InvalidArgument,
            InboxError::Subscription(_) | InboxError::Transport(_) => {
                WalletErrorKind::TransportFailed
            }
            _ => WalletErrorKind::Other,
        };
        Self::chained(kind, &error)
    }
}

impl From<RelayCancelError> for WalletError {
    fn from(error: RelayCancelError) -> Self {
        let kind = match &error {
            RelayCancelError::Wallet(inner) => return Self::from_inner(inner, &error),
            RelayCancelError::Transport(_) => WalletErrorKind::TransportFailed,
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
            | E::ToAddress
            | E::UnknownTransport { .. }
            | E::CannotExport { .. }
            | E::SlateIdTaken { .. }
            | E::NotFinalizable { .. } => WalletErrorKind::InvalidArgument,
            E::Decode(_)
            | E::WrongStage { .. }
            | E::UnknownSlate { .. }
            | E::MessageSignature { .. }
            | E::PayerSignature(_)
            | E::FeeBelowMinimum { .. }
            | E::FeeOverflow
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
            E::InputsReorged { .. } => WalletErrorKind::InputsReorged,
            E::InputsSpentElsewhere { .. } => WalletErrorKind::InputsSpentElsewhere,
            E::InputsSpentByOwnTransaction { .. } => WalletErrorKind::InputsSpentByOwnTransaction,
            E::PeerInputsSpent { .. } | E::AnswerInputsSpent { .. } => {
                WalletErrorKind::PeerInputsSpent
            }
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
                E::RelayNotRead(_) => K::TransportFailed,
                E::NoSharedMailbox { .. } => K::NoSharedMailbox,
                E::Mailboxes(error) => mailbox_kind(error),
                E::SealOff => K::SealingOff,
                E::UnknownTransaction => K::NoSlateToSend,
                E::NotForThisInstall => K::SealedForAnotherWallet,
                E::CannotOpen => K::SealedUnopenable,
                E::NotASlate | E::Stage(_) => K::InvalidSlate,
                E::KeyCheckRefused => K::KeyCheckRefused,
                E::WordsNotFound => K::PairingWordsNotFound,
                E::DoesNotPayInvoices => K::ContactRefusesInvoices,
                E::WrongClass => K::WrongPairingClass,
                E::OtherAddress => K::OtherAddress,
                E::AddressProofMissing => K::AddressProofMissing,
                E::KindDiffers => K::PairingKindDiffers,
                E::PairingInProgress => K::PairingInProgress,
                E::Crossed => K::PairingCrossed,
                E::Ended => K::PairingEnded,
                E::Waiting => K::PairingWaiting,
                E::RelayMoveNotRequested => K::RelayMoveNotRequested,
                E::Domain(_) | E::NoDomainConfigured | E::NoDomainClaim => K::InvalidArgument,
                E::Native(_) => K::InvalidSlate,
                E::InPerson(refusal) => in_person_kind(*refusal),
                E::Epic1(refusal) => epic1_kind(*refusal),
                E::Epic1Link(link) if link.is_earlier_address() => K::EarlierEpic1Address,
                E::Epic1Link(_) => K::NotAnEpic1Link,
                E::Encode(inner) => contact_encode_kind(*inner),
                E::SavedTransaction => K::SavedTransaction,
                // As the decoder refused such text before the payment-file classifier.
                E::NotPaymentFile => K::InvalidPairingText,
                _ => K::Other,
            },
        };
        Self::chained(kind, &error)
    }
}

/// The kind of a card or envelope that could not be built. Every variant is named, so a new
/// one is mapped where it is added.
const fn contact_encode_kind(error: ContactEncodeError) -> WalletErrorKind {
    use ContactEncodeError as E;
    use WalletErrorKind as K;
    match error {
        E::FieldTooLong { .. } | E::BodyTooLarge { .. } | E::Oversized { .. } | E::WrongNetwork => {
            K::InvalidArgument
        }
        E::WrongClass => K::WrongPairingClass,
        E::ReplyRoute | E::SigningKeyMismatch | E::Encapsulation | E::Encryption => K::Other,
    }
}

/// The kind of an in-person refusal: a code or answer refused is an invalid slate.
const fn in_person_kind(refusal: InPersonRefusal) -> WalletErrorKind {
    use InPersonRefusal as R;
    use WalletErrorKind as K;
    match refusal {
        R::NoCode | R::NoAnswer => K::InPersonNotFound,
        R::NoMailbox => K::InPersonNoMailbox,
        R::UrIncomplete => K::UrCodeIncomplete,
        R::StoredAnswer => K::Other,
        R::TtlTooShort { .. } | R::DirectRoute | R::RepeatDiffers => K::InvalidArgument,
        R::Ended => K::Cancelled,
        _ => K::InvalidSlate,
    }
}

/// The kind of an epic1 refusal: a payment or answer refused is an invalid slate.
const fn epic1_kind(refusal: Epic1Refusal) -> WalletErrorKind {
    use Epic1Refusal as R;
    use WalletErrorKind as K;
    match refusal {
        // Tor is expected and only direct entries are left: no entry this payer may use.
        R::CannotPay | R::TorExpected => K::Epic1CannotPay,
        R::NoMoreEntries => K::Epic1NoMoreRelays,
        R::NoPayment => K::Epic1NotFound,
        R::LinkRelay | R::TooManyRelays => K::Epic1RelayInvalid,
        R::Message => K::Epic1MessageInvalid,
        R::Finalized => K::Epic1Finalized,
        R::WrongNetwork => K::Epic1WrongNetwork,
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
    #[allow(clippy::too_many_lines)] // One line per kind.
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
            (K::InvalidPairingText, 58),
            (K::InvalidContactName, 59),
            (K::InviteExpired, 60),
            (K::AlreadyPaired, 61),
            (K::ContactNotFound, 62),
            (K::PairingNotFound, 63),
            (K::ContactNotVerified, 64),
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
            (K::PairingInProgress, 84),
            (K::PairingCrossed, 85),
            (K::PairingEnded, 87),
            (K::PairingWaiting, 88),
            (K::ForeignProofAddress, 89),
            (K::WrongKey, 90),
            (K::PairingKindDiffers, 91),
            (K::RelayMoveNotRequested, 92),
            (K::InPersonNotFound, 93),
            (K::InPersonNoMailbox, 95),
            (K::UrCodeIncomplete, 96),
            (K::SavedTransaction, 102),
            (K::Epic1CannotPay, 103),
            (K::Epic1NoMoreRelays, 104),
            (K::Epic1NotFound, 106),
            (K::Epic1RelayInvalid, 108),
            (K::Epic1MessageInvalid, 109),
            (K::Epic1Finalized, 110),
            (K::Epic1WrongNetwork, 111),
            (K::NotAnEpic1Link, 112),
            (K::WalletTooNew, 113),
            (K::CancelledOnRelay, 115),
            (K::RecoveryOpen, 116),
            (K::NotRecoverable, 117),
            (K::SlateTooLarge, 118),
            (K::NoSharedMailbox, 119),
            (K::MailboxInvalid, 120),
            (K::MailboxNotPublic, 121),
            (K::MailboxListFull, 122),
            (K::LastMailbox, 123),
            (K::DamagedKept, 124),
            (K::EarlierEpic1Address, 125),
            (K::InputsReorged, 126),
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
    fn a_store_from_a_newer_version_is_wallet_too_new_on_every_route() {
        use lepic_wallet::WalletError as E;
        let too_new = || lepic_store::StoreError::SchemaTooNew {
            found: 17,
            supported: 16,
        };
        let expected = "this wallet was saved by a newer version of the app (store version 17; \
                        this version reads up to 16): update the app to open it";
        let errors = [
            WalletError::from(E::Store(too_new())),
            WalletError::from(SendError::Wallet(E::Store(too_new()))),
            WalletError::from(ReceiveError::from(too_new())),
            WalletError::from(ContactError::from(too_new())),
        ];
        for error in errors {
            assert_eq!(error.kind, WalletErrorKind::WalletTooNew);
            assert_eq!(error.code, 113);
            assert_eq!(error.message, expected);
        }
        let other = WalletError::from(E::Store(lepic_store::StoreError::WalUnavailable));
        assert_eq!(other.kind, WalletErrorKind::Io);
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
            (E::RecoveryOpen(tx), WalletErrorKind::RecoveryOpen),
            (E::NotRecoverable(tx), WalletErrorKind::NotRecoverable),
            (
                E::Node(lepic_node::NodeError::Timeout),
                WalletErrorKind::NodeUnreachable,
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
            (
                FinalizeError::InputsReorged {
                    tx_id,
                    source: source(),
                },
                WalletErrorKind::InputsReorged,
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
            (
                InvoiceError::InputsReorged {
                    tx_id,
                    source: source(),
                },
                WalletErrorKind::InputsReorged,
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
            (E::InviteExpired, K::InviteExpired),
            (E::AlreadyPaired, K::AlreadyPaired),
            (E::UnknownContact, K::ContactNotFound),
            (E::UnknownPairing, K::PairingNotFound),
            (E::NotVerified, K::ContactNotVerified),
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
            (E::PairingInProgress, K::PairingInProgress),
            (E::Crossed, K::PairingCrossed),
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
                E::InPerson(InPersonRefusal::NoMailbox),
                K::InPersonNoMailbox,
            ),
            (
                E::InPerson(InPersonRefusal::UrIncomplete),
                K::UrCodeIncomplete,
            ),
            (
                E::InPerson(InPersonRefusal::TtlTooShort { margin: 10 }),
                K::InvalidArgument,
            ),
            (E::InPerson(InPersonRefusal::Proof), K::InvalidSlate),
            (E::InPerson(InPersonRefusal::Ended), K::Cancelled),
            (E::InPerson(InPersonRefusal::Loopback), K::InvalidSlate),
            (
                E::InPerson(InPersonRefusal::RepeatDiffers),
                K::InvalidArgument,
            ),
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

    #[test]
    fn epic1_refusals_have_their_own_kinds() {
        use Epic1Refusal as R;
        use WalletErrorKind as K;
        let cases = [
            (R::CannotPay, K::Epic1CannotPay),
            (R::TorExpected, K::Epic1CannotPay),
            (R::NoMoreEntries, K::Epic1NoMoreRelays),
            (R::NoPayment, K::Epic1NotFound),
            (R::LinkRelay, K::Epic1RelayInvalid),
            (R::TooManyRelays, K::Epic1RelayInvalid),
            (R::Message, K::Epic1MessageInvalid),
            (R::Finalized, K::Epic1Finalized),
            (R::WrongNetwork, K::Epic1WrongNetwork),
        ];
        for (refusal, kind) in cases {
            let mapped = WalletError::from(ContactError::Epic1(refusal));
            assert_eq!(mapped.kind, kind);
        }
        assert_eq!(
            WalletError::from(ContactError::SavedTransaction).kind,
            K::SavedTransaction
        );
        assert_eq!(
            WalletError::from(ContactError::NotPaymentFile).kind,
            K::InvalidPairingText
        );
    }

    /// Every engine error the wallet can return, one sample per variant, beside its debug text.
    fn engine_samples() -> Vec<(String, WalletError)> {
        use lepic_wallet_contacts::error_samples as samples;
        fn walk<E: std::fmt::Debug + Into<WalletError>>(
            errors: Vec<E>,
            prefix: &str,
            out: &mut Vec<(String, WalletError)>,
        ) {
            for error in errors {
                out.push((format!("{prefix}({error:?})"), error.into()));
            }
        }
        let mut out = Vec::new();
        walk(samples::wallet_errors(), "Wallet", &mut out);
        walk(samples::send_errors(), "Send", &mut out);
        walk(samples::receive_errors(), "Receive", &mut out);
        walk(samples::finalize_errors(), "Finalize", &mut out);
        walk(samples::invoice_errors(), "Invoice", &mut out);
        walk(samples::inbox_errors(), "Inbox", &mut out);
        walk(samples::contact_errors(), "Contact", &mut out);
        out
    }

    /// Engine errors that reach the app as `Other`: a defect of the wallet, its storage or its
    /// keys, never the input, the node or the network. Each entry is the start of the error's
    /// debug text and names at least one sample.
    const OTHER: &[&str] = &[
        "Wallet(StoredSeed(",
        "Wallet(Keychain(",
        "Wallet(Identifier(",
        "Wallet(SecretName(",
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
        "Receive(Codecs(",
        "Receive(Encode(",
        "Finalize(Signing(",
        "Finalize(Excess(",
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
        "Invoice(Arithmetic(",
        "Invoice(Codecs(",
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
        "Contact(InPerson(StoredAnswer)",
    ];

    #[test]
    fn only_a_defect_of_the_wallet_is_other() {
        let samples = engine_samples();
        let unexpected: Vec<&str> = samples
            .iter()
            .filter(|(_, mapped)| mapped.kind == WalletErrorKind::Other)
            .map(|(debug, _)| debug.as_str())
            .filter(|debug| !OTHER.iter().any(|prefix| debug.starts_with(prefix)))
            .collect();
        assert!(unexpected.is_empty(), "mapped to Other: {unexpected:#?}");
        for prefix in OTHER {
            assert!(
                samples
                    .iter()
                    .any(|(debug, mapped)| debug.starts_with(prefix)
                        && mapped.kind == WalletErrorKind::Other),
                "no sample maps {prefix} to Other"
            );
        }
    }

    #[test]
    fn a_card_that_cannot_be_built_says_why() {
        use ContactEncodeError as E;
        use WalletErrorKind as K;
        let cases = [
            (E::FieldTooLong { tag: 1 }, K::InvalidArgument),
            (E::BodyTooLarge { limit: 1, found: 2 }, K::InvalidArgument),
            (E::Oversized { limit: 1, found: 2 }, K::InvalidArgument),
            (E::WrongNetwork, K::InvalidArgument),
            (E::WrongClass, K::WrongPairingClass),
            (E::Encryption, K::Other),
        ];
        for (error, kind) in cases {
            assert_eq!(WalletError::from(ContactError::Encode(error)).kind, kind);
        }
    }

    #[test]
    fn a_refusal_that_names_a_wait_gives_its_seconds() {
        use lepic_epicbox::{ClientError, MailboxError, RelayErrorKind};
        let refused = |wait: Option<u64>| {
            ContactError::Relay(MailboxError::Protocol(ClientError::PostRefused {
                kind: RelayErrorKind::InvalidRequest,
                description: Some("Rate limit exceeded.".to_owned()),
                retry_after: wait.map(std::time::Duration::from_secs),
                mailbox: Some("relay.test:443".to_owned()),
            }))
        };
        let mapped = WalletError::from(refused(Some(12)));
        assert_eq!(mapped.kind, WalletErrorKind::TransportFailed);
        assert_eq!(mapped.retry_after_secs, Some(12));
        assert_eq!(mapped.mailbox.as_deref(), Some("relay.test:443"));
        assert_eq!(
            WalletError::from(refused(Some(u64::MAX))).retry_after_secs,
            Some(u32::MAX)
        );
        assert_eq!(WalletError::from(refused(None)).retry_after_secs, None);
        assert_eq!(
            WalletError::from(ContactError::Offline).retry_after_secs,
            None
        );
        assert_eq!(WalletError::from(ContactError::Offline).mailbox, None);
    }

    #[test]
    fn an_epic1_of_an_earlier_release_has_its_own_kind_and_names_its_mailbox() {
        use lepic_wallet_contacts::{Epic1Error, LinkError};
        let named = WalletError::from(ContactError::Epic1Link(LinkError::EarlierAddress {
            mailbox: Some("box.example:8443".to_owned()),
        }));
        assert_eq!(named.kind, WalletErrorKind::EarlierEpic1Address);
        assert_eq!(named.code, 125);
        assert_eq!(named.mailbox.as_deref(), Some("box.example:8443"));
        assert!(
            named.message.contains("box.example:8443"),
            "{}",
            named.message
        );
        // A bare address names no mailbox; the text says what to use instead.
        let bare = WalletError::from(ContactError::Epic1Link(LinkError::Address(
            Epic1Error::EarlierAddress,
        )));
        assert_eq!(bare.kind, WalletErrorKind::EarlierEpic1Address);
        assert_eq!(bare.mailbox, None);
        assert!(bare.message.contains("Epicbox address"), "{}", bare.message);
        // Any other epic1 text keeps its kind.
        let other = WalletError::from(ContactError::Epic1Link(LinkError::NotAnEpic1Link));
        assert_eq!(other.kind, WalletErrorKind::NotAnEpic1Link);
    }
}
