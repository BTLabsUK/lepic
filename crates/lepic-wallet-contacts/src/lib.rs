// SPDX-License-Identifier: Apache-2.0
//! Contact pairing (RFC 0002 sections 7, 8 and 10): invites, replies and confirms through
//! throwaway mailboxes on a home relay, in-person pairing by scanning cards, the SAS check, and
//! the contact mailboxes each side collects.
//!
//! A pairing record holds no secret: our keys for a contact come from the seed, the account, the
//! record's slot and its box salt. The secrets of a pairing in progress are sealed in the store.
//! Nothing here touches the wallet's payments address, its listener or the node.
//!
//! The crate drives the engine of `lepic-wallet` from outside: it borrows a wallet as
//! [`ContactBook`] with [`WalletContacts::contact_book`], and [`install`] gives the engine the reply key
//! of file and paste slates. The engine keeps no contact code of its own.

mod address_proof;
mod check;
mod collect;
mod direct;
mod domain;
mod epic1;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod epic1_testing;
mod hex;
mod in_person;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod in_person_testing;
mod invoices;
mod key_schedule;
mod keycheck;
mod keys;
mod manage;
mod native;
mod outbox;
mod pairing;
mod payload;
mod private;
mod quarantine;
mod relay;
mod requests;
mod sealed;
mod status;
mod words;

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use jiff::Timestamp;
use lepic_epicbox::{MailboxError, RelayEndpoint};
use lepic_methods::epicbox::Epicbox;
use lepic_node::NodeApi;
use lepic_store::{AccountIndex, ContactId, ContactState, PairingId, SealMode, StoreError};
use lepic_wallet::Wallet;
use lepic_wallet::error::WalletError;
use lepic_wallet::extension::ContactNotices;
use lepic_wallet::method::Method;
use lepic_wallet::notice::Notice;
use lepic_wallet::ports::{SecretVault, StoreOpener};
use thiserror::Error;

pub use collect::{CollectReport, CollectTrigger};
pub use direct::{Dialect, DirectError, DirectHandler, DirectSent, NativeFailure};
pub use domain::{DOMAIN_FILE_MAX, DomainFile, DomainRefused, DomainSigner, DomainVerdict, verify};
pub use epic1::{
    EPIC1_TTL_BLOCKS, Epic1AnswerView, Epic1Attempt, Epic1LinkIssued, Epic1LinkKind,
    Epic1LinkRequest, Epic1LinkView, Epic1Paid, Epic1PayRequest, Epic1Read, Epic1Refusal,
    ON_SCREEN_LIVE_FOR,
};
pub use in_person::{
    IN_PERSON_TTL_BLOCKS, InPersonAnswerView, InPersonCode, InPersonCodeView,
    InPersonInvoiceRequest, InPersonPaid, InPersonRead, InPersonRefusal, InPersonTaken,
};
pub use invoices::{ContactInvoice, InvoiceDetails, SAME_AMOUNT_WINDOW};
pub use key_schedule::{
    BOX_SALT_LEN, ContactKeyError, ContactKeys, ContactRoot, PRIVATE_SLOT_BASE, ReplyKey,
    SLOT_COUNT, contact_root, key_check_tag, pairing_mailbox_keys,
};
pub use keycheck::{KEY_CHECK_WINDOW, KeyCheckStart, KeysDecision};
pub use lepic_contact::PaymentFile;
/// The contact formats a host names in these calls.
pub use lepic_contact::{
    ContactKind, DomainName, Network as ContactNetwork, PairingClass, Purpose, Refusal, SasSymbol,
    VerifyingKey,
};
pub use lepic_store::PairingEndReason;
pub use lepic_store::PairingRole;
pub use lepic_wallet::event::PairingFailure;
pub use manage::{MAX_APP_CONTACT_LEN, MAX_BACKUP_LEN, MAX_HOME_DRAIN, PendingPairingView};
pub use outbox::{NOT_POSTED_AFTER, OUTBOX_STUCK_AFTER, OutboxReport, OutboxView};
pub use pairing::{
    AcceptOutcome, AcceptRequest, CardOffer, CardRequest, InviteExpiry, InviteOffer, InvitePreview,
    InviteRequest, LinkOutcome, SasDecision,
};
pub use payload::{
    ContactPayload, MAX_APP_PAYLOAD_LEN, MAX_KEPT_PAYLOADS, MAX_KEPT_PAYLOADS_PER_CONTACT,
    PayloadId, PostedPayload,
};
pub use quarantine::{QuarantineReason, QuarantineRetry, QuarantinedMessage};
pub use relay::{MAX_MEETING_RELAYS, meeting_host, meeting_relays};
pub use requests::{MAX_LIVE_REQUESTS, MAX_SETTLED_REQUESTS, PairRequestView, REQUEST_EXPIRY};
pub use sealed::{
    SEAL_LAPSE, SealedAnswer, SealedPayment, SealedReceived, SealedSlate, is_epictx, payment_file,
};
pub use status::{
    NEVER_FINISHED_AFTER, PairingStatus, STATUS_NOTICES, STATUS_RETRY_FOR, status_of,
};
pub use words::WORDS_INVITE_EXPIRY;

/// The contact engine of one wallet: pairing, contact mailboxes, sealed slates, contact
/// invoices, key checks and app payloads.
pub struct ContactBook<'w, N, S: StoreOpener, V> {
    wallet: &'w Wallet<N, S, V>,
}

/// Borrows a wallet's contact engine.
pub trait WalletContacts<N, S: StoreOpener, V> {
    fn contact_book(&self) -> ContactBook<'_, N, S, V>;
}

impl<N, S: StoreOpener, V> WalletContacts<N, S, V> for Wallet<N, S, V> {
    fn contact_book(&self) -> ContactBook<'_, N, S, V> {
        ContactBook { wallet: self }
    }
}

/// Gives `wallet` what the engine takes from the contact engine: the reply key a file or
/// paste S1 and an I1 carry, so a LEPIC peer can answer them sealed, and the `lepic.v1`
/// conversions of native slates over Epicbox. Call it once for each
/// wallet handle, before its first send.
pub fn install<N, S, V>(wallet: &Wallet<N, S, V>)
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    wallet.set_reply_keys(Arc::new(keys::ContactReplyKeys));
    wallet.set_native_slates(Arc::new(native::EpicboxNativeSlates));
    wallet.set_contact_notices(Arc::new(SealedNotices));
    requests::install_requests(wallet);
}

/// The engine's hook for notices about a contact's slates: sealed into the contact's mailbox.
struct SealedNotices;

impl<N, S, V> ContactNotices<N, S, V> for SealedNotices
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn queue<'a>(
        &'a self,
        wallet: &'a Wallet<N, S, V>,
        contact: ContactId,
        notice: Notice,
    ) -> BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            wallet
                .contact_book()
                .queue_contact_notice(contact, notice)
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

/// How long an inviter keeps draining its reply mailbox after the invite expired, for the clock
/// skew of RFC 0002 C-26. Also the skew an invitee allows an invite's expiry.
pub const CLOCK_SKEW: Duration = Duration::from_secs(10 * 60);

/// How long an invitee waits for the confirm after replying (RFC 0002 8.2), at the least: it
/// also waits as long as the inviter may still take the reply, see [`LATE_DRAIN_WAIT`].
pub const CONFIRM_WAIT: Duration = Duration::from_secs(60 * 60);

/// How long past its deadline a pairing in progress waits for one drain of its home relay. A
/// reply or confirm that reached the relay in time is still taken when the relay did not answer
/// or the app was closed at the deadline; the pairing ends at the first drain that starts after
/// the deadline, or after this wait without one.
pub const LATE_DRAIN_WAIT: Duration = Duration::from_secs(60 * 60);

/// Contact updates (type 05) accepted from one contact in a day (RFC 0002 8.5).
pub const UPDATES_PER_CONTACT_PER_DAY: usize = 3;

/// Contact updates accepted from all contacts together in an hour (RFC 0002 8.5).
pub const UPDATES_PER_HOUR: usize = 100;

/// Whether the wallet may reach relays for contacts, and how (RFC 0002 8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    Online,
    /// The user chose Offline: nothing connects anywhere.
    Offline,
    /// The user switched Epicbox off: no relay is reached, home relays included.
    EpicboxOff,
}

/// What the pairing engine reaches relays with: the wallet's Epicbox transport, whose relay is
/// the home relay of the invites this wallet makes and whose connector every drain and post
/// uses, the meeting relays pairing words are posted to and looked for on, and whether relays
/// may be reached at all.
#[derive(Clone)]
pub struct ContactRelays {
    pub epicbox: Epicbox,
    /// The meeting relays, which the caller names with [`ContactRelays::with_meeting`]: the
    /// only relays pairing words are posted to and looked for on. None until named.
    pub meeting: Vec<RelayEndpoint>,
    pub mode: RelayMode,
}

impl ContactRelays {
    /// The relays for `epicbox`, with no meeting relays: enough for every call but pairing
    /// words.
    pub fn new(epicbox: Epicbox, mode: RelayMode) -> Self {
        Self {
            epicbox,
            meeting: Vec::new(),
            mode,
        }
    }

    /// These relays with `meeting`, as [`meeting_relays`] parses them, as the meeting relays.
    #[must_use]
    pub fn with_meeting(mut self, meeting: Vec<RelayEndpoint>) -> Self {
        self.meeting = meeting;
        self
    }
}

impl std::fmt::Debug for ContactRelays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactRelays")
            .field("relay", &self.epicbox.settings().endpoint)
            .field("meeting", &self.meeting)
            .field("mode", &self.mode)
            .finish()
    }
}

/// A paired contact as the host shows it. Holds no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    pub contact_id: ContactId,
    pub account: AccountIndex,
    /// The user's own name for the contact, empty until the user gives one: the host asks,
    /// and shows `claimed_name` only as what the contact calls itself (RFC 0002 6.1).
    pub label: String,
    /// The name the contact gives itself, shown only as "calls themselves".
    pub claimed_name: Option<String>,
    /// Deprecated: always written for wallets that read it, never to be read for meaning;
    /// to be removed (docs/adr/0041 or RFC 0002 6.1).
    pub kind: Option<ContactKind>,
    pub state: ContactState,
    /// The four SAS entries, to show the check again.
    pub sas: Option<[SasSymbol; 4]>,
    pub verified_at: Option<Timestamp>,
    pub allow_invoices: bool,
    pub seal: SealMode,
    pub app_contact: Option<String>,
    /// The relay where the contact's messages to this wallet wait.
    pub home_relay: Option<String>,
    /// The record came from a backup and may also live on another device (RFC 0002 9.5).
    pub imported_from_backup: bool,
    /// No envelope from the contact opened in [`SEAL_LAPSE`]: a sealed send should warn that
    /// the contact needs LEPIC to open it (RFC 0002 9.4).
    pub lapsed: bool,
    /// When an envelope from the contact was last opened, if ever: of a contact's several
    /// pairings, the one it uses is the one heard from last.
    pub last_sealed_in: Option<Timestamp>,
    /// The relay, `domain:port`, a contact update asked to move to and the contact has not
    /// been moved to: derived from the stored card and the mailbox in use. Apply it with
    /// [`ContactBook::apply_relay_move`].
    pub requested_relay: Option<String>,
    /// The contact removed this pairing on its side and said so: nothing sent through it
    /// arrives any more. The same as `ended_reason` being [`PairingEndReason::Unpaired`].
    pub removed_by_peer: bool,
    /// The contact's payments address, `key@relay`, only when an address proof of this
    /// pairing verified; a later proof that fails keeps it. `None` for a contact that proved
    /// none.
    pub payments_address: Option<String>,
    pub created_at: Timestamp,
    /// Where the pairing stands, derived from the record.
    pub status: PairingStatus,
    /// When the contact was first heard in this pairing.
    pub peer_heard_at: Option<Timestamp>,
    /// When the contact's match verdict for this pairing's words was accepted.
    pub peer_verified_at: Option<Timestamp>,
    /// The features the contact claimed in this pairing; 0 when none were received.
    pub peer_features: u32,
    /// The profile the contact sent: `peer_features` from bit 16 up, moved down. LEPIC never
    /// reads a bit of it; the host names them.
    pub peer_profile: u32,
    /// New slates to the contact go as native slates (type `0A`, RFC 0003): the host set
    /// `native_direct`, the contact claims native slates and the pairing is not private.
    pub native_slates: bool,
    /// The domain the contact claimed in this pairing, unverified: the host proves it with
    /// `domain_verify` against the domain's well-known file.
    pub peer_domain: Option<String>,
    /// The claim as received (extension 0x83), kept so a host can verify it later.
    pub peer_domain_attestation: Option<Vec<u8>>,
    /// The X25519 encryption key (card tag 05) of the contact's stored card; `None` before
    /// the contact's card arrived. A completed pairing shows the contact holds it, so a host
    /// may recognise a service by it.
    pub peer_enc_key: Option<[u8; 32]>,
    pub ended_reason: Option<PairingEndReason>,
    pub ended_at: Option<Timestamp>,
}

/// A pairing that ended in a collecting cycle; its record is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndedPairing {
    pub contact_id: ContactId,
    pub reason: PairingEndReason,
}

/// Why a pairing operation failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContactError {
    #[error(transparent)]
    Wallet(#[from] WalletError),
    /// The user chose Offline; nothing was sent or fetched.
    #[error("the wallet is offline")]
    Offline,
    /// Epicbox is switched off; no relay is reached.
    #[error("epicbox is switched off")]
    EpicboxOff,
    #[error("epicbox transport serves another network than the wallet")]
    NetworkMismatch,
    #[error("pairing text was refused")]
    Decode(#[source] lepic_contact::DecodeError),
    #[error("pairing message could not be built")]
    Encode(#[source] lepic_contact::EncodeError),
    #[error("contact key derivation failed")]
    Keys(#[source] crate::key_schedule::ContactKeyError),
    #[error("name is not allowed")]
    Name(#[source] lepic_contact::TextError),
    #[error("relay address is not a domain with an optional port")]
    RelayAddress,
    /// The invite expired, also allowing for clock skew.
    #[error("the invite has expired")]
    InviteExpired,
    /// The card or reply belongs to a contact this wallet holds already, or to this wallet.
    #[error("this contact is already paired")]
    AlreadyPaired,
    /// The pairing proves another payments address than the one given.
    #[error("the pairing proves another address")]
    OtherAddress,
    /// An address was given, and the pairing proves none.
    #[error("the pairing proves no address")]
    AddressProofMissing,
    #[error("no such contact")]
    UnknownContact,
    #[error("no such pairing in progress")]
    UnknownPairing,
    /// Invoices can be allowed only from a contact whose SAS the user confirmed. Payloads pass
    /// over a contact pairing once paired, over a private pairing once verified.
    #[error("the contact is not verified")]
    NotVerified,
    /// The relay could not be reached or broke off. Nothing that was not stored is lost.
    #[error("relay failed")]
    Relay(#[source] MailboxError),
    /// No meeting relay was named to offer pairing words on.
    #[error("pairing words are not available")]
    WordsUnavailable,
    /// Sealing is off for the contact, or its card says it cannot open sealed files.
    #[error("the contact does not take sealed slates")]
    SealOff,
    #[error("no such transaction with a slate")]
    UnknownTransaction,
    /// No key of this wallet matches, or the signer is not the contact of the key that matched:
    /// the text was sealed for another wallet or install.
    #[error("sealed for another wallet or install")]
    NotForThisInstall,
    #[error("the sealed text cannot be opened")]
    CannotOpen,
    #[error("the sealed text holds no slate")]
    NotASlate,
    #[error("a slate at stage {0} is not taken here")]
    Stage(lepic_slate::stage::Stage),
    #[error("slate was not received")]
    Receive(#[source] lepic_wallet::receive::ReceiveError),
    #[error("invoice was not handled")]
    Invoice(#[source] lepic_wallet::invoice::InvoiceError),
    #[error("slate was not finalized")]
    Finalize(#[source] lepic_wallet::finalize::FinalizeError),
    #[error("payment was not sent")]
    Send(#[source] lepic_wallet::send::SendError),
    /// A payment to a contact was stored and its inputs locked, a later step failed, and
    /// cancelling it failed as well: it stays stored until it is cancelled with
    /// `Wallet::cancel` or sent again. `cause` is what failed first.
    #[error("{cause}; transaction {tx_id} is still stored and could not be cancelled: {cancel}")]
    NotCancelled {
        tx_id: lepic_store::TxId,
        cause: Box<ContactError>,
        cancel: WalletError,
    },
    /// The text is larger than this call reads.
    #[error("text is larger than {max} bytes")]
    TooLarge { max: usize },
    /// A card, invite or envelope this wallet stored or made itself could not be read: damaged
    /// data, not the user's input.
    #[error("data this wallet stored could not be read")]
    StoredData(#[source] lepic_contact::DecodeError),
    /// A key check is allowed once per pairing and per slot, within a day of the new pairing.
    #[error("no key check is allowed for these pairings now")]
    KeyCheckRefused,
    /// No invite opened with these words on any meeting relay.
    #[error("no invite found for these words")]
    WordsNotFound,
    #[error("pairing words are not valid")]
    Words(#[source] lepic_contact::WordsError),
    /// The contact's card says it does not pay invoices.
    #[error("the contact does not pay invoices")]
    DoesNotPayInvoices,
    /// The call is for the other pairing class: an invite answered as the class it is not, words
    /// offered for a private pairing, or a contact call for a private pairing and the other way
    /// round.
    #[error("the pairing is of another class")]
    WrongClass,
    /// Every private pairing slot of this store is used.
    #[error("no private pairing slot is left")]
    NoFreeSlot,
    /// The pairing ended: nothing new goes through it.
    #[error("the pairing ended")]
    Ended,
    /// The inviter's card names another kind than its invite did: nothing is stored.
    #[error("the card names another kind than the invite")]
    KindDiffers,
    /// The key did not run LEPIC lately, answered unmarked since, or never claimed pair
    /// requests: nothing is sent to it.
    #[error("the peer is not proven to take pairing requests")]
    PeerNotProven,
    /// A pairing with that wallet is in progress, waits for it, or a request from it waits.
    #[error("a pairing with this wallet is in progress")]
    PairingInProgress,
    /// This wallet's own pairing with the same wallet wins under the lower-key rule: wait for
    /// its answer.
    #[error("a crossed pairing with this wallet wins")]
    Crossed,
    /// The invite of a request this wallet dismissed.
    #[error("this pairing request was dismissed")]
    InviteDismissed,
    /// The request could not be posted; nothing was kept.
    #[error("pairing request not posted")]
    Post(#[source] lepic_transport::error::TransportError),
    /// The contact's wallet has not been heard in this pairing yet.
    #[error("the pairing waits for the contact's wallet")]
    Waiting,
    /// The relay given is not the one the contact's stored card asked to move to, or the
    /// contact asked for no move.
    #[error("the contact asked for no move to this relay")]
    RelayMoveNotRequested,
    /// The domain this wallet is set to claim is not a valid domain name.
    #[error("the configured domain is not valid")]
    Domain(#[source] lepic_contact::DomainError),
    /// The call needs a domain and the wallet is configured with none.
    #[error("the wallet claims no domain")]
    NoDomainConfigured,
    /// The contact claimed no domain in its pairing, or its stored claim cannot be read.
    #[error("the contact claimed no domain")]
    NoDomainClaim,
    /// A `lepic.v1` slate was refused.
    #[error("the slate code was refused")]
    Native(#[source] lepic_native_slate::NativeError),
    /// An in-person code or answer was refused.
    #[error("in-person slate refused: {0}")]
    InPerson(InPersonRefusal),
    /// A payment to an epic1 address, or a link to one, was refused.
    #[error("epic1 payment refused: {0}")]
    Epic1(Epic1Refusal),
    /// The text is not an epic1 link.
    #[error("not an epic1 link")]
    Epic1Link(#[source] lepic_epic1::LinkError),
    /// Hex digits only: a saved transaction another Epic wallet keeps in its `saved_txs`
    /// directory, never a slate (RFC 0003 5.12).
    #[error("not a payment file: a record another Epic wallet keeps")]
    SavedTransaction,
    /// Neither armored text nor a JSON slate (RFC 0003 5.12).
    #[error("not a payment file")]
    NotPaymentFile,
}

impl From<StoreError> for ContactError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// The ids a pairing hands the host to follow it by.
/// The method contact slates are encoded and decoded with: sealed text and contact mailboxes
/// carry them as files do.
pub(crate) fn file_method() -> Arc<dyn Method> {
    Arc::new(lepic_transport::file::FileTransport::new())
}

pub(crate) fn new_id<R: rand_core::CryptoRng + ?Sized>(rng: &mut R) -> [u8; 16] {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    id
}

/// The id of the pairing in progress that belongs to a contact record: the same bytes, so
/// either finds the other.
pub(crate) fn pairing_id_of(contact: ContactId) -> PairingId {
    PairingId(contact.0)
}

/// The wallet's shared generator, borrowed for code generic over a sized generator.
pub(crate) struct LockedRng<'a>(pub(crate) &'a mut (dyn rand_core::CryptoRng + Send));

impl rand_core::TryRng for LockedRng<'_> {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for LockedRng<'_> {}

/// Compares two secrets without stopping at the first differing byte.
pub(crate) fn same_secret(ours: &[u8; 16], theirs: &[u8; 16]) -> bool {
    ours.iter()
        .zip(theirs)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
