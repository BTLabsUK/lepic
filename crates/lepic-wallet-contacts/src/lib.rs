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

mod collect;
mod invoices;
mod key_schedule;
mod keycheck;
mod keys;
mod manage;
mod outbox;
mod pairing;
mod payload;
mod private;
mod relay;
mod sealed;
mod words;

use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use jiff::Timestamp;
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{MailboxError, RelayEndpoint};
use lepic_node::NodeApi;
use lepic_store::{AccountIndex, ContactId, ContactState, PairingId, SealMode, StoreError};
use lepic_wallet::Wallet;
use lepic_wallet::error::WalletError;
use lepic_wallet::extension::ContactNotices;
use lepic_wallet::notice::Notice;
use lepic_wallet::ports::{SecretVault, StoreOpener};
use thiserror::Error;

pub use collect::{CollectReport, CollectTrigger};
pub use invoices::{ContactInvoice, InvoiceDetails, SAME_AMOUNT_WINDOW};
pub use key_schedule::{
    BOX_SALT_LEN, ContactKeyError, ContactKeys, ContactRoot, PRIVATE_SLOT_BASE, ReplyKey,
    SLOT_COUNT, contact_root, key_check_tag, pairing_mailbox_keys,
};
pub use keycheck::{KEY_CHECK_WINDOW, KeyCheckStart, KeysDecision};
/// The contact formats a host names in these calls.
pub use lepic_contact::{ContactKind, PairingClass, Purpose, Refusal, SasSymbol};
pub use lepic_store::PairingRole;
pub use lepic_wallet::event::PairingFailure;
pub use manage::{MAX_APP_CONTACT_LEN, MAX_BACKUP_LEN, PendingPairingView};
pub use outbox::{NOT_POSTED_AFTER, OUTBOX_STUCK_AFTER, OutboxReport, OutboxView};
pub use pairing::{
    AcceptOutcome, AcceptRequest, CardOffer, CardRequest, InviteExpiry, InviteOffer, InvitePreview,
    InviteRequest, LinkOutcome, SasDecision,
};
pub use payload::{ContactPayload, MAX_APP_PAYLOAD_LEN, MAX_KEPT_PAYLOADS, PayloadId};
pub use relay::{MAX_MEETING_RELAYS, meeting_host, meeting_relays};
pub use sealed::{SEAL_LAPSE, SealedAnswer, SealedPayment, SealedReceived, SealedSlate};
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
/// paste S1 and an I1 carry, so a LEPIC peer can answer them sealed. Call it once for each
/// wallet handle, before its first send.
pub fn install<N, S, V>(wallet: &Wallet<N, S, V>)
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    wallet.set_reply_keys(Arc::new(keys::ContactReplyKeys));
    wallet.set_contact_notices(Arc::new(SealedNotices));
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
    pub epicbox: EpicboxTransport,
    /// The meeting relays: the built-in relays of the network unless
    /// [`ContactRelays::with_meeting`] named others.
    pub built_in: Vec<RelayEndpoint>,
    pub mode: RelayMode,
}

impl ContactRelays {
    /// The relays for `epicbox`, with the built-in relays of its network from
    /// [`lepic_epicbox::built_in_relays`] as the meeting relays.
    pub fn new(epicbox: EpicboxTransport, mode: RelayMode) -> Self {
        let built_in = lepic_epicbox::built_in_relays(epicbox.network());
        Self {
            epicbox,
            built_in,
            mode,
        }
    }

    /// These relays with `meeting`, as [`meeting_relays`] parses them, as the meeting relays.
    #[must_use]
    pub fn with_meeting(mut self, meeting: Vec<RelayEndpoint>) -> Self {
        self.built_in = meeting;
        self
    }
}

impl std::fmt::Debug for ContactRelays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactRelays")
            .field("relay", &self.epicbox.settings().endpoint)
            .field("built_in", &self.built_in)
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
    /// The contact removed this pairing on its side and said so: nothing sent through it
    /// arrives any more.
    pub removed_by_peer: bool,
    pub created_at: Timestamp,
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
    #[error("no such contact")]
    UnknownContact,
    #[error("no such pairing in progress")]
    UnknownPairing,
    /// Invoices can be allowed only from a contact whose SAS the user confirmed.
    #[error("the contact is not verified")]
    NotVerified,
    /// The relay could not be reached or broke off. Nothing that was not stored is lost.
    #[error("relay failed")]
    Relay(#[source] MailboxError),
    /// The network has no built-in relay to offer pairing words on.
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
    /// No invite opened with these words on any built-in relay.
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
}

impl From<StoreError> for ContactError {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// The ids a pairing hands the host to follow it by.
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
