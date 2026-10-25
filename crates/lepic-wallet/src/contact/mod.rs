//! Contact pairing (RFC 0002 sections 7, 8 and 10): invites, replies and confirms through
//! throwaway mailboxes on a home relay, in-person pairing by scanning cards, the SAS check, and
//! the contact mailboxes each side collects.
//!
//! A pairing record holds no secret: our keys for a contact come from the seed, the account, the
//! record's slot and its box salt. The secrets of a pairing in progress are sealed in the store.
//! Nothing here touches the wallet's payments address, its listener or the node.

mod collect;
mod invoices;
mod keycheck;
mod keys;
mod manage;
mod outbox;
mod pairing;
mod relay;
mod sealed;
mod words;

use std::time::Duration;

use jiff::Timestamp;

use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{MailboxError, RelayEndpoint};
use lepic_store::{AccountIndex, ContactId, ContactState, PairingId, SealMode, StoreError};
use thiserror::Error;

use crate::error::WalletError;

pub use collect::{CollectReport, CollectTrigger};
pub(crate) use invoices::slate_contact;
pub use invoices::{ContactInvoice, InvoiceDetails, SAME_AMOUNT_WINDOW};
pub use keycheck::{KEY_CHECK_WINDOW, KeysDecision};
pub(crate) use keys::reply_public_key;
/// The contact formats a host names in these calls.
pub use lepic_contact::{ContactKind, Purpose, Refusal, SasSymbol};
pub use lepic_store::PairingRole;
pub use manage::PendingPairingView;
pub use outbox::{NOT_POSTED_AFTER, OUTBOX_STUCK_AFTER, OutboxReport, OutboxView};
pub use pairing::{
    AcceptOutcome, AcceptRequest, CardOffer, CardRequest, InviteExpiry, InviteOffer, InvitePreview,
    InviteRequest, LinkOutcome, SasDecision,
};
pub use sealed::{SEAL_LAPSE, SealedAnswer, SealedPayment, SealedReceived, SealedSlate};
pub use words::WORDS_INVITE_EXPIRY;

/// How long an inviter keeps draining its reply mailbox after the invite expired, for the clock
/// skew of RFC 0002 C-26. Also the skew an invitee allows an invite's expiry.
pub const CLOCK_SKEW: Duration = Duration::from_secs(10 * 60);

/// How long an invitee waits for the confirm after replying (RFC 0002 8.2).
pub const CONFIRM_WAIT: Duration = Duration::from_secs(60 * 60);

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
/// uses, the built-in relays of the network, and whether relays may be reached at all.
#[derive(Clone)]
pub struct ContactRelays {
    pub epicbox: EpicboxTransport,
    pub built_in: Vec<RelayEndpoint>,
    pub mode: RelayMode,
}

impl ContactRelays {
    /// The relays for `epicbox`, with the built-in relays of its network from
    /// [`lepic_epicbox::built_in_relays`], where pairing words are offered and looked for: the
    /// transport's own relay first when it is one of them, then the others in their order.
    pub fn new(epicbox: EpicboxTransport, mode: RelayMode) -> Self {
        let mut built_in = lepic_epicbox::built_in_relays(epicbox.network());
        let own = &epicbox.settings().endpoint;
        if let Some(at) = built_in
            .iter()
            .position(|relay| relay.domain() == own.domain() && relay.port() == own.port())
        {
            let first = built_in.remove(at);
            built_in.insert(0, first);
        }
        Self {
            epicbox,
            built_in,
            mode,
        }
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
    pub created_at: Timestamp,
}

/// Why a pairing ended without a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingFailure {
    /// The confirm does not match the invite's commitment or enc key: something changed the
    /// invite on the way. Nothing was stored.
    ChangedOnTheWay,
    /// The invite expired before a reply arrived, or no confirm came in time.
    Expired,
    /// The inviter refused the reply: the invite was used, expired or cancelled. Advisory.
    Refused(lepic_contact::Refusal),
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
    Keys(#[source] lepic_keychain::ContactKeyError),
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
    /// Pairing words are not offered yet.
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
    Receive(#[source] crate::receive::ReceiveError),
    #[error("invoice was not handled")]
    Invoice(#[source] crate::invoice::InvoiceError),
    #[error("slate was not finalized")]
    Finalize(#[source] crate::finalize::FinalizeError),
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
