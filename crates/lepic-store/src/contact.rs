//! Paired contacts, their mailboxes, pairings in progress and the outbox of sealed messages
//! (RFC 0002 sections 7.6, 10.1, 10.3 and 12.4).
//!
//! A contact holds the peer's card as the opaque bytes the card codec produced, beside the fields
//! the wallet looks contacts up by. The store never parses a card. The secrets of a pairing in
//! progress are sealed under the private context key, with the pairing id and invite id as
//! associated data, so a row copied to another pairing does not open.

use std::fmt;

use jiff::Timestamp;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::account::AccountIndex;
use crate::context::{self, ContextKey, SealFailure};
use crate::encoding::{stored_enum, timestamp_to_column};
use crate::error::{Record, StoreError};
use crate::slate::SlateStage;

/// Contacts kept at once. Storing one more fails with [`StoreError::ContactCapReached`].
pub const MAX_CONTACTS: usize = 10_000;

/// Pairings in progress kept at once. Storing one more fails with
/// [`StoreError::ContactCapReached`].
pub const MAX_PENDING_PAIRINGS: usize = 64;

/// Length of a contact id, a pairing id and a pairing secret.
pub const CONTACT_ID_LEN: usize = 16;

/// Length of the invite id.
pub const INVITE_ID_LEN: usize = 8;

/// Slots run below this bound (RFC 0002 2.2); a counter that reached it hands out no more.
pub const CONTACT_SLOT_COUNT: u32 = 65_536;

/// Length of the random salt of a contact's mailbox key.
pub const BOX_SALT_LEN: usize = 16;

/// Length of the SAS kept to show the check again.
pub const SAS_LEN: usize = 4;

/// Length of a key in a peer card.
pub const CARD_KEY_LEN: usize = 32;

/// Which cap refused a contact or a pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactCap {
    Contacts,
    PendingPairings,
    /// Every slot of the account was handed out.
    Slots,
}

impl fmt::Display for ContactCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Contacts => "contacts",
            Self::PendingPairings => "pending pairings",
            Self::Slots => "contact slots",
        })
    }
}

/// Our local id for a contact record. Never sent and never used to derive keys: those come from
/// the record's account, slot and box salt.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContactId(pub [u8; CONTACT_ID_LEN]);

impl fmt::Debug for ContactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContactId({self})")
    }
}

impl fmt::Display for ContactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Id of a pairing in progress.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PairingId(pub [u8; CONTACT_ID_LEN]);

impl fmt::Debug for PairingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PairingId(")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))?;
        f.write_str(")")
    }
}

stored_enum! {
    /// What the contact says it is.
    pub enum ContactKind {
        Person => "person",
        Shop => "shop",
        Exchange => "exchange",
    }
}

stored_enum! {
    /// Where a contact stands in the pairing state machine (RFC 0002 10.2).
    pub enum ContactState {
        PendingInvite => "pending-invite",
        PendingReply => "pending-reply",
        Paired => "paired",
        Verified => "verified",
        /// The contact showed new keys. It seals nothing and accepts no invoices until the user
        /// decides.
        KeysChanged => "keys-changed",
    }
}

stored_enum! {
    /// Whether messages to the contact are sealed.
    pub enum SealMode {
        On => "on",
        Off => "off",
        /// The last fallback to a plain message was used.
        Degraded => "degraded",
    }
}

/// A verified contact card, as bytes and as the fields the wallet indexes.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerCard {
    /// The card as the peer signed it.
    pub bytes: Vec<u8>,
    pub sig_key: [u8; CARD_KEY_LEN],
    pub enc_key: [u8; CARD_KEY_LEN],
    pub hint_key: [u8; CARD_KEY_LEN],
    pub seq: u32,
    pub kind: ContactKind,
    /// The name the contact claims. The wallet shows the user's own label.
    pub claimed_name: String,
}

impl fmt::Debug for PeerCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerCard")
            .field("seq", &self.seq)
            .field("kind", &self.kind)
            .field("claimed_name", &self.claimed_name)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRecord {
    pub contact_id: ContactId,
    /// The account whose contact-identity root derives our keys for the contact.
    pub account: AccountIndex,
    /// Our slot for the contact (RFC 0002 2.2). Not unique: twin installs on one seed, or a slot
    /// taken back by the key check, may share it with another record.
    pub slot: u32,
    /// The salt of our mailbox key for the contact.
    pub box_salt: [u8; BOX_SALT_LEN],
    /// Our card for the contact as we last gave it, in its exact signed bytes.
    pub own_card: Vec<u8>,
    /// The latest verified card. `None` while an invite waits for its reply.
    pub peer: Option<PeerCard>,
    /// The card of the new keys while the state is [`ContactState::KeysChanged`]; `peer` keeps
    /// the old ones.
    pub alternate: Option<PeerCard>,
    /// The user's own name for the contact.
    pub label: String,
    pub state: ContactState,
    /// The SAS of the pairing, kept so the check can be shown again.
    pub sas: Option<[u8; SAS_LEN]>,
    pub verified_at: Option<Timestamp>,
    pub allow_invoices: bool,
    pub seal: SealMode,
    pub last_sealed_in: Option<Timestamp>,
    /// The id of the app's address-book contact the pairing is attached to.
    pub app_contact: Option<String>,
    /// Set when the record came from a backup: the pairing may live on another device too.
    pub imported_from_backup: bool,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// The home relay a contact's mailboxes lived on before it moved, kept until `until`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousHome {
    pub relay: String,
    pub peer_mailbox: String,
    pub our_mailbox: String,
    pub until: Timestamp,
}

/// When a relay may be tried again after failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBackoff {
    pub relay: String,
    pub next_try_at: Timestamp,
    pub failures: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactMailbox {
    pub contact_id: ContactId,
    /// Where we deliver to the contact, `key@domain[:port]`.
    pub peer_mailbox: String,
    /// Where the contact delivers to us.
    pub our_mailbox: String,
    pub home_relay: String,
    pub onion: Option<String>,
    pub previous: Option<PreviousHome>,
    pub backoff: Vec<RelayBackoff>,
}

stored_enum! {
    pub enum PairingRole {
        Inviter => "inviter",
        Invitee => "invitee",
    }
}

stored_enum! {
    pub enum PairingState {
        /// The inviter waits for a reply.
        PendingInvite => "pending-invite",
        /// The invitee sent a reply and waits for the confirmation.
        PendingReply => "pending-reply",
    }
}

const SECRET_LEN: usize = 16;

/// The secrets of a pairing. Each role holds the ones it knows. Wiped on drop, never printed.
#[derive(Default, PartialEq, Eq)]
pub struct PairingSecrets {
    pub code: Option<[u8; SECRET_LEN]>,
    pub na: Option<[u8; SECRET_LEN]>,
    pub nb: Option<[u8; SECRET_LEN]>,
    pub rc: Option<[u8; SECRET_LEN]>,
}

impl Clone for PairingSecrets {
    fn clone(&self) -> Self {
        Self {
            code: self.code,
            na: self.na,
            nb: self.nb,
            rc: self.rc,
        }
    }
}

impl Drop for PairingSecrets {
    fn drop(&mut self) {
        self.code.zeroize();
        self.na.zeroize();
        self.nb.zeroize();
        self.rc.zeroize();
    }
}

impl fmt::Debug for PairingSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingSecrets([redacted])")
    }
}

/// A pairing in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPairing {
    pub pairing_id: PairingId,
    pub role: PairingRole,
    pub contact_id: ContactId,
    pub secrets: PairingSecrets,
    /// The invite id, unique among stored pairings.
    pub invite_id: [u8; INVITE_ID_LEN],
    pub expires_at: Timestamp,
    pub our_mailbox: String,
    pub peer_mailbox: Option<String>,
    pub state: PairingState,
    pub created_at: Timestamp,
    /// The invite in its exact bytes: the inviter's own, or the one the invitee answered.
    pub invite: Vec<u8>,
}

/// Local id of a stored outbox entry, assigned by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContactOutboxId(pub u64);

impl fmt::Display for ContactOutboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

stored_enum! {
    pub enum ContactOutboxState {
        Queued => "queued",
        Delivered => "delivered",
        /// Undelivered for 24 hours (RFC 0002 12.4).
        Stuck => "stuck",
    }
}

/// A message that must reach a contact's mailbox on a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactOutboxEntry {
    pub contact_id: ContactId,
    pub slate_id: Uuid,
    pub stage: SlateStage,
    /// The armored payload.
    pub payload: String,
    pub destination: String,
    pub attempts: u32,
    pub next_try_at: Timestamp,
    pub state: ContactOutboxState,
    pub created_at: Timestamp,
    pub delivered_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredContactOutbox {
    pub id: ContactOutboxId,
    pub entry: ContactOutboxEntry,
}

pub trait ContactRepository {
    /// Inserts the contact, or replaces the one with the same id. Fails with
    /// [`StoreError::Duplicate`] when another contact has the same peer signing key, and with
    /// [`StoreError::ContactCapReached`] when a new contact would pass [`MAX_CONTACTS`].
    fn put_contact(&mut self, contact: &ContactRecord) -> Result<(), StoreError>;

    fn contact(&self, id: ContactId) -> Result<Option<ContactRecord>, StoreError>;

    fn contact_by_peer_sig_key(
        &self,
        key: &[u8; CARD_KEY_LEN],
    ) -> Result<Option<ContactRecord>, StoreError>;

    fn contact_by_peer_hint_key(
        &self,
        key: &[u8; CARD_KEY_LEN],
    ) -> Result<Option<ContactRecord>, StoreError>;

    /// The contacts whose current or previous mailbox of ours is `address`.
    fn contacts_by_our_mailbox(&self, address: &str) -> Result<Vec<ContactRecord>, StoreError>;

    /// Every contact, oldest first.
    fn contacts(&self) -> Result<Vec<ContactRecord>, StoreError>;

    /// The contacts whose invoices are accepted, oldest first.
    fn contacts_allowing_invoices(&self) -> Result<Vec<ContactRecord>, StoreError>;

    /// Every account's slot counter, by account.
    fn contact_slot_counters(&self) -> Result<Vec<(AccountIndex, u32)>, StoreError>;

    /// The next slot the account would hand out, or `None` while it has none.
    fn contact_slot_counter(&self, account: AccountIndex) -> Result<Option<u32>, StoreError>;

    /// Hands out the account's next slot and raises the counter past it. Without a counter the
    /// account starts at `start`, which the caller picks at random (RFC 0002 2.2). Fails with
    /// [`StoreError::ContactCapReached`] when the counter reached [`CONTACT_SLOT_COUNT`], and
    /// with [`StoreError::OutOfRange`] when `start` is not below it.
    fn take_contact_slot(&mut self, account: AccountIndex, start: u32) -> Result<u32, StoreError>;

    /// Raises the account's counter to at least `next`, so a slot taken back by the key check or
    /// restored from a backup is never handed out again. A lower value changes nothing; a value
    /// above [`CONTACT_SLOT_COUNT`] fails with [`StoreError::OutOfRange`].
    fn raise_contact_slot_counter(
        &mut self,
        account: AccountIndex,
        next: u32,
    ) -> Result<(), StoreError>;

    /// Removes the contact with its mailbox and outbox entries, and returns whether it was
    /// stored. A pairing in progress for it stays, and its slot stays used.
    fn delete_contact(&mut self, id: ContactId) -> Result<bool, StoreError>;

    /// Inserts the mailbox, or replaces the contact's one with its backoff. Fails with
    /// [`StoreError::NotFound`] when the contact is not stored.
    fn put_contact_mailbox(&mut self, mailbox: &ContactMailbox) -> Result<(), StoreError>;

    fn contact_mailbox(&self, id: ContactId) -> Result<Option<ContactMailbox>, StoreError>;

    /// Inserts the pairing, or replaces the one with the same id. Fails with
    /// [`StoreError::Duplicate`] when another pairing has the same invite id, and with
    /// [`StoreError::ContactCapReached`] when a new pairing would pass
    /// [`MAX_PENDING_PAIRINGS`].
    fn put_pending_pairing(&mut self, pairing: &PendingPairing) -> Result<(), StoreError>;

    fn pending_pairing(&self, id: PairingId) -> Result<Option<PendingPairing>, StoreError>;

    fn pending_pairing_by_invite(
        &self,
        invite_id: &[u8; INVITE_ID_LEN],
    ) -> Result<Option<PendingPairing>, StoreError>;

    /// Every pairing in progress, oldest first.
    fn pending_pairings(&self) -> Result<Vec<PendingPairing>, StoreError>;

    /// Removes the pairing, and returns whether it was stored.
    fn delete_pending_pairing(&mut self, id: PairingId) -> Result<bool, StoreError>;

    /// Removes every pairing that expired at or before `now`, and returns how many.
    fn prune_expired_pairings(&mut self, now: Timestamp) -> Result<usize, StoreError>;

    /// Stores a new outbox entry under the next free id. Fails with [`StoreError::NotFound`]
    /// when the contact is not stored.
    fn enqueue_contact_outbox(
        &mut self,
        entry: &ContactOutboxEntry,
    ) -> Result<ContactOutboxId, StoreError>;

    fn update_contact_outbox(
        &mut self,
        id: ContactOutboxId,
        entry: &ContactOutboxEntry,
    ) -> Result<(), StoreError>;

    fn contact_outbox_entry(
        &self,
        id: ContactOutboxId,
    ) -> Result<Option<StoredContactOutbox>, StoreError>;

    /// The contact's entries in every state, by id.
    fn contact_outbox(&self, contact: ContactId) -> Result<Vec<StoredContactOutbox>, StoreError>;

    /// Queued entries whose next try is at or before `now`, most overdue first.
    fn due_contact_outbox(&self, now: Timestamp) -> Result<Vec<StoredContactOutbox>, StoreError>;

    /// Points the contact's undelivered entries at `destination` (RFC 0002 12.4, home relay
    /// move), and returns how many changed.
    fn redirect_contact_outbox(
        &mut self,
        contact: ContactId,
        destination: &str,
    ) -> Result<usize, StoreError>;

    /// Removes the entry if it is stored.
    fn delete_contact_outbox(&mut self, id: ContactOutboxId) -> Result<(), StoreError>;

    /// Whether an envelope with this hash was taken from a contact or pairing mailbox before
    /// (RFC 0002 8.2: the wallet deduplicates by the envelope's hash).
    fn envelope_seen(&self, hash: &[u8; 32]) -> Result<bool, StoreError>;

    /// Records that an envelope with this hash was taken at `at`.
    fn remember_envelope(&mut self, hash: &[u8; 32], at: Timestamp) -> Result<(), StoreError>;

    /// Forgets the envelopes taken before `cutoff`, and returns how many.
    fn forget_envelopes_before(&mut self, cutoff: Timestamp) -> Result<usize, StoreError>;
}

/// Rejects timestamps the SQLite backend could not hold, so both backends accept the same data.
pub(crate) fn check_contact(contact: &ContactRecord) -> Result<(), StoreError> {
    if contact.slot >= CONTACT_SLOT_COUNT {
        return Err(StoreError::OutOfRange { field: "slot" });
    }
    timestamp_to_column(contact.created_at)?;
    timestamp_to_column(contact.updated_at)?;
    for time in [contact.verified_at, contact.last_sealed_in]
        .into_iter()
        .flatten()
    {
        timestamp_to_column(time)?;
    }
    Ok(())
}

/// The slot a counter at `next` hands out, and the counter after it.
pub(crate) fn next_slot(next: u32) -> Result<(u32, u32), StoreError> {
    if next >= CONTACT_SLOT_COUNT {
        return Err(StoreError::ContactCapReached {
            cap: ContactCap::Slots,
        });
    }
    Ok((next, next.saturating_add(1)))
}

/// A counter may stand at most at [`CONTACT_SLOT_COUNT`], once every slot was handed out.
pub(crate) fn check_slot_counter(next: u32) -> Result<(), StoreError> {
    if next > CONTACT_SLOT_COUNT {
        return Err(StoreError::OutOfRange {
            field: "slot counter",
        });
    }
    Ok(())
}

pub(crate) fn check_slot_start(start: u32) -> Result<(), StoreError> {
    if start >= CONTACT_SLOT_COUNT {
        return Err(StoreError::OutOfRange {
            field: "slot start",
        });
    }
    Ok(())
}

pub(crate) fn check_mailbox(mailbox: &ContactMailbox) -> Result<(), StoreError> {
    if let Some(previous) = &mailbox.previous {
        timestamp_to_column(previous.until)?;
    }
    for backoff in &mailbox.backoff {
        timestamp_to_column(backoff.next_try_at)?;
    }
    Ok(())
}

pub(crate) fn check_pairing(pairing: &PendingPairing) -> Result<(), StoreError> {
    timestamp_to_column(pairing.expires_at)?;
    timestamp_to_column(pairing.created_at)?;
    Ok(())
}

pub(crate) fn check_outbox(entry: &ContactOutboxEntry) -> Result<(), StoreError> {
    timestamp_to_column(entry.next_try_at)?;
    timestamp_to_column(entry.created_at)?;
    if let Some(time) = entry.delivered_at {
        timestamp_to_column(time)?;
    }
    Ok(())
}

const ASSOCIATED_DATA_DOMAIN: &[u8] = b"lepic-store pairing v1";

fn associated_data(id: PairingId, invite_id: &[u8; INVITE_ID_LEN]) -> Vec<u8> {
    let mut data = Vec::with_capacity(
        ASSOCIATED_DATA_DOMAIN
            .len()
            .saturating_add(CONTACT_ID_LEN)
            .saturating_add(INVITE_ID_LEN),
    );
    data.extend_from_slice(ASSOCIATED_DATA_DOMAIN);
    data.extend_from_slice(&id.0);
    data.extend_from_slice(invite_id);
    data
}

fn sealing_error(failure: SealFailure) -> StoreError {
    let record = Record::PendingPairing;
    match failure {
        SealFailure::Randomness(error) => StoreError::Randomness(error),
        SealFailure::Unsealable => StoreError::Unsealable { record },
        SealFailure::Malformed => StoreError::Corrupt {
            record,
            field: "sealed bytes",
        },
        SealFailure::Undecryptable => StoreError::Undecryptable { record },
    }
}

/// Plain layout: for each of code, nA, nB and rc in turn, a presence byte then 16 bytes (zero
/// when absent).
const PLAIN_LEN: usize = 4 * (1 + SECRET_LEN);

pub(crate) fn seal_secrets(
    key: &ContextKey,
    pairing: &PendingPairing,
) -> Result<Vec<u8>, StoreError> {
    let secrets = &pairing.secrets;
    let mut plain = Zeroizing::new(Vec::with_capacity(PLAIN_LEN));
    for secret in [&secrets.code, &secrets.na, &secrets.nb, &secrets.rc] {
        plain.push(u8::from(secret.is_some()));
        plain.extend_from_slice(&secret.unwrap_or([0; SECRET_LEN]));
    }
    context::seal_bytes(
        key,
        &associated_data(pairing.pairing_id, &pairing.invite_id),
        &plain,
    )
    .map_err(sealing_error)
}

/// Fails with [`StoreError::Undecryptable`] under another key, or when the row was altered.
pub(crate) fn open_secrets(
    key: &ContextKey,
    id: PairingId,
    invite_id: &[u8; INVITE_ID_LEN],
    sealed: &[u8],
) -> Result<PairingSecrets, StoreError> {
    let plain = Zeroizing::new(
        context::open_bytes(key, &associated_data(id, invite_id), sealed).map_err(sealing_error)?,
    );
    let malformed = || StoreError::Corrupt {
        record: Record::PendingPairing,
        field: "secrets",
    };
    if plain.len() != PLAIN_LEN {
        return Err(malformed());
    }
    let mut secrets = PairingSecrets::default();
    let (chunks, _) = plain.as_chunks::<{ 1 + SECRET_LEN }>();
    for (slot, chunk) in [
        &mut secrets.code,
        &mut secrets.na,
        &mut secrets.nb,
        &mut secrets.rc,
    ]
    .into_iter()
    .zip(chunks)
    {
        let (flag, bytes) = chunk.split_first().ok_or_else(malformed)?;
        *slot = match flag {
            0 => None,
            1 => Some(<[u8; SECRET_LEN]>::try_from(bytes).map_err(|_| malformed())?),
            _ => return Err(malformed()),
        };
    }
    Ok(secrets)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let secrets = PairingSecrets {
            code: Some([0xab; SECRET_LEN]),
            ..PairingSecrets::default()
        };
        let text = format!("{secrets:?}");
        assert!(!text.contains("ab"));
        assert!(text.contains("redacted"));
    }

    #[test]
    fn sealed_secrets_round_trip_and_are_bound_to_their_row() {
        let key = ContextKey::from_bytes([1; 32]);
        let pairing = PendingPairing {
            pairing_id: PairingId([2; 16]),
            role: PairingRole::Inviter,
            contact_id: ContactId([3; 16]),
            secrets: PairingSecrets {
                code: Some([4; 16]),
                na: Some([5; 16]),
                nb: None,
                rc: Some([6; 16]),
            },
            invite_id: [7; 8],
            expires_at: Timestamp::from_second(10).unwrap(),
            our_mailbox: "a@relay".to_owned(),
            peer_mailbox: None,
            state: PairingState::PendingInvite,
            created_at: Timestamp::from_second(1).unwrap(),
            invite: vec![8; 40],
        };
        let sealed = seal_secrets(&key, &pairing).unwrap();
        let opened = open_secrets(&key, pairing.pairing_id, &pairing.invite_id, &sealed).unwrap();
        assert_eq!(opened, pairing.secrets);
        assert!(matches!(
            open_secrets(&key, PairingId([9; 16]), &pairing.invite_id, &sealed),
            Err(StoreError::Undecryptable { .. })
        ));
        assert!(matches!(
            open_secrets(
                &ContextKey::from_bytes([2; 32]),
                pairing.pairing_id,
                &pairing.invite_id,
                &sealed
            ),
            Err(StoreError::Undecryptable { .. })
        ));
    }
}
