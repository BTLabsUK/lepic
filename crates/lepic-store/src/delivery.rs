// SPDX-License-Identifier: Apache-2.0
//! What delivery keeps: the mailboxes the wallet watches on relays, the native posts it still
//! owes, and the delivery state of each payment.

use std::fmt;

use jiff::Timestamp;
use lepic_primitives::amount::Height;
use uuid::Uuid;

use crate::encoding::{stored_enum, timestamp_to_column};
use crate::error::{Record, StoreError};
use crate::slate::SlateStage;

/// The longest reference to a stored record, in bytes: [`WatchRow::key_ref`] and
/// [`NativeOutboxEntry::from_ref`].
pub const MAX_KEY_REF_LEN: usize = 128;
/// The longest relay, as `domain[:port]`, in bytes.
pub const MAX_RELAY_LEN: usize = 300;
pub const MAX_ROUTE_METHOD_LEN: usize = 32;
pub const MAX_ROUTE_VALUE_LEN: usize = 1024;
/// The longest envelope a native post carries, in bytes.
pub const MAX_ENVELOPE_LEN: usize = 1_048_576;
/// The longest caller-chosen alias of a payment, in bytes.
pub const MAX_ALIAS_LEN: usize = 128;
pub const MAX_STATE_REASON_LEN: usize = 512;

stored_enum! {
    /// Why the wallet watches a mailbox.
    pub enum MailClass {
        Contact => "contact",
        Pairing => "pairing",
        /// An epic1 address of the wallet, public or a link's. Stored as "link", the code the
        /// stored table allows for it.
        Address => "link",
        Reply => "reply",
        InPerson => "in-person",
        /// A contact's mailbox on the relay it moved away from, until its drain ends.
        PreviousHome => "previous-home",
    }
}

/// One mailbox the wallet watches on one relay.
///
/// `key_ref` names the stored record the mailbox key is derived from; it is never key material
/// and never a mailbox address. The forms:
///
/// | `key_ref`                           | class           | relay                    | expires   |
/// |-------------------------------------|-----------------|--------------------------|-----------|
/// | `contact:<contact id hex>`          | `contact`       | the contact's home relay | never     |
/// | `contact:<contact id hex>`          | `previous-home` | the relay it moved from  | drain end |
/// | `contact-old-salt:<contact id hex>` | `contact`       | the contact's home relay | never     |
/// | `pairing:<pairing id hex>`          | `pairing`       | the invite's relay       | pairing   |
/// | `address:<account>.<index>`         | `link`          | each usable relay        | never     |
/// | `reply:<slate id>`                  | `reply`         | the reply relay          | never     |
/// | `inperson:<slate id>`               | `in-person`     | the code's mailbox relay | never     |
/// | `inperson-slot:<account>`           | `in-person`     | the slot's relay         | never     |
///
/// Slate ids are hyphenated lowercase UUIDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchRow {
    pub key_ref: String,
    /// As the source wrote it: `domain[:port]`.
    pub relay: String,
    pub class: MailClass,
    /// Watched while `expires_at` is later than now; `None` until removed.
    pub expires_at: Option<Timestamp>,
}

pub trait WatchSetRepository {
    /// Stores `row`, replacing the one with the same key reference and relay. Fails with
    /// [`StoreError::OutOfRange`] for an empty or too long key reference or relay.
    fn put_watch(&mut self, row: &WatchRow) -> Result<(), StoreError>;

    /// Deletes the row of `key_ref` on `relay`, and returns whether there was one.
    fn delete_watch(&mut self, key_ref: &str, relay: &str) -> Result<bool, StoreError>;

    /// Every row, by relay then key reference.
    fn watch_set(&self) -> Result<Vec<WatchRow>, StoreError>;

    /// Deletes the rows whose `expires_at` is not later than `now`, and returns how many.
    fn remove_expired_watches(&mut self, now: Timestamp) -> Result<usize, StoreError>;
}

stored_enum! {
    /// Where a native post stands, and the delivery state of a payment.
    pub enum OutboxState {
        Queued => "queued",
        Posted => "posted",
        /// A post went unanswered: it may have arrived.
        Uncertain => "uncertain",
        Failed => "failed",
    }
}

/// Local id of a native outbox entry, assigned by the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeOutboxId(pub u64);

impl fmt::Display for NativeOutboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A post the wallet owes for one payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeOutboxEntry {
    /// The slate id.
    pub payment_id: Uuid,
    /// The record the sending key is derived from:
    ///
    /// | `from_ref`                          | sent from                                       |
    /// |-------------------------------------|-------------------------------------------------|
    /// | `epic1-init:<account>`              | the payer's post key of the payment             |
    /// | `epic1-resp:<account>`              | the payee's post key of the payment             |
    /// | `contact:<contact id hex>`          | the contact's mailbox                           |
    /// | `contact-old-salt:<contact id hex>` | the contact's mailbox under its previous salt   |
    pub from_ref: String,
    pub route_method: String,
    pub route_value: String,
    pub envelope: String,
    pub state: OutboxState,
    pub attempts: u32,
    pub next_at: Timestamp,
    /// The height past which the post is useless; `None` when unknown.
    pub cutoff_height: Option<Height>,
    /// The stage of the slate a contact's post carries; `None` for other posts.
    pub stage: Option<SlateStage>,
    /// Whether the post carries a notice (ADR 0067). A notice has no stage.
    pub notice: bool,
    pub created_at: Timestamp,
    /// When a relay or endpoint last took the post.
    pub posted_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNativeOutbox {
    pub id: NativeOutboxId,
    pub entry: NativeOutboxEntry,
}

stored_enum! {
    /// Where one mailbox stands with a post to a key's mailbox on every relay of the list.
    pub enum CopyState {
        /// The mailbox took the post.
        Taken => "taken",
        /// The mailbox has not taken the post: it is posted there again at `next_at`.
        Owed => "owed",
        /// The mailbox took the post and the payment was answered on another: the copy is
        /// cancelled there at `next_at`.
        Cancel => "cancel",
    }
}

/// One mailbox's part in an entry posted to a key's mailbox on several relays. A copy that is
/// done with, its post or cancel no longer owed, is deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxCopy {
    /// The relay, `domain:port`.
    pub mailbox: String,
    pub state: CopyState,
    /// Posts or cancels tried since the state was set.
    pub attempts: u32,
    pub next_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOutboxCopy {
    pub id: NativeOutboxId,
    pub copy: OutboxCopy,
}

pub trait NativeOutboxRepository {
    /// Stores `entry` under a new id. Fails with [`StoreError::OutOfRange`] for a field outside
    /// its bounds.
    fn enqueue_native_outbox(
        &mut self,
        entry: &NativeOutboxEntry,
    ) -> Result<NativeOutboxId, StoreError>;

    /// Replaces the entry `id`. Fails with [`StoreError::NotFound`] when there is none.
    fn update_native_outbox(
        &mut self,
        id: NativeOutboxId,
        entry: &NativeOutboxEntry,
    ) -> Result<(), StoreError>;

    fn native_outbox_entry(
        &self,
        id: NativeOutboxId,
    ) -> Result<Option<StoredNativeOutbox>, StoreError>;

    /// The entries of one payment, by id.
    fn native_outbox_of(&self, payment_id: Uuid) -> Result<Vec<StoredNativeOutbox>, StoreError>;

    /// The queued and uncertain entries whose `next_at` is not later than `now`, earliest
    /// first.
    fn due_native_outbox(&self, now: Timestamp) -> Result<Vec<StoredNativeOutbox>, StoreError>;

    /// Deletes the entry `id`, and returns whether there was one.
    fn delete_native_outbox(&mut self, id: NativeOutboxId) -> Result<bool, StoreError>;

    /// The entries sent from `from_ref`, by id.
    fn native_outbox_from(&self, from_ref: &str) -> Result<Vec<StoredNativeOutbox>, StoreError>;

    /// Points the queued entries sent from `from_ref` whose route value is `old` at `new`, and
    /// returns how many changed. Entries in any other state keep the route they were posted on.
    fn redirect_native_outbox(
        &mut self,
        from_ref: &str,
        old: &str,
        new: &str,
    ) -> Result<usize, StoreError>;

    /// Deletes the entries sent from `from_ref`, and returns how many.
    fn delete_native_outbox_from(&mut self, from_ref: &str) -> Result<usize, StoreError>;

    /// Stores `copy` for the entry `id`, replacing the copy of the same mailbox. Fails with
    /// [`StoreError::NotFound`] when there is no entry `id`, and with
    /// [`StoreError::OutOfRange`] for an empty or too long mailbox. Deleting an entry deletes
    /// its copies.
    fn put_outbox_copy(&mut self, id: NativeOutboxId, copy: &OutboxCopy) -> Result<(), StoreError>;

    /// Deletes the copy of the entry `id` on `mailbox`, and returns whether there was one.
    fn delete_outbox_copy(&mut self, id: NativeOutboxId, mailbox: &str)
    -> Result<bool, StoreError>;

    /// The copies of the entry `id`, by mailbox.
    fn outbox_copies(&self, id: NativeOutboxId) -> Result<Vec<OutboxCopy>, StoreError>;

    /// The owed and cancelled copies whose `next_at` is not later than `now`, earliest first.
    fn due_outbox_copies(&self, now: Timestamp) -> Result<Vec<StoredOutboxCopy>, StoreError>;
}

/// The delivery state of one payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentDelivery {
    /// The slate id.
    pub payment_id: Uuid,
    /// A caller-chosen id the payment is also found by, unique among payments.
    pub alias: Option<String>,
    /// `None` when nothing was posted for the payment yet.
    pub state: Option<OutboxState>,
    pub state_reason: Option<String>,
    pub updated_at: Timestamp,
}

pub trait PaymentDeliveryRepository {
    /// Stores `delivery`, replacing the one of the same payment. Fails with
    /// [`StoreError::Duplicate`] when another payment has the alias, and with
    /// [`StoreError::OutOfRange`] for an empty or too long alias or reason.
    fn put_payment_delivery(&mut self, delivery: &PaymentDelivery) -> Result<(), StoreError>;

    fn payment_delivery(&self, payment_id: Uuid) -> Result<Option<PaymentDelivery>, StoreError>;

    fn payment_delivery_by_alias(&self, alias: &str)
    -> Result<Option<PaymentDelivery>, StoreError>;
}

fn check_text(text: &str, max: usize, field: &'static str) -> Result<(), StoreError> {
    if text.is_empty() || text.len() > max {
        return Err(StoreError::OutOfRange { field });
    }
    Ok(())
}

pub(crate) fn check_watch(row: &WatchRow) -> Result<(), StoreError> {
    check_text(&row.key_ref, MAX_KEY_REF_LEN, "watch key reference")?;
    check_text(&row.relay, MAX_RELAY_LEN, "watch relay")?;
    if let Some(time) = row.expires_at {
        timestamp_to_column(time)?;
    }
    Ok(())
}

pub(crate) fn check_native_outbox(entry: &NativeOutboxEntry) -> Result<(), StoreError> {
    check_text(&entry.from_ref, MAX_KEY_REF_LEN, "outbox sender reference")?;
    check_text(&entry.route_method, MAX_ROUTE_METHOD_LEN, "route method")?;
    check_route_value(&entry.route_value)?;
    check_text(&entry.envelope, MAX_ENVELOPE_LEN, "envelope")?;
    if entry.notice && entry.stage.is_some() {
        return Err(StoreError::InvalidStatus {
            record: Record::NativeOutbox,
        });
    }
    timestamp_to_column(entry.next_at)?;
    timestamp_to_column(entry.created_at)?;
    if let Some(time) = entry.posted_at {
        timestamp_to_column(time)?;
    }
    Ok(())
}

pub(crate) fn check_outbox_copy(copy: &OutboxCopy) -> Result<(), StoreError> {
    check_text(&copy.mailbox, MAX_RELAY_LEN, "outbox copy mailbox")?;
    timestamp_to_column(copy.next_at)?;
    Ok(())
}

pub(crate) fn check_route_value(value: &str) -> Result<(), StoreError> {
    check_text(value, MAX_ROUTE_VALUE_LEN, "route value")
}

pub(crate) fn check_payment_delivery(delivery: &PaymentDelivery) -> Result<(), StoreError> {
    if let Some(alias) = &delivery.alias {
        check_text(alias, MAX_ALIAS_LEN, "payment alias")?;
    }
    if let Some(reason) = &delivery.state_reason {
        check_text(reason, MAX_STATE_REASON_LEN, "delivery state reason")?;
    }
    timestamp_to_column(delivery.updated_at)?;
    Ok(())
}
