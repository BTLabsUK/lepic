// SPDX-License-Identifier: Apache-2.0
//! Opaque payloads over pairings: bytes the host app sends its other wallet over a private
//! pairing once both sides matched the words check, or a contact pairing once both sides have
//! heard each other (paired or verified). They are sealed to the pairing's keys (and under its
//! channel key for a private pairing) and signed, queued in the outbox, and kept on arrival until
//! the host acknowledges them. LEPIC never reads them; the host judges them.

use std::collections::BTreeSet;

use crate::hex;
use jiff::Timestamp;
use lepic_contact::{Content, MessageType, Reference};
use lepic_epicbox::Handled;
use lepic_epicbox::marker::features::APP_PAYLOADS;
use lepic_node::NodeApi;
use lepic_store::{ContactId, ContactRecord, Repositories, SlateStage, StoreError, WalletStore};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::collect::envelope_hash;
use super::private::{RecordClass, class_of, is_private};
use super::{ContactError, ContactRelays, LockedRng, new_id};
use crate::ContactBook;
use lepic_wallet::event::{ContactEvent, Event};
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// The largest payload one message carries.
pub const MAX_APP_PAYLOAD_LEN: usize = 64 * 1024;

/// Payloads from private pairings kept unacknowledged at once; more stay on the relay until the
/// host acknowledges some. Payloads from contacts do not count against it.
pub const MAX_KEPT_PAYLOADS: usize = 256;

/// Payloads from one contact kept unacknowledged at once; more stay on the relay until the host
/// acknowledges some. A contact is another person's wallet, or a service such as a name service
/// that exchanges a few small signed records over the pairing, so a host that acknowledges what
/// it reads never comes near it; it bounds what one contact can make the wallet store to an
/// eighth of the private pairings' share, which linked devices rely on.
pub const MAX_KEPT_PAYLOADS_PER_CONTACT: usize = 32;

const INDEX_KEY: &str = "contact.payloads";
const PAYLOAD_PREFIX: &str = "contact.payload.";
/// The layout of the kept payloads: absent while they are kept under their id alone, as
/// before a payload was kept per contact.
const LAYOUT_KEY: &str = "contact.payloads.layout";
const LAYOUT: &str = "2";
const ACKED_PREFIX: &str = "contact.acked.";
const PARKED_PREFIX: &str = "contact.parked.";

/// The sender's id for a payload, 32 lowercase hex characters as text: a repeat of it from the
/// same pairing is kept once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadId(Uuid);

impl PayloadId {
    /// The id `text` names, in any form a UUID is written in.
    pub fn parse(text: &str) -> Option<Self> {
        Uuid::try_parse(text).ok().map(Self)
    }

    /// Where the payload `from` (a contact id in hex) sent under this id is kept.
    fn key(self, from: &str) -> String {
        format!("{PAYLOAD_PREFIX}{from}.{}", self.0.simple())
    }

    /// Where it was kept before payloads were kept per contact.
    fn legacy_key(self) -> String {
        format!("{PAYLOAD_PREFIX}{}", self.0.simple())
    }

    /// The mark that the host acknowledged the payload `from` sent under this id.
    fn acked_key(self, from: &str) -> String {
        format!("{ACKED_PREFIX}{from}.{}", self.0.simple())
    }
}

impl std::fmt::Display for PayloadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.simple().fmt(f)
    }
}

/// A payload a paired contact sent, kept until [`Wallet::contact_payloads_ack`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactPayload {
    pub id: PayloadId,
    pub contact_id: ContactId,
    pub received_at: Timestamp,
    pub payload: Vec<u8>,
}

/// A payload queued by [`ContactBook::contact_post_payload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostedPayload {
    /// The id the other wallet keeps it under.
    pub id: PayloadId,
    /// Whether the other wallet's recorded features are known and do not claim
    /// [`APP_PAYLOADS`]: a wallet built before the bit existed, or one that does not keep
    /// payloads. The payload is queued all the same.
    pub peer_lacks_app_payloads: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index(Vec<(String, String)>);

#[derive(Serialize, Deserialize)]
struct Kept {
    received_at: i64,
    payload: String,
}

/// The index of kept payloads. A damaged one is an error rather than an empty index, which
/// the next arrival would write over and so lose every payload kept.
fn read_index(repos: &dyn Repositories) -> Result<Index, StoreError> {
    let Some(text) = repos.setting(INDEX_KEY)? else {
        return Ok(Index::default());
    };
    serde_json::from_str(&text).map_err(|_| {
        warn!("payload index not readable");
        StoreError::Corrupt {
            record: lepic_store::Record::Contact,
            field: "payload index",
        }
    })
}

fn write_index(repos: &mut dyn Repositories, index: &Index) -> Result<(), StoreError> {
    let text = serde_json::to_string(index).map_err(|_| StoreError::Corrupt {
        record: lepic_store::Record::Contact,
        field: "payload index",
    })?;
    repos.put_setting(INDEX_KEY, &text)
}

/// Moves payloads kept under their id alone to the key of the pairing that sent them, once,
/// in the transaction of whatever first touches the kept payloads. The index is unchanged; an
/// entry whose payload is already under its new key keeps that one.
fn migrate(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    if repos.setting(LAYOUT_KEY)?.as_deref() == Some(LAYOUT) {
        return Ok(());
    }
    for (id, from) in read_index(repos)?.0 {
        let Some(id) = PayloadId::parse(&id) else {
            continue;
        };
        let Some(text) = repos.setting(&id.legacy_key())? else {
            continue;
        };
        if repos.setting(&id.key(&from))?.is_none() {
            repos.put_setting(&id.key(&from), &text)?;
        }
        repos.delete_setting(&id.legacy_key())?;
    }
    repos.put_setting(LAYOUT_KEY, LAYOUT)
}

/// What became of a payload that arrived.
#[derive(Debug, PartialEq, Eq)]
enum Arrival {
    New,
    Repeat,
    Full { cap: usize },
}

/// The kind of pairing a payload came over, which decides the cap it counts against.
#[derive(Clone, Copy)]
enum Sender {
    Private,
    Contact,
}

impl Sender {
    fn of(record: &ContactRecord) -> Self {
        if is_private(record) {
            Self::Private
        } else {
            Self::Contact
        }
    }
}

/// Whether the payloads kept from `sender` fill its cap: [`MAX_KEPT_PAYLOADS_PER_CONTACT`] for
/// one contact, [`MAX_KEPT_PAYLOADS`] for the private pairings together. An entry whose pairing
/// is gone counts against the private share, so the total stays bounded.
fn full(
    repos: &dyn Repositories,
    index: &Index,
    contact_id: ContactId,
    sender: Sender,
) -> Result<Option<usize>, StoreError> {
    let (cap, kept) = match sender {
        Sender::Contact => {
            let ours = hex::encode(&contact_id.0);
            let kept = index.0.iter().filter(|(_, from)| *from == ours).count();
            (MAX_KEPT_PAYLOADS_PER_CONTACT, kept)
        }
        Sender::Private => {
            let mut kept = 0usize;
            let mut classes: Vec<(&str, bool)> = Vec::new();
            for (_, from) in &index.0 {
                let from_contact = match classes.iter().find(|(seen, _)| *seen == from) {
                    Some(&(_, class)) => class,
                    None => {
                        let class = match contact_of(from) {
                            Some(id) => repos
                                .contact(id)?
                                .is_some_and(|record| !is_private(&record)),
                            None => false,
                        };
                        classes.push((from, class));
                        class
                    }
                };
                if !from_contact {
                    kept = kept.saturating_add(1);
                }
            }
            (MAX_KEPT_PAYLOADS, kept)
        }
    };
    Ok((kept >= cap).then_some(cap))
}

/// Keeps `payload` from `contact_id` under `id`, unless that pairing's payload `id` is kept
/// already or was acknowledged, or the cap of `sender` is reached.
fn keep(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    sender: Sender,
    id: PayloadId,
    payload: &[u8],
    now: Timestamp,
) -> Result<Arrival, StoreError> {
    migrate(repos)?;
    let mut index = read_index(repos)?;
    let from = hex::encode(&contact_id.0);
    let kept_already = index
        .0
        .iter()
        .any(|(kept, by)| *by == from && PayloadId::parse(kept) == Some(id));
    if kept_already || repos.setting(&id.acked_key(&from))?.is_some() {
        return Ok(Arrival::Repeat);
    }
    if let Some(cap) = full(repos, &index, contact_id, sender)? {
        return Ok(Arrival::Full { cap });
    }
    let kept = Kept {
        received_at: now.as_millisecond(),
        payload: hex::encode(payload),
    };
    let text = serde_json::to_string(&kept).map_err(|_| StoreError::Corrupt {
        record: lepic_store::Record::Contact,
        field: "payload",
    })?;
    repos.put_setting(&id.key(&from), &text)?;
    index.0.push((id.to_string(), from));
    write_index(repos, &index)?;
    Ok(Arrival::New)
}

/// The payload kept under `id` from `from`, when it is there and reads.
fn read_kept(
    repos: &dyn Repositories,
    id: PayloadId,
    from: &str,
) -> Result<Option<(Vec<u8>, Timestamp)>, StoreError> {
    let Some(text) = repos.setting(&id.key(from))? else {
        return Ok(None);
    };
    Ok(serde_json::from_str::<Kept>(&text).ok().and_then(|kept| {
        Some((
            hex::unhex(&kept.payload)?,
            Timestamp::from_millisecond(kept.received_at).ok()?,
        ))
    }))
}

/// The kept payloads, oldest first. An index entry whose payload is missing or does not read
/// is forgotten, so it no longer counts against a cap; one damaged entry does not hide the
/// others.
fn kept_payloads(repos: &mut dyn Repositories) -> Result<Vec<ContactPayload>, StoreError> {
    migrate(repos)?;
    let index = read_index(repos)?;
    let mut live = Index::default();
    let mut payloads = Vec::new();
    let mut forgotten = false;
    for (id_text, from) in index.0 {
        let id = PayloadId::parse(&id_text);
        let found = match (id, contact_of(&from)) {
            (Some(id), Some(contact_id)) => {
                read_kept(repos, id, &from)?.map(|(payload, received_at)| ContactPayload {
                    id,
                    contact_id,
                    received_at,
                    payload,
                })
            }
            _ => None,
        };
        if let Some(payload) = found {
            payloads.push(payload);
            live.0.push((id_text, from));
        } else {
            warn!("kept payload not readable, forgotten");
            if let Some(id) = id {
                repos.delete_setting(&id.key(&from))?;
            }
            forgotten = true;
        }
    }
    if forgotten {
        write_index(repos, &live)?;
        unpark(repos)?;
    }
    Ok(payloads)
}

/// Forgets the kept payloads `ids` names, from whichever pairing sent them, and marks each as
/// acknowledged at `now`. Returns how many were forgotten.
///
/// The marks stay bounded: only the acknowledgement of a payload that was kept writes one, and
/// a payload is kept only under its pairing's cap, so they grow no faster than the payloads the
/// caps let in, each of which leaves a remembered envelope too. [`forget_old_marks`] drops a
/// mark once a payload sealed before it was written could no longer be taken.
fn forget(
    repos: &mut dyn Repositories,
    ids: &[PayloadId],
    now: Timestamp,
) -> Result<usize, StoreError> {
    migrate(repos)?;
    let index = read_index(repos)?;
    let (gone, live): (Vec<_>, Vec<_>) = index
        .0
        .into_iter()
        .partition(|(id, _)| PayloadId::parse(id).is_some_and(|id| ids.contains(&id)));
    let seconds = now.as_second().to_string();
    for (id, from) in &gone {
        let Some(id) = PayloadId::parse(id) else {
            continue;
        };
        repos.delete_setting(&id.key(from))?;
        if contact_of(from).is_some() {
            repos.put_setting(&id.acked_key(from), &seconds)?;
        }
    }
    if !gone.is_empty() {
        write_index(repos, &Index(live))?;
        unpark(repos)?;
    }
    Ok(gone.len())
}

/// Forgets the acknowledgement marks and parked messages older than `lifetime`: by then any
/// payload sealed before the mark was written is refused as too old.
pub(crate) fn forget_old_marks(
    repos: &mut dyn Repositories,
    now: Timestamp,
    lifetime: std::time::Duration,
) -> Result<(), StoreError> {
    let now = now.as_second();
    let lifetime = i64::try_from(lifetime.as_secs()).unwrap_or(i64::MAX);
    let old =
        |written: Option<i64>| written.is_none_or(|written| now.saturating_sub(written) > lifetime);
    for (key, value) in repos.settings_with_prefix(ACKED_PREFIX)? {
        if old(value.parse().ok()) {
            repos.delete_setting(&key)?;
        }
    }
    for (key, value) in repos.settings_with_prefix(PARKED_PREFIX)? {
        let written = value.split_once(':').and_then(|(_, at)| at.parse().ok());
        if old(written) {
            repos.delete_setting(&key)?;
        }
    }
    Ok(())
}

fn parked_key(hash: &[u8; 32]) -> String {
    format!("{PARKED_PREFIX}{}", hex::encode(hash))
}

/// Notes that the envelope `hash` from `contact_id` holds a payload left on the relay because
/// its cap was reached, so the next cycle leaves it there without opening it again.
fn park(
    repos: &mut dyn Repositories,
    hash: &[u8; 32],
    contact_id: ContactId,
    now: Timestamp,
) -> Result<(), StoreError> {
    let value = format!("{}:{}", hex::encode(&contact_id.0), now.as_second());
    repos.put_setting(&parked_key(hash), &value)
}

/// Whether the envelope `hash` from `contact_id` holds a payload left on the relay for its cap,
/// and the cap is still reached.
pub(crate) fn still_parked(
    repos: &dyn Repositories,
    hash: &[u8; 32],
    contact_id: ContactId,
) -> Result<bool, StoreError> {
    let Some(value) = repos.setting(&parked_key(hash))? else {
        return Ok(false);
    };
    let from = hex::encode(&contact_id.0);
    if value.split_once(':').map(|(by, _)| by) != Some(from.as_str()) {
        return Ok(false);
    }
    let Some(record) = repos.contact(contact_id)? else {
        return Ok(false);
    };
    Ok(full(repos, &read_index(repos)?, contact_id, Sender::of(&record))?.is_some())
}

/// Forgets every parked message: room was made, so each is opened again.
fn unpark(repos: &mut dyn Repositories) -> Result<(), StoreError> {
    for (key, _) in repos.settings_with_prefix(PARKED_PREFIX)? {
        repos.delete_setting(&key)?;
    }
    Ok(())
}

/// Whether a peer that claimed `features` is known not to keep app payloads: 0 is a peer whose
/// features were never received, which says nothing.
fn lacks_app_payloads(features: u32) -> bool {
    features != 0 && features & APP_PAYLOADS == 0
}

/// The contact a stored id names, when it is one.
fn contact_of(text: &str) -> Option<ContactId> {
    hex::unhex(text)?.try_into().ok().map(ContactId)
}

/// Whether `record` is a pairing payloads may travel over: paired, with the peer's card.
fn sendable(record: &ContactRecord) -> bool {
    record.peer.is_some() && heard_both_ways(record)
}

/// Whether both sides of `record` have heard each other: paired or verified.
fn heard_both_ways(record: &ContactRecord) -> bool {
    matches!(
        record.state,
        lepic_store::ContactState::Paired | lepic_store::ContactState::Verified
    )
}

/// Whether a payload may travel over `record` now. A private pairing waits for the words check,
/// since its payloads are the owner's own; a contact pairing passes once paired, so a service's
/// first record can reach the wallet before the user compares the words, and the host judges
/// what the bytes are worth.
fn open_for_payloads(record: &ContactRecord) -> bool {
    if is_private(record) {
        record.state == lepic_store::ContactState::Verified
    } else {
        heard_both_ways(record)
    }
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Sends `payload` through the pairing `contact_id`, a private pairing or a contact: sealed
    /// to its keys, under its channel key for a private pairing, and signed with ours, queued in the outbox, and posted once when relays may
    /// be reached; the outbox retries it as it retries slates. Returns the payload's id, under
    /// which the other wallet keeps it once, and whether the other wallet's recorded features
    /// are known and lack [`APP_PAYLOADS`]; the payload is queued either way. LEPIC does not
    /// read the bytes.
    ///
    /// Fails with [`ContactError::TooLarge`] for more than [`MAX_APP_PAYLOAD_LEN`] bytes,
    /// [`ContactError::Ended`] for an ended contact pairing, [`ContactError::NotVerified`] for a
    /// contact pairing not yet paired (pending, or keys changed) and for a private pairing
    /// before both sides matched the words check, [`ContactError::UnknownContact`] for no such pairing or
    /// one whose secrets do not open, and as the store does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_post_payload(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        payload: Vec<u8>,
    ) -> Result<PostedPayload, ContactError> {
        if payload.len() > MAX_APP_PAYLOAD_LEN {
            return Err(ContactError::TooLarge {
                max: MAX_APP_PAYLOAD_LEN,
            });
        }
        self.check_contact_network(relays)?;
        let session = self.wallet.session()?;
        let (record, id) = self
            .contact_work(move |ports, _| {
                session.store.read(|repos| {
                    let record = repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    match class_of(repos, &record)? {
                        RecordClass::Unreadable => return Err(ContactError::UnknownContact),
                        RecordClass::Private(_) if !sendable(&record) => {
                            return Err(ContactError::UnknownContact);
                        }
                        RecordClass::Private(_) => {}
                        RecordClass::Contact if record.facts.ended_reason.is_some() => {
                            return Err(ContactError::Ended);
                        }
                        RecordClass::Contact if record.peer.is_none() => {
                            return Err(ContactError::NotVerified);
                        }
                        RecordClass::Contact => {}
                    }
                    if !open_for_payloads(&record) {
                        return Err(ContactError::NotVerified);
                    }
                    let id = PayloadId(Uuid::from_bytes(new_id(&mut LockedRng(
                        &mut **ports.rng.lock(),
                    ))));
                    Ok((record, id))
                })
            })
            .await?;
        let reference = Reference::new(&id.to_string()).map_err(ContactError::Name)?;
        let envelope = self
            .seal_for_contact(
                &record,
                Content {
                    reference: Some(reference),
                    ..Content::new(MessageType::AppPayload, payload)
                },
            )
            .await?;
        self.enqueue_for_contact(contact_id, id.0, SlateStage::Standard1, &envelope)
            .await?;
        self.deliver_soon(relays).await;
        info!("payload queued for a pairing");
        let features = record.facts.peer_features;
        let peer_lacks_app_payloads = lacks_app_payloads(features);
        if peer_lacks_app_payloads {
            warn!(
                features,
                "the other wallet does not claim app payloads; it may not keep this one"
            );
        }
        Ok(PostedPayload {
            id,
            peer_lacks_app_payloads,
        })
    }

    /// The payloads private pairings and contacts sent that the host has not acknowledged,
    /// oldest first. One that no longer reads is forgotten, so its room under the cap is free.
    pub async fn contact_payloads(&self) -> Result<Vec<ContactPayload>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| Ok(session.store.write(kept_payloads)?))
            .await
    }

    /// Forgets the kept payloads `ids` names, from whichever pairing sent them; ids not kept are
    /// ignored. A payload forgotten is not kept again when its pairing sends it once more.
    /// Returns how many were forgotten.
    pub async fn contact_payloads_ack(&self, ids: &[PayloadId]) -> Result<usize, ContactError> {
        let ids: Vec<PayloadId> = ids.to_vec();
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.write(|repos| forget(repos, &ids, now))?)
        })
        .await
    }

    /// Whether the envelope `hash` from `contact_id` holds a payload left on the relay for its
    /// cap, which is still reached: it stays there without being opened again.
    pub(crate) async fn payload_parked(
        &self,
        hash: [u8; 32],
        contact_id: ContactId,
    ) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .read(|repos| still_parked(repos, &hash, contact_id))?)
        })
        .await
    }

    /// Raises [`Event::ContactPayloadsParked`] for `contact_id`, once a cycle in `told`.
    pub(crate) fn tell_parked(&self, contact_id: ContactId, told: &mut BTreeSet<ContactId>) {
        if told.insert(contact_id) {
            self.wallet
                .emit(Event::ContactPayloadsParked(ContactEvent { contact_id }));
        }
    }

    /// Keeps a payload the pairing `record` carried, then raises [`Event::ContactPayload`]; a
    /// repeat is acknowledged and kept once, one without its id or too large is dropped, and
    /// one that finds its cap reached ([`MAX_KEPT_PAYLOADS`] for the private pairings,
    /// [`MAX_KEPT_PAYLOADS_PER_CONTACT`] for each contact), or arrives before the pairing is open
    /// for payloads here (a private pairing before this side matched the words check, a contact
    /// pairing before it is paired), stays on the relay. One left for its cap is noted under the
    /// hash of its `envelope`, so later cycles leave it without opening it, and raises
    /// [`Event::ContactPayloadsParked`] once a cycle in `told`.
    pub(crate) async fn take_contact_payload(
        &self,
        record: &ContactRecord,
        content: Content,
        envelope: &[u8],
        told: &mut BTreeSet<ContactId>,
    ) -> Result<Handled, ContactError> {
        let contact_id = record.contact_id;
        let sender = Sender::of(record);
        if !open_for_payloads(record) {
            return Ok(Handled::Later);
        }
        let id = content
            .reference
            .as_ref()
            .and_then(|reference| PayloadId::parse(reference.as_str()));
        let Some(id) = id.filter(|_| content.body.len() <= MAX_APP_PAYLOAD_LEN) else {
            debug!("malformed payload from a contact dropped");
            return Ok(Handled::Stored);
        };
        let session = self.wallet.session()?;
        let body = content.body;
        let hash = envelope_hash(envelope);
        let kept = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let kept = keep(repos, contact_id, sender, id, &body, now)?;
                    if matches!(kept, Arrival::Full { .. }) {
                        park(repos, &hash, contact_id, now)?;
                    }
                    Ok::<_, StoreError>(kept)
                })?)
            })
            .await?;
        Ok(match kept {
            Arrival::New => {
                debug!("payload from a contact kept");
                self.wallet
                    .emit(Event::ContactPayload(ContactEvent { contact_id }));
                Handled::Stored
            }
            Arrival::Repeat => Handled::Stored,
            Arrival::Full { cap } => {
                warn!(count = cap, "payloads unacknowledged; left on the relay");
                self.tell_parked(contact_id, told);
                Handled::Later
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;
    use lepic_store::{AccountIndex, ContactState, MemoryStore, PairingFacts, SealMode, StoreKeys};

    const ANNA: ContactId = ContactId([1; 16]);
    const BEN: ContactId = ContactId([2; 16]);

    fn id(n: u128) -> PayloadId {
        PayloadId(Uuid::from_u128(n))
    }

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    fn store() -> MemoryStore {
        MemoryStore::new(StoreKeys::from_bytes([1; 32], [1; 32]))
    }

    fn contact(contact_id: ContactId) -> ContactRecord {
        ContactRecord {
            contact_id,
            account: AccountIndex(0),
            slot: 0,
            box_salt: [0; 16],
            own_card: Vec::new(),
            peer: None,
            alternate: None,
            label: String::new(),
            state: ContactState::Verified,
            sas: None,
            verified_at: None,
            allow_invoices: false,
            seal: SealMode::On,
            last_sealed_in: None,
            app_contact: None,
            imported_from_backup: false,
            created_at: at(0),
            updated_at: at(0),
            facts: PairingFacts::default(),
        }
    }

    fn arrive(store: &MemoryStore, from: ContactId, payload: PayloadId, now: i64) -> Arrival {
        store
            .write(|repos| keep(repos, from, Sender::Contact, payload, b"bytes", at(now)))
            .unwrap()
    }

    fn listed(store: &MemoryStore) -> Vec<(PayloadId, ContactId)> {
        store
            .write(kept_payloads)
            .unwrap()
            .into_iter()
            .map(|kept| (kept.id, kept.contact_id))
            .collect()
    }

    fn ack(store: &MemoryStore, ids: &[PayloadId], now: i64) -> usize {
        store.write(|repos| forget(repos, ids, at(now))).unwrap()
    }

    #[test]
    fn a_payload_acknowledged_is_a_repeat_when_it_arrives_again() {
        let store = store();
        assert_eq!(arrive(&store, ANNA, id(1), 10), Arrival::New);
        assert_eq!(ack(&store, &[id(1)], 20), 1);
        assert_eq!(arrive(&store, ANNA, id(1), 30), Arrival::Repeat);
        assert!(listed(&store).is_empty());
    }

    #[test]
    fn acknowledgement_marks_are_forgotten_once_old() {
        let store = store();
        arrive(&store, ANNA, id(1), 10);
        ack(&store, &[id(1)], 100);
        let lifetime = std::time::Duration::from_secs(1000);
        store
            .write(|repos| forget_old_marks(repos, at(1100), lifetime))
            .unwrap();
        assert_eq!(arrive(&store, ANNA, id(2), 1100), Arrival::New);
        assert_eq!(ack(&store, &[id(2)], 1100), 1);
        store
            .write(|repos| forget_old_marks(repos, at(1101), lifetime))
            .unwrap();
        let marks = store
            .read(|repos| repos.settings_with_prefix(ACKED_PREFIX))
            .unwrap();
        assert_eq!(marks.len(), 1);
        assert!(marks[0].0.ends_with(&id(2).to_string()));
    }

    #[test]
    fn two_pairings_may_use_one_id_and_each_payload_is_kept() {
        let store = store();
        assert_eq!(arrive(&store, ANNA, id(1), 10), Arrival::New);
        assert_eq!(arrive(&store, BEN, id(1), 11), Arrival::New);
        assert_eq!(arrive(&store, BEN, id(1), 12), Arrival::Repeat);
        assert_eq!(listed(&store), vec![(id(1), ANNA), (id(1), BEN)]);
        assert_eq!(ack(&store, &[id(1)], 20), 2);
        assert_eq!(arrive(&store, ANNA, id(1), 30), Arrival::Repeat);
        assert_eq!(arrive(&store, BEN, id(1), 30), Arrival::Repeat);
    }

    #[test]
    fn payloads_kept_under_their_id_alone_still_list_and_acknowledge() {
        let store = store();
        let kept = r#"{"received_at":5000,"payload":"6f6c64"}"#;
        store
            .write(|repos| {
                repos.put_setting(&id(1).legacy_key(), kept)?;
                repos.put_setting(&id(2).legacy_key(), kept)?;
                let index = Index(vec![
                    (id(1).to_string(), hex::encode(&ANNA.0)),
                    (id(2).to_string(), hex::encode(&BEN.0)),
                ]);
                write_index(repos, &index)
            })
            .unwrap();
        let payloads = store.write(kept_payloads).unwrap();
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].payload, b"old");
        assert_eq!(
            payloads[0].received_at,
            Timestamp::from_millisecond(5000).unwrap()
        );
        assert_eq!(payloads[1].contact_id, BEN);
        let legacy = store
            .read(|repos| repos.setting(&id(1).legacy_key()))
            .unwrap();
        assert_eq!(legacy, None);

        assert_eq!(ack(&store, &[id(1)], 20), 1);
        assert_eq!(listed(&store), vec![(id(2), BEN)]);
        assert_eq!(arrive(&store, ANNA, id(1), 30), Arrival::Repeat);
    }

    #[test]
    fn the_old_layout_moves_on_the_first_arrival_too() {
        let store = store();
        let kept = r#"{"received_at":5000,"payload":"6f6c64"}"#;
        store
            .write(|repos| {
                repos.put_setting(&id(1).legacy_key(), kept)?;
                write_index(
                    repos,
                    &Index(vec![(id(1).to_string(), hex::encode(&ANNA.0))]),
                )
            })
            .unwrap();
        assert_eq!(arrive(&store, ANNA, id(1), 10), Arrival::Repeat);
        assert_eq!(arrive(&store, ANNA, id(2), 10), Arrival::New);
        assert_eq!(listed(&store), vec![(id(1), ANNA), (id(2), ANNA)]);
    }

    #[test]
    fn an_entry_that_does_not_read_is_forgotten_and_frees_its_room() {
        let store = store();
        for n in 0..MAX_KEPT_PAYLOADS_PER_CONTACT {
            arrive(&store, ANNA, id(n as u128), 10);
        }
        assert!(matches!(
            arrive(&store, ANNA, id(100), 10),
            Arrival::Full { .. }
        ));
        store
            .write(|repos| {
                repos.delete_setting(&id(0).key(&hex::encode(&ANNA.0)))?;
                repos.put_setting(&id(1).key(&hex::encode(&ANNA.0)), "not json")
            })
            .unwrap();
        assert_eq!(listed(&store).len(), MAX_KEPT_PAYLOADS_PER_CONTACT - 2);
        let index = store.read(|repos| read_index(repos)).unwrap();
        assert_eq!(index.0.len(), MAX_KEPT_PAYLOADS_PER_CONTACT - 2);
        assert_eq!(arrive(&store, ANNA, id(100), 10), Arrival::New);
        assert_eq!(arrive(&store, ANNA, id(101), 10), Arrival::New);
        assert!(matches!(
            arrive(&store, ANNA, id(102), 10),
            Arrival::Full { .. }
        ));
    }

    #[test]
    fn a_parked_message_stays_parked_until_room_is_made() {
        let store = store();
        store
            .write(|repos| repos.put_contact(&contact(ANNA)))
            .unwrap();
        for n in 0..MAX_KEPT_PAYLOADS_PER_CONTACT {
            arrive(&store, ANNA, id(n as u128), 10);
        }
        let hash = [7; 32];
        let parked = |contact_id| {
            store
                .read(|repos| still_parked(repos, &hash, contact_id))
                .unwrap()
        };
        assert!(!parked(ANNA));
        store
            .write(|repos| park(repos, &hash, ANNA, at(10)))
            .unwrap();
        assert!(parked(ANNA));
        assert!(!parked(BEN));
        ack(&store, &[id(0)], 20);
        assert!(!parked(ANNA));

        arrive(&store, ANNA, id(100), 30);
        store
            .write(|repos| park(repos, &hash, ANNA, at(30)))
            .unwrap();
        assert!(parked(ANNA));
        let lifetime = std::time::Duration::from_secs(100);
        store
            .write(|repos| forget_old_marks(repos, at(131), lifetime))
            .unwrap();
        assert!(!parked(ANNA));
    }

    #[test]
    fn only_a_peer_whose_features_are_known_can_lack_app_payloads() {
        use lepic_epicbox::marker::features::{LEPIC_FEATURES, MARKER, STATUS_NOTICES};
        assert!(!lacks_app_payloads(0));
        assert!(!lacks_app_payloads(LEPIC_FEATURES));
        assert!(lacks_app_payloads(MARKER | STATUS_NOTICES));
    }
}
