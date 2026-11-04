// SPDX-License-Identifier: Apache-2.0
//! Opaque payloads over pairings: bytes the host app sends its other wallet over a private
//! pairing once both sides matched the words check, or a contact pairing once both sides have
//! heard each other (paired or verified). They are sealed to the pairing's keys (and under its
//! channel key for a private pairing) and signed, queued in the outbox, and kept on arrival until
//! the host acknowledges them. LEPIC never reads them; the host judges them.

use crate::hex;
use jiff::Timestamp;
use lepic_contact::{Content, MessageType, Reference};
use lepic_epicbox::Handled;
use lepic_node::NodeApi;
use lepic_store::{ContactId, ContactRecord, Repositories, SlateStage, StoreError, WalletStore};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

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
/// acknowledges some. A contact is another person's wallet, or a service such as a directory
/// that exchanges a few small signed records over the pairing, so a host that acknowledges what
/// it reads never comes near it; it bounds what one contact can make the wallet store to an
/// eighth of the private pairings' share, which linked devices rely on.
pub const MAX_KEPT_PAYLOADS_PER_CONTACT: usize = 32;

const INDEX_KEY: &str = "contact.payloads";
const PAYLOAD_PREFIX: &str = "contact.payload.";

/// The sender's id for a payload, 32 lowercase hex characters as text: a repeat of it is kept
/// once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadId(Uuid);

impl PayloadId {
    /// The id `text` names, in any form a UUID is written in.
    pub fn parse(text: &str) -> Option<Self> {
        Uuid::try_parse(text).ok().map(Self)
    }

    fn key(self) -> String {
        format!("{PAYLOAD_PREFIX}{}", self.0.simple())
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

/// What became of a payload that arrived.
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

/// Keeps `payload` from `contact_id` under `id`, unless it is kept already or the cap of
/// `sender` is reached.
fn keep(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    sender: Sender,
    id: PayloadId,
    payload: &[u8],
    now: Timestamp,
) -> Result<Arrival, StoreError> {
    let mut index = read_index(repos)?;
    let id_text = id.to_string();
    if index.0.iter().any(|(kept, _)| *kept == id_text) {
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
    repos.put_setting(&id.key(), &text)?;
    index.0.push((id_text, hex::encode(&contact_id.0)));
    write_index(repos, &index)?;
    Ok(Arrival::New)
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
    /// which the other wallet keeps it once. LEPIC does not read the bytes.
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
    ) -> Result<PayloadId, ContactError> {
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
        Ok(id)
    }

    /// The payloads private pairings and contacts sent that the host has not acknowledged,
    /// oldest first.
    pub async fn contact_payloads(&self) -> Result<Vec<ContactPayload>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                let mut payloads = Vec::new();
                for (id, contact) in read_index(repos)?.0 {
                    let (Some(id), Some(contact_id)) =
                        (PayloadId::parse(&id), contact_of(&contact))
                    else {
                        continue;
                    };
                    let Some(text) = repos.setting(&id.key())? else {
                        continue;
                    };
                    let decoded = serde_json::from_str::<Kept>(&text).ok().and_then(|kept| {
                        Some((
                            hex::unhex(&kept.payload)?,
                            Timestamp::from_millisecond(kept.received_at).ok()?,
                        ))
                    });
                    // One damaged entry does not hide the others.
                    let Some((payload, received_at)) = decoded else {
                        warn!("kept payload not readable, skipped");
                        continue;
                    };
                    payloads.push(ContactPayload {
                        id,
                        contact_id,
                        received_at,
                        payload,
                    });
                }
                Ok::<_, StoreError>(payloads)
            })?)
        })
        .await
    }

    /// Forgets the kept payloads `ids` names; ids not kept are ignored. Returns how many were
    /// forgotten.
    pub async fn contact_payloads_ack(&self, ids: &[PayloadId]) -> Result<usize, ContactError> {
        let ids: Vec<PayloadId> = ids.to_vec();
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.write(|repos| {
                let mut index = read_index(repos)?;
                let before = index.0.len();
                index
                    .0
                    .retain(|(id, _)| PayloadId::parse(id).is_none_or(|id| !ids.contains(&id)));
                for id in &ids {
                    repos.delete_setting(&id.key())?;
                }
                write_index(repos, &index)?;
                Ok::<_, StoreError>(before.saturating_sub(index.0.len()))
            })?)
        })
        .await
    }

    /// Keeps a payload the pairing `record` carried, then raises [`Event::ContactPayload`]; a
    /// repeat is acknowledged and kept once, one without its id or too large is dropped, and
    /// one that finds its cap reached ([`MAX_KEPT_PAYLOADS`] for the private pairings,
    /// [`MAX_KEPT_PAYLOADS_PER_CONTACT`] for each contact), or arrives before the pairing is open
    /// for payloads here (a private pairing before this side matched the words check, a contact
    /// pairing before it is paired), stays on the relay.
    pub(crate) async fn take_contact_payload(
        &self,
        record: &ContactRecord,
        content: Content,
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
        let kept = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session
                    .store
                    .write(|repos| keep(repos, contact_id, sender, id, &body, now))?)
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
                Handled::Later
            }
        })
    }
}
