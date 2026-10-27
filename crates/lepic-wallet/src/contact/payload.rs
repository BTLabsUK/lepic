//! Opaque payloads between paired wallets: bytes the host app sends its paired counterpart,
//! sealed and signed as every contact message is, queued in the outbox, and kept on arrival
//! until the host acknowledges them. LEPIC never reads them.

use jiff::Timestamp;
use lepic_contact::{ContactCard, Content, MessageType, Reference, seal};
use lepic_epicbox::Handled;
use lepic_node::NodeApi;
use lepic_store::{ContactId, ContactRecord, Repositories, SlateStage, StoreError, WalletStore};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::keys::{contact_keys, contact_network, signing_key};
use super::{ContactError, ContactRelays, LockedRng, new_id};
use crate::event::{ContactEvent, Event};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// The largest payload one message carries.
pub const MAX_APP_PAYLOAD_LEN: usize = 64 * 1024;

/// Payloads kept unacknowledged at once; more stay on the relay until the host acknowledges
/// some.
pub const MAX_KEPT_PAYLOADS: usize = 256;

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

fn read_index(repos: &dyn Repositories) -> Result<Index, StoreError> {
    Ok(repos
        .setting(INDEX_KEY)?
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default())
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
    Full,
}

/// Keeps `payload` from `contact_id` under `id`, unless it is kept already or the store holds
/// [`MAX_KEPT_PAYLOADS`].
fn keep(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    id: PayloadId,
    payload: &[u8],
    now: Timestamp,
) -> Result<Arrival, StoreError> {
    let mut index = read_index(repos)?;
    let id_text = id.to_string();
    if index.0.iter().any(|(kept, _)| *kept == id_text) {
        return Ok(Arrival::Repeat);
    }
    if index.0.len() >= MAX_KEPT_PAYLOADS {
        return Ok(Arrival::Full);
    }
    let kept = Kept {
        received_at: now.as_millisecond(),
        payload: hex(payload),
    };
    let text = serde_json::to_string(&kept).map_err(|_| StoreError::Corrupt {
        record: lepic_store::Record::Contact,
        field: "payload",
    })?;
    repos.put_setting(&id.key(), &text)?;
    index.0.push((id_text, hex(&contact_id.0)));
    write_index(repos, &index)?;
    Ok(Arrival::New)
}

/// The contact a stored id names, when it is one.
fn contact_of(text: &str) -> Option<ContactId> {
    unhex(text)?.try_into().ok().map(ContactId)
}

/// Whether `record` is a pairing payloads may travel over: paired, with the peer's card.
fn sendable(record: &ContactRecord) -> bool {
    record.peer.is_some()
        && matches!(
            record.state,
            lepic_store::ContactState::Paired | lepic_store::ContactState::Verified
        )
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Sends `payload` to the paired contact `contact_id`: sealed to its keys and signed with
    /// ours, queued in the outbox, and posted once when relays may be reached; the outbox
    /// retries it as it retries slates. Returns the payload's id, under which the contact keeps
    /// it once. LEPIC does not read the bytes.
    ///
    /// Fails with [`ContactError::TooLarge`] for more than [`MAX_APP_PAYLOAD_LEN`] bytes,
    /// [`ContactError::UnknownContact`] for a contact that is not paired, and as the store
    /// does.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
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
        let network = self.config().network;
        let net = contact_network(network);
        let session = self.session()?;
        let (id, envelope) = self
            .contact_work(move |ports, _| {
                session.store.read(|repos| {
                    let record = repos
                        .contact(contact_id)?
                        .filter(sendable)
                        .ok_or(ContactError::UnknownContact)?;
                    let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
                    let card =
                        ContactCard::decode(&peer.bytes, net).map_err(ContactError::StoredData)?;
                    let keys = contact_keys(
                        &session.keychain,
                        network,
                        record.account,
                        record.slot,
                        record.box_salt,
                    )?;
                    let mut rng = LockedRng(&mut **ports.rng.lock());
                    let id = PayloadId(Uuid::from_bytes(new_id(&mut rng)));
                    let reference = Reference::new(&id.to_string()).map_err(ContactError::Name)?;
                    let content = Content {
                        reference: Some(reference),
                        ..Content::new(MessageType::AppPayload, payload)
                    };
                    let envelope = seal(
                        net,
                        card.enc_key(),
                        card.hint_rule(),
                        &content,
                        Some(&signing_key(&keys)),
                        &mut rng,
                    )
                    .map_err(ContactError::Encode)?;
                    Ok::<_, ContactError>((id, envelope))
                })
            })
            .await?;
        self.enqueue_for_contact(contact_id, id.0, SlateStage::Standard1, &envelope)
            .await?;
        self.deliver_soon(relays).await;
        info!("payload queued for a contact");
        Ok(id)
    }

    /// The payloads contacts sent that the host has not acknowledged, oldest first.
    pub async fn contact_payloads(&self) -> Result<Vec<ContactPayload>, ContactError> {
        let session = self.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                let mut payloads = Vec::new();
                for (id, contact) in read_index(repos)?.0 {
                    let (Some(id), Some(contact_id)) =
                        (PayloadId::parse(&id), contact_of(&contact))
                    else {
                        continue;
                    };
                    let Some(kept) = repos
                        .setting(&id.key())?
                        .and_then(|text| serde_json::from_str::<Kept>(&text).ok())
                    else {
                        continue;
                    };
                    let (Some(payload), Ok(received_at)) = (
                        unhex(&kept.payload),
                        Timestamp::from_millisecond(kept.received_at),
                    ) else {
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
        let session = self.session()?;
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

    /// Keeps a payload the contact of `record` sent, then raises [`Event::ContactPayload`];
    /// a repeat is acknowledged and kept once, one without its id or too large is dropped, and
    /// one that finds the store full stays on the relay.
    pub(crate) async fn take_contact_payload(
        &self,
        record: &ContactRecord,
        content: Content,
    ) -> Result<Handled, ContactError> {
        let contact_id = record.contact_id;
        let id = content
            .reference
            .as_ref()
            .and_then(|reference| PayloadId::parse(reference.as_str()));
        let Some(id) = id.filter(|_| content.body.len() <= MAX_APP_PAYLOAD_LEN) else {
            debug!("malformed payload from a contact dropped");
            return Ok(Handled::Stored);
        };
        let session = self.session()?;
        let body = content.body;
        let kept = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session
                    .store
                    .write(|repos| keep(repos, contact_id, id, &body, now))?)
            })
            .await?;
        Ok(match kept {
            Arrival::New => {
                debug!("payload from a contact kept");
                self.emit(Event::ContactPayload(ContactEvent { contact_id }));
                Handled::Stored
            }
            Arrival::Repeat => Handled::Stored,
            Arrival::Full => {
                warn!(
                    count = MAX_KEPT_PAYLOADS,
                    "payloads unacknowledged; left on the relay"
                );
                Handled::Later
            }
        })
    }
}
