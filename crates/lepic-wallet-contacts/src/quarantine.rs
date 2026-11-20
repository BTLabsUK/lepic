// SPDX-License-Identifier: Apache-2.0
//! Local quarantine: contact messages that opened under the contact's key and could not be taken
//! stay here, as settings rows, instead of being acknowledged and dropped (ADR 0049). The host
//! decides whether they are kept ([`lepic_wallet::config::WalletPolicy::quarantine_max_bytes`]),
//! when to retry them and when to discard them; LEPIC never retries on its own.

use crate::hex;
use jiff::Timestamp;
use lepic_epicbox::Handled;
use lepic_node::NodeApi;
use lepic_store::{ContactId, Repositories, StoreError, WalletStore};
use lepic_wallet::ports::{SecretVault, StoreOpener};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument, warn};

use super::collect::Told;
use super::{ContactError, ContactRelays};
use crate::ContactBook;
use lepic_primitives::error_chain::ErrorChain;

/// One row per entry without its envelope, so listing and counting never load the bodies.
const ENTRY_PREFIX: &str = "contact.quarantine.entry.";
const BODY_PREFIX: &str = "contact.quarantine.body.";

/// Why a message is in quarantine. The names are stored and shown to hosts; they never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// Taking it kept failing until the hold bound.
    HoldBound,
    /// A slate that does not decode, or of a stage no contact sends.
    UndecodableSlate,
    /// A notice of a kind this build does not know.
    UnknownNotice,
    /// A payment over the open receipt caps.
    ReceiptCap,
    /// A payment the wallet refused to receive.
    ReceiveRefused,
}

impl QuarantineReason {
    /// The stable name of the reason.
    pub const fn name(self) -> &'static str {
        match self {
            Self::HoldBound => "hold_bound",
            Self::UndecodableSlate => "undecodable_slate",
            Self::UnknownNotice => "unknown_notice",
            Self::ReceiptCap => "receipt_cap",
            Self::ReceiveRefused => "receive_refused",
        }
    }
}

/// A message kept in quarantine, without its envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedMessage {
    /// The envelope's hash as 64 hex characters: what retry and discard take.
    pub id: String,
    pub contact_id: ContactId,
    pub reason: QuarantineReason,
    pub first_seen: Timestamp,
    /// Times a retry did not clear it.
    pub attempts: u32,
    /// The envelope's size in bytes.
    pub size: u64,
}

/// What one retry did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuarantineRetry {
    pub retried: usize,
    /// Entries handled and gone.
    pub cleared: usize,
    /// Entries still in quarantine.
    pub kept: usize,
}

/// An entry's row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Entry {
    contact: String,
    reason: QuarantineReason,
    first_seen: i64,
    attempts: u32,
    /// Whether it came through the contact's current mailbox and not one being retired.
    current: bool,
    size: u64,
}

impl Entry {
    fn contact_id(&self) -> Option<ContactId> {
        hex::decode_array(&self.contact).ok().map(ContactId)
    }
}

/// What [`keep`] did with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Kept {
    /// Whether the message is in quarantine now.
    pub(crate) kept: bool,
    /// Messages lost to make this one fit, the message itself when it never fits.
    pub(crate) dropped: usize,
}

/// One message to keep.
pub(crate) struct Message<'a> {
    pub(crate) hash: [u8; 32],
    pub(crate) envelope: &'a [u8],
    pub(crate) contact_id: ContactId,
    pub(crate) current: bool,
    pub(crate) reason: QuarantineReason,
}

fn entry_key(id: &str) -> String {
    format!("{ENTRY_PREFIX}{id}")
}

fn body_key(id: &str) -> String {
    format!("{BODY_PREFIX}{id}")
}

/// Every readable entry with its id, oldest first.
fn entries(repos: &dyn Repositories) -> Result<Vec<(String, Entry)>, StoreError> {
    let mut entries: Vec<(String, Entry)> = repos
        .settings_with_prefix(ENTRY_PREFIX)?
        .into_iter()
        .filter_map(|(key, value)| {
            let id = key.strip_prefix(ENTRY_PREFIX)?.to_owned();
            Some((id, serde_json::from_str(&value).ok()?))
        })
        .collect();
    entries.sort_by(|(left_id, left), (right_id, right)| {
        (left.first_seen, left_id).cmp(&(right.first_seen, right_id))
    });
    Ok(entries)
}

/// An entry, and its envelope when the body row is readable.
type Stored = (Entry, Option<Vec<u8>>);

/// The entry `id`.
fn entry(repos: &dyn Repositories, id: &str) -> Result<Option<Stored>, StoreError> {
    let Some(entry) = repos
        .setting(&entry_key(id))?
        .and_then(|text| serde_json::from_str::<Entry>(&text).ok())
    else {
        return Ok(None);
    };
    let body = repos
        .setting(&body_key(id))?
        .and_then(|text| hex::unhex(&text));
    Ok(Some((entry, body)))
}

/// Forgets the entry `id`; returns whether there was one.
fn delete(repos: &mut dyn Repositories, id: &str) -> Result<bool, StoreError> {
    let had = repos.setting(&entry_key(id))?.is_some();
    repos.delete_setting(&entry_key(id))?;
    repos.delete_setting(&body_key(id))?;
    Ok(had)
}

/// Writes one more attempt on `entry`.
fn count_attempt(repos: &mut dyn Repositories, id: &str, entry: &Entry) -> Result<(), StoreError> {
    let mut entry = entry.clone();
    entry.attempts = entry.attempts.saturating_add(1);
    put_entry(repos, id, &entry)
}

fn put_entry(repos: &mut dyn Repositories, id: &str, entry: &Entry) -> Result<(), StoreError> {
    let text = serde_json::to_string(entry).map_err(|_| StoreError::Corrupt {
        record: lepic_store::Record::Contact,
        field: "quarantine entry",
    })?;
    repos.put_setting(&entry_key(id), &text)
}

/// Keeps `message` within `cap` bytes over the wallet. Over the cap the oldest entry of the same
/// contact goes first, then the wallet's oldest, so a contact that fills the quarantine loses its
/// own first. A message larger than `cap` is not kept. A message kept already stays as it is.
pub(crate) fn keep(
    repos: &mut dyn Repositories,
    cap: u64,
    message: &Message<'_>,
    now: Timestamp,
) -> Result<Kept, StoreError> {
    let size = u64::try_from(message.envelope.len()).unwrap_or(u64::MAX);
    if size > cap {
        return Ok(Kept {
            kept: false,
            dropped: 1,
        });
    }
    let id = hex::encode(&message.hash);
    if repos.setting(&entry_key(&id))?.is_some() {
        return Ok(Kept {
            kept: true,
            dropped: 0,
        });
    }
    let mut held = entries(repos)?;
    let mut total = held
        .iter()
        .fold(0_u64, |total, (_, entry)| total.saturating_add(entry.size));
    let contact = hex::encode(&message.contact_id.0);
    let mut dropped = 0_usize;
    while total.saturating_add(size) > cap {
        let Some(position) = held
            .iter()
            .position(|(_, entry)| entry.contact == contact)
            .or((!held.is_empty()).then_some(0))
        else {
            break;
        };
        let (old_id, old) = held.remove(position);
        delete(repos, &old_id)?;
        total = total.saturating_sub(old.size);
        dropped = dropped.saturating_add(1);
    }
    repos.put_setting(&body_key(&id), &hex::encode(message.envelope))?;
    put_entry(
        repos,
        &id,
        &Entry {
            contact,
            reason: message.reason,
            first_seen: now.as_second(),
            attempts: 0,
            current: message.current,
            size,
        },
    )?;
    Ok(Kept {
        kept: true,
        dropped,
    })
}

/// The kept messages, oldest first.
fn list(repos: &dyn Repositories) -> Result<Vec<QuarantinedMessage>, StoreError> {
    Ok(entries(repos)?
        .into_iter()
        .filter_map(|(id, entry)| {
            Some(QuarantinedMessage {
                contact_id: entry.contact_id()?,
                reason: entry.reason,
                first_seen: Timestamp::from_second(entry.first_seen).ok()?,
                attempts: entry.attempts,
                size: entry.size,
                id,
            })
        })
        .collect())
}

/// Forgets every entry of the contact, which is being removed.
pub(crate) fn delete_contact_entries(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
) -> Result<(), StoreError> {
    let contact = hex::encode(&contact_id.0);
    for (id, entry) in entries(repos)? {
        if entry.contact == contact {
            delete(repos, &id)?;
        }
    }
    Ok(())
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// The messages kept in quarantine, oldest first, never their envelopes. Works whatever
    /// [`lepic_wallet::WalletPolicy::quarantine_max_bytes`] is now.
    pub async fn contact_quarantine(&self) -> Result<Vec<QuarantinedMessage>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| Ok(session.store.read(|repos| list(repos))?))
            .await
    }

    /// Runs the normal handling again on the message `id`, or on every kept message for `None`,
    /// oldest first. A message handled leaves quarantine; any other gets one more attempt
    /// counted and stays. Runs only when called: LEPIC never retries on its own. An id not kept
    /// retries nothing.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_quarantine_retry(
        &self,
        relays: &ContactRelays,
        id: Option<&str>,
    ) -> Result<QuarantineRetry, ContactError> {
        self.check_contact_network(relays)?;
        let _turn = self.wallet.contact_turn().await;
        let ids: Vec<String> = match id {
            Some(id) => vec![id.to_owned()],
            None => {
                let session = self.wallet.session()?;
                self.contact_work(move |_, _| {
                    Ok(session.store.read(|repos| {
                        Ok::<_, StoreError>(entries(repos)?.into_iter().map(|(id, _)| id).collect())
                    })?)
                })
                .await?
            }
        };
        let mut retry = QuarantineRetry::default();
        for id in ids {
            let session = self.wallet.session()?;
            let read = {
                let session = std::sync::Arc::clone(&session);
                let id = id.clone();
                self.contact_work(move |_, _| Ok(session.store.read(|repos| entry(repos, &id))?))
                    .await?
            };
            let Some((kept, envelope)) = read else {
                continue;
            };
            retry.retried = retry.retried.saturating_add(1);
            let cleared = match (kept.contact_id(), envelope) {
                (Some(contact_id), Some(envelope)) => {
                    self.retry_message(relays, contact_id, &envelope).await
                }
                _ => false,
            };
            self.contact_work(move |_, _| {
                Ok(session.store.write(|repos| {
                    if cleared {
                        delete(repos, &id).map(|_| ())
                    } else {
                        count_attempt(repos, &id, &kept)
                    }
                })?)
            })
            .await?;
            if cleared {
                retry.cleared = retry.cleared.saturating_add(1);
            } else {
                retry.kept = retry.kept.saturating_add(1);
            }
        }
        info!(
            count = retry.retried,
            cleared = retry.cleared,
            "quarantined messages retried"
        );
        Ok(retry)
    }

    /// Whether the normal handling took the envelope: it opened, and it ended stored with no
    /// reason to keep it. A message that did not open is not one that was handled. It is never
    /// taken as news that the contact uses its current mailbox, which only a fresh message says.
    async fn retry_message(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        envelope: &[u8],
    ) -> bool {
        let mut told = Told::default();
        match self
            .take_contact_message(relays, contact_id, false, envelope, &mut told)
            .await
        {
            Ok(Handled::Stored) => told.opened && told.dropped.is_none(),
            Ok(Handled::Later) => false,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "quarantined message failed again");
                false
            }
        }
    }

    /// Forgets the kept message `id`. Returns whether there was one.
    pub async fn contact_quarantine_discard(&self, id: &str) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        let id = id.to_owned();
        self.contact_work(move |_, _| Ok(session.store.write(|repos| delete(repos, &id))?))
            .await
    }

    /// Puts an envelope that could not be taken in quarantine, with `remember` and the clearing
    /// of its hold count in one store transaction, ahead of the acknowledgement.
    pub(crate) async fn quarantine_message(
        &self,
        cap: u64,
        message: Message<'_>,
    ) -> Result<Kept, ContactError> {
        let session = self.wallet.session()?;
        let hash = message.hash;
        let held = super::collect::held_key(hash);
        let envelope = message.envelope.to_vec();
        let (contact_id, current, reason) = (message.contact_id, message.current, message.reason);
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.write(|repos| {
                let kept = keep(
                    repos,
                    cap,
                    &Message {
                        hash,
                        envelope: &envelope,
                        contact_id,
                        current,
                        reason,
                    },
                    now,
                )?;
                repos.remember_envelope(&hash, now)?;
                repos.delete_setting(&held)?;
                Ok::<_, StoreError>(kept)
            })?)
        })
        .await
    }
}
