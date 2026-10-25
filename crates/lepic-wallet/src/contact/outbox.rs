//! The outbox of sealed messages that must reach a contact's mailbox on the home relay (RFC 0002
//! 12.4): payments of invoices, answers to withdrawals, notices. It lives in the store, so a
//! killed app loses nothing, and retries at once, then after 30 s, 2 min, 10 min and every
//! 30 min, and on every collecting cycle.

use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::{ContactCard, armor};
use lepic_epicbox::EpicboxAddress;
use lepic_node::NodeApi;
use lepic_slate::model::SlateId;
use lepic_store::{
    ContactId, ContactOutboxEntry, ContactOutboxId, ContactOutboxState, SlateStage, StoreError,
    TxDirection, TxState, WalletStore,
};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::keys::{box_identity, contact_keys, contact_network};
use super::relay::{check_online, endpoint_for, mailbox_client};
use super::{ContactError, ContactRelays};
use crate::event::{Event, OutboxNews};
use crate::inbox::ErrorChain;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// Waits before the next try, one step per failed try; the last repeats.
const RETRY: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_secs(2 * 60),
    Duration::from_secs(10 * 60),
    Duration::from_secs(30 * 60),
];

/// An entry undelivered this long is stuck (RFC 0002 12.4).
pub const OUTBOX_STUCK_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// A delivered entry is kept this long, as long as the relay keeps its message, unless its
/// transaction ended sooner.
const DELIVERED_KEPT: Duration = lepic_epicbox::RELAY_RETENTION;

/// A payment delivered this long ago and not posted yet is shown so (RFC 0002 12.4).
pub const NOT_POSTED_AFTER: Duration = Duration::from_secs(2 * 60 * 60);

/// An outbox entry as the host shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxView {
    pub id: ContactOutboxId,
    pub contact_id: ContactId,
    pub slate_id: SlateId,
    pub stage: SlateStage,
    pub state: ContactOutboxState,
    pub attempts: u32,
    pub created_at: Timestamp,
    pub delivered_at: Option<Timestamp>,
    /// Delivered more than [`NOT_POSTED_AFTER`] ago while the payment still waits for the
    /// contact: "X has not posted yet", with "Send again".
    pub not_posted_yet: bool,
}

/// What one outbox run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboxReport {
    pub delivered: usize,
    pub failed: usize,
    pub stuck: usize,
}

fn retry_after(attempts: u32) -> Duration {
    let step = usize::try_from(attempts.saturating_sub(1)).unwrap_or(usize::MAX);
    RETRY
        .get(step)
        .or(RETRY.last())
        .copied()
        .unwrap_or_default()
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Queues `envelope` for the contact's mailbox, due at once.
    pub(crate) async fn enqueue_for_contact(
        &self,
        contact_id: ContactId,
        slate_id: Uuid,
        stage: SlateStage,
        envelope: &[u8],
    ) -> Result<ContactOutboxId, ContactError> {
        let session = self.session()?;
        let payload = armor(envelope);
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                let mailbox = repos
                    .contact_mailbox(contact_id)?
                    .ok_or(ContactError::UnknownContact)?;
                Ok(repos.enqueue_contact_outbox(&ContactOutboxEntry {
                    contact_id,
                    slate_id,
                    stage,
                    payload,
                    destination: mailbox.peer_mailbox,
                    attempts: 0,
                    next_try_at: now,
                    state: ContactOutboxState::Queued,
                    created_at: now,
                    delivered_at: None,
                })?)
            })
        })
        .await
    }

    /// Posts every outbox entry that is due to its contact's mailbox, from our mailbox key for
    /// that contact, and raises [`Event::OutboxDelivered`] for each that reached the relay.
    /// An entry undelivered for [`OUTBOX_STUCK_AFTER`] stops retrying and raises
    /// [`Event::OutboxStuck`].
    ///
    /// Fails with [`ContactError::Offline`] or [`ContactError::EpicboxOff`] before connecting,
    /// and as the store does; a relay that fails is counted, not returned.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contacts_outbox_deliver(
        &self,
        relays: &ContactRelays,
    ) -> Result<OutboxReport, ContactError> {
        check_online(relays)?;
        let _turn = self.contact_turn().await;
        self.deliver_outbox(relays, false).await
    }

    /// The outbox run of [`Wallet::contacts_outbox_deliver`], for a caller that holds the
    /// contact engine's turn. `all` tries every queued entry at once, due or not.
    pub(crate) async fn deliver_outbox(
        &self,
        relays: &ContactRelays,
        all: bool,
    ) -> Result<OutboxReport, ContactError> {
        check_online(relays)?;
        let session = self.session()?;
        let due = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |ports, _| {
                let now = ports.clock.now();
                // Every queued entry waits at most the longest retry step past now.
                let until = if all {
                    now.checked_add(OUTBOX_STUCK_AFTER).unwrap_or(now)
                } else {
                    now
                };
                Ok(session
                    .store
                    .read(|repos| repos.due_contact_outbox(until))?)
            })
            .await?
        };
        let mut report = OutboxReport::default();
        for stored in due {
            let delivered = self.post_outbox_entry(relays, &stored.entry).await;
            let id = stored.id;
            let mut entry = stored.entry;
            let now = self.ports().clock.now();
            entry.attempts = entry.attempts.saturating_add(1);
            let news = match &delivered {
                Ok(()) => {
                    entry.state = ContactOutboxState::Delivered;
                    entry.delivered_at = Some(now);
                    report.delivered = report.delivered.saturating_add(1);
                    Some(Event::OutboxDelivered(OutboxNews {
                        contact_id: entry.contact_id,
                        slate_id: SlateId::from_bytes(entry.slate_id.into_bytes()),
                    }))
                }
                Err(error) => {
                    warn!(error = %ErrorChain(error), attempt = entry.attempts, "outbox entry not delivered");
                    report.failed = report.failed.saturating_add(1);
                    let stuck = entry
                        .created_at
                        .checked_add(OUTBOX_STUCK_AFTER)
                        .is_ok_and(|end| end <= now);
                    if stuck {
                        entry.state = ContactOutboxState::Stuck;
                        report.stuck = report.stuck.saturating_add(1);
                        Some(Event::OutboxStuck(OutboxNews {
                            contact_id: entry.contact_id,
                            slate_id: SlateId::from_bytes(entry.slate_id.into_bytes()),
                        }))
                    } else {
                        entry.next_try_at =
                            now.checked_add(retry_after(entry.attempts)).unwrap_or(now);
                        None
                    }
                }
            };
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |_, _| {
                Ok(session
                    .store
                    .write(|repos| repos.update_contact_outbox(id, &entry))?)
            })
            .await?;
            if let Some(news) = news {
                self.emit(news);
            }
        }
        if report != OutboxReport::default() {
            debug!(count = report.delivered, "contact outbox run");
        }
        Ok(report)
    }

    /// Deletes outbox entries nothing waits for any more: delivered ones older than the relay
    /// keeps messages, and any whose transaction confirmed, was cancelled or expired.
    pub(crate) async fn prune_outbox(&self) -> Result<(), ContactError> {
        let session = self.session()?;
        let pruned = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let mut pruned = 0usize;
                    for record in repos.contacts()? {
                        for stored in repos.contact_outbox(record.contact_id)? {
                            let entry = &stored.entry;
                            let old = entry.state == ContactOutboxState::Delivered
                                && entry
                                    .delivered_at
                                    .and_then(|at| at.checked_add(DELIVERED_KEPT).ok())
                                    .is_some_and(|end| end <= now);
                            let mut ended = false;
                            for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                                if let Some(tx) =
                                    repos.transaction_by_slate(entry.slate_id, direction)?
                                {
                                    ended |= matches!(
                                        tx.entry.state,
                                        TxState::Confirmed | TxState::Cancelled | TxState::Expired
                                    );
                                }
                            }
                            if old || ended {
                                repos.delete_contact_outbox(stored.id)?;
                                pruned = pruned.saturating_add(1);
                            }
                        }
                    }
                    Ok::<_, StoreError>(pruned)
                })?)
            })
            .await?;
        if pruned > 0 {
            debug!(count = pruned, "contact outbox pruned");
        }
        Ok(())
    }

    /// Posts an outbox entry again, whatever its state: "Send again" for a payment the contact
    /// has not posted, or a stuck one. The contact treats a repeated slate id as a duplicate.
    ///
    /// Fails with [`ContactError::UnknownTransaction`] for an id the outbox does not hold, or
    /// whose transaction no longer waits for the contact (finalized, posted, confirmed,
    /// cancelled or expired), with
    /// [`ContactError::Offline`] or [`ContactError::EpicboxOff`], and with
    /// [`ContactError::Relay`] when the relay fails.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contact_outbox_resend(
        &self,
        relays: &ContactRelays,
        id: ContactOutboxId,
    ) -> Result<(), ContactError> {
        check_online(relays)?;
        let _turn = self.contact_turn().await;
        let session = self.session()?;
        let stored = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    let Some(stored) = repos.contact_outbox_entry(id)? else {
                        return Ok::<_, StoreError>(None);
                    };
                    // A slate goes again only while its transaction still waits for the
                    // contact; entries of no transaction, such as contact updates, always may.
                    for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
                        if let Some(tx) =
                            repos.transaction_by_slate(stored.entry.slate_id, direction)?
                            && !matches!(tx.entry.state, TxState::Sent | TxState::Received)
                        {
                            return Ok(None);
                        }
                    }
                    Ok(Some(stored))
                })?)
            })
            .await?
            .ok_or(ContactError::UnknownTransaction)?
        };
        self.post_outbox_entry(relays, &stored.entry).await?;
        let mut entry = stored.entry;
        let now = self.ports().clock.now();
        entry.attempts = entry.attempts.saturating_add(1);
        entry.state = ContactOutboxState::Delivered;
        entry.delivered_at = Some(now);
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .write(|repos| repos.update_contact_outbox(id, &entry))?)
        })
        .await?;
        info!("outbox entry sent again");
        Ok(())
    }

    /// The contact's outbox entries, by id.
    pub async fn contact_outbox(
        &self,
        contact_id: ContactId,
    ) -> Result<Vec<OutboxView>, ContactError> {
        let session = self.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.read(|repos| {
                let mut views = Vec::new();
                for stored in repos.contact_outbox(contact_id)? {
                    let entry = &stored.entry;
                    let waiting = matches!(
                        repos.transaction_by_slate(entry.slate_id, TxDirection::Outgoing)?,
                        Some(tx) if tx.entry.state == TxState::Sent
                    );
                    let late = entry
                        .delivered_at
                        .and_then(|at| at.checked_add(NOT_POSTED_AFTER).ok())
                        .is_some_and(|end| end <= now);
                    views.push(OutboxView {
                        id: stored.id,
                        contact_id: entry.contact_id,
                        slate_id: SlateId::from_bytes(entry.slate_id.into_bytes()),
                        stage: entry.stage,
                        state: entry.state,
                        attempts: entry.attempts,
                        created_at: entry.created_at,
                        delivered_at: entry.delivered_at,
                        not_posted_yet: entry.state == ContactOutboxState::Delivered
                            && late
                            && waiting,
                    });
                }
                Ok::<_, StoreError>(views)
            })?)
        })
        .await
    }

    async fn post_outbox_entry(
        &self,
        relays: &ContactRelays,
        entry: &ContactOutboxEntry,
    ) -> Result<(), ContactError> {
        let network = self.config().network;
        let session = self.session()?;
        let contact_id = entry.contact_id;
        let (record, mailbox) = self
            .contact_work(move |_, _| {
                session.store.read(|repos| {
                    let record = repos
                        .contact(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    let mailbox = repos
                        .contact_mailbox(contact_id)?
                        .ok_or(ContactError::UnknownContact)?;
                    Ok((record, mailbox))
                })
            })
            .await?;
        let session = self.session()?;
        let keys = contact_keys(
            &session.keychain,
            network,
            record.account,
            record.slot,
            record.box_salt,
        )?;
        let home = endpoint_for(&mailbox.home_relay, relays)?;
        let from = box_identity(&keys, network, &home)?;
        let to = EpicboxAddress::parse(&entry.destination, relays.epicbox.network())
            .map_err(|_| ContactError::RelayAddress)?;
        let onion = record
            .peer
            .as_ref()
            .and_then(|peer| ContactCard::decode(&peer.bytes, contact_network(network)).ok())
            .and_then(|card| {
                card.fields()
                    .home_onion
                    .as_ref()
                    .map(|onion| onion.as_str().to_owned())
            });
        let endpoint = super::relay::endpoint_of_address(&to, relays)?;
        mailbox_client(relays, endpoint, onion.as_deref())
            .post(&from, &to, &entry.payload)
            .await
            .map_err(ContactError::Relay)
    }
}
