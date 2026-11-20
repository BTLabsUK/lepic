// SPDX-License-Identifier: Apache-2.0
//! Where a pairing stands after it was stored, and the status notices that tell the contact.
//!
//! A record's state stays one of the stored codes; Waiting and Ended are derived from its facts.
//! The inviter waits until it hears the contact in the pairing; a contact that claims the
//! status notices says it finished with `pair-finished`, and each side's words verdict travels
//! as `pair-match` or `pair-mismatch` carrying a hash of the SAS, so a verdict counts only for
//! the pairing whose words it judged. Status notices go only through the pairing's mailbox,
//! sealed and signed like every contact message, and only to a contact that claimed them
//! (feature bit 3). They are outbox rows to the contact's mailbox key on every usable relay,
//! retried by the outbox's back-off until a relay takes them or they are a day old, and then
//! dropped without a word. An inviter that never hears the contact during seven days of
//! collecting ends the pairing.

use std::time::Duration;

use blake2::Blake2b256;
use blake2::digest::Digest;
use jiff::Timestamp;
use lepic_node::NodeApi;
use lepic_store::{
    ContactId, ContactRecord, ContactState, NativeOutboxId, PairingEndReason, Repositories,
    StoreError, VERDICT_LEN, WalletStore,
};
use tracing::{debug, info, warn};

use super::notice_out::{NoticeTo, send_notice};
use super::{ContactError, LockedRng};
use crate::ContactBook;
use lepic_primitives::error_chain::ErrorChain;
use lepic_wallet::event::{ContactChange, ContactUpdate, Event};
use lepic_wallet::notice::Notice;
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// The feature bit of a contact that sends and reads the pairing status notices, and makes
/// its inviter wait until it is heard.
pub const STATUS_NOTICES: u32 = lepic_transport::features::STATUS_NOTICES;

/// Collecting time after which an inviter that never heard the contact ends the pairing.
pub const NEVER_FINISHED_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The most one gap between two collects adds to that collecting time. A wallet that collects
/// in the foreground, or wakes in the background every quarter of an hour or so, counts its
/// gaps in full; time the app was closed counts for at most this.
pub const HEARD_WAIT_MAX_GAP: Duration = Duration::from_secs(60 * 60);

const VERDICT_DOMAIN: &[u8] = b"lepic-wallet pairing verdict v1";

/// Where a pairing stands, derived from its record; never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStatus {
    /// Stored, but the contact's wallet has not been heard in this pairing yet.
    Waiting,
    Paired,
    Verified,
    KeysChanged,
    Ended,
}

/// How the record stands, first match winning: ended, keys changed, unheard, then its state.
pub fn status_of(record: &ContactRecord) -> PairingStatus {
    if record.facts.ended_reason.is_some() {
        return PairingStatus::Ended;
    }
    match record.state {
        ContactState::KeysChanged => PairingStatus::KeysChanged,
        _ if record.facts.peer_heard_at.is_none() => PairingStatus::Waiting,
        ContactState::Verified => PairingStatus::Verified,
        _ => PairingStatus::Paired,
    }
}

/// Refuses a send, a seal, an invoice or a check through a pairing that ended or still waits.
pub(crate) fn require_live(record: &ContactRecord) -> Result<(), ContactError> {
    match status_of(record) {
        PairingStatus::Ended => Err(ContactError::Ended),
        PairingStatus::Waiting => Err(ContactError::Waiting),
        _ => Ok(()),
    }
}

/// Whether the contact claimed the status notices in this pairing.
pub(crate) fn sends_status(record: &ContactRecord) -> bool {
    record.facts.peer_features & STATUS_NOTICES != 0 && !super::private::is_private(record)
}

/// The hash of a SAS a verdict carries.
pub(crate) fn verdict_hash(sas: &[u8; lepic_store::SAS_LEN]) -> [u8; VERDICT_LEN] {
    let mut hash = Blake2b256::new();
    hash.update(VERDICT_DOMAIN);
    hash.update(sas);
    hash.finalize().into()
}

/// Sends the pairing notice `notice` to the contact of `record` by [`send_notice`], in the
/// caller's write, and returns the row. Nothing is queued for a pairing with no peer card or
/// mailbox.
pub(crate) fn queue_status(
    repos: &mut dyn Repositories,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    rng: &lepic_wallet::SharedRng,
    record: &ContactRecord,
    notice: &Notice,
    now: Timestamp,
) -> Result<Option<NativeOutboxId>, ContactError> {
    let mut guard = rng.lock();
    let mut rng = LockedRng(&mut **guard);
    let to = NoticeTo::Contact { record, keychain };
    let id = send_notice(repos, (network, &mut rng), notice, to, now)?;
    if id.is_some() {
        debug!(kind = notice.kind(), "pairing status queued");
    }
    Ok(id)
}

/// Records that the contact of `contact_id` was heard now, once; returns whether this was the
/// first time. An ended pairing hears nothing.
pub(crate) fn mark_heard(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    now: Timestamp,
) -> Result<bool, StoreError> {
    let Some(mut record) = repos.contact(contact_id)? else {
        return Ok(false);
    };
    if !heard_now(&mut record, now) {
        return Ok(false);
    }
    repos.put_contact(&record)?;
    Ok(true)
}

/// Sets the record heard at `now` unless it was heard or ended; returns whether it changed.
pub(crate) fn heard_now(record: &mut ContactRecord, now: Timestamp) -> bool {
    if record.facts.peer_heard_at.is_some() || record.facts.ended_reason.is_some() {
        return false;
    }
    record.facts.peer_heard_at = Some(now);
    record.facts.heard_wait = Duration::ZERO;
    record.facts.heard_wait_mark = None;
    true
}

/// Ends the record for `reason` at `now`, unless it ended already; returns whether it changed.
pub(crate) fn end_record(
    record: &mut ContactRecord,
    reason: PairingEndReason,
    now: Timestamp,
) -> bool {
    if record.facts.ended_reason.is_some() {
        return false;
    }
    record.facts.ended_reason = Some(reason);
    record.facts.ended_at = Some(now);
    record.allow_invoices = false;
    record.updated_at = now;
    true
}

impl<N, S, V> ContactBook<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes a status notice the contact of `contact_id` sent in its pairing. Ended is final:
    /// a notice for an ended pairing changes nothing.
    pub(crate) async fn take_status(
        &self,
        contact_id: ContactId,
        notice: Notice,
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let changes = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let mut changes = Vec::new();
                    let Some(mut record) = repos.contact(contact_id)? else {
                        return Ok::<_, StoreError>(changes);
                    };
                    if record.facts.ended_reason.is_some() {
                        return Ok(changes);
                    }
                    match notice {
                        Notice::PairFinished => {}
                        Notice::PairMatch { sas: hash } => {
                            let ours = record.sas.as_ref().map(verdict_hash);
                            if ours == Some(hash) && record.facts.peer_verdict != Some(hash) {
                                record.facts.peer_verdict = Some(hash);
                                record.facts.peer_verified_at = Some(now);
                                changes.push(ContactUpdate::of(
                                    contact_id,
                                    ContactChange::PeerVerified,
                                ));
                            }
                        }
                        Notice::PairMismatch { sas: hash } => {
                            let ours = record.sas.as_ref().map(verdict_hash);
                            if ours == Some(hash) {
                                super::invoices::drop_contact_invoices(repos, contact_id)?;
                                end_record(&mut record, PairingEndReason::PeerMismatch, now);
                                changes.push(ContactUpdate {
                                    ended_reason: Some(PairingEndReason::PeerMismatch),
                                    ..ContactUpdate::of(contact_id, ContactChange::Ended)
                                });
                            }
                        }
                        _ => return Ok(changes),
                    }
                    repos.put_contact(&record)?;
                    Ok(changes)
                })?)
            })
            .await?;
        for change in changes {
            info!("pairing status from the contact taken");
            self.wallet.emit(Event::ContactUpdated(change));
        }
        Ok(())
    }

    /// Records that the contact of `contact_id` was heard, and tells the host the first time.
    pub(crate) async fn heard(&self, contact_id: ContactId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let first = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session
                    .store
                    .write(|repos| mark_heard(repos, contact_id, now))?)
            })
            .await?;
        if first {
            info!("contact heard in its pairing");
            self.wallet.emit(Event::ContactUpdated(ContactUpdate::of(
                contact_id,
                ContactChange::Heard,
            )));
        }
        Ok(())
    }

    /// Counts collecting time for the unheard pairings among `contacts`, whose home relay a
    /// read that started at `started` just reached, and ends those that waited
    /// [`NEVER_FINISHED_AFTER`], each with an unpaired notice to the contact.
    pub(crate) async fn count_heard_wait(
        &self,
        contacts: Vec<ContactId>,
        started: Timestamp,
    ) -> Result<Vec<super::EndedPairing>, ContactError> {
        if contacts.is_empty() {
            return Ok(Vec::new());
        }
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let ended = self
            .contact_work(move |ports, _| {
                session.store.write(|repos| {
                    let mut ended = Vec::new();
                    for contact_id in contacts {
                        let Some(mut record) = repos.contact(contact_id)? else {
                            continue;
                        };
                        if record.peer.is_none()
                            || record.facts.peer_heard_at.is_some()
                            || record.facts.ended_reason.is_some()
                        {
                            continue;
                        }
                        let facts = &mut record.facts;
                        if let Some(mark) = facts.heard_wait_mark {
                            let since = started.duration_since(mark);
                            if let Ok(since) = Duration::try_from(since) {
                                facts.heard_wait = facts
                                    .heard_wait
                                    .saturating_add(since.min(HEARD_WAIT_MAX_GAP));
                            }
                        }
                        facts.heard_wait_mark = Some(started);
                        let finished = facts.heard_wait >= NEVER_FINISHED_AFTER;
                        if finished {
                            end_record(&mut record, PairingEndReason::NeverFinished, started);
                            super::invoices::drop_contact_invoices(repos, contact_id)?;
                            queue_status(
                                repos,
                                &session.keychain,
                                network,
                                &ports.rng,
                                &record,
                                &Notice::Unpaired,
                                started,
                            )?;
                            ended.push(super::EndedPairing {
                                contact_id,
                                reason: PairingEndReason::NeverFinished,
                            });
                        }
                        repos.put_contact(&record)?;
                    }
                    Ok::<_, ContactError>(ended)
                })
            })
            .await?;
        for end in &ended {
            info!("pairing never finished by the contact ended");
            self.wallet.emit(Event::ContactUpdated(ContactUpdate {
                ended_reason: Some(end.reason),
                ..ContactUpdate::of(end.contact_id, ContactChange::Ended)
            }));
        }
        Ok(ended)
    }
}

/// Logs a status notice that could not be queued; the pairing goes on without it.
pub(crate) fn queue_failed(error: &ContactError) {
    warn!(error = %ErrorChain(error), "pairing status not queued");
}

#[cfg(test)]
mod tests {
    // Tests may unwrap and do plain arithmetic (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;

    /// `testdata/vectors/keys/pairing_verdicts.json`, written by the conformance generator with
    /// `blake2-rfc`: the hash a verdict carries for each SAS.
    #[test]
    fn verdict_hashes_match_the_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/keys/pairing_verdicts.json"
        ))
        .unwrap();
        let unhex = |text: &str| -> Vec<u8> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect()
        };
        assert_eq!(
            vector["inputs"]["domain"].as_str().unwrap().as_bytes(),
            VERDICT_DOMAIN
        );
        let sas = vector["inputs"]["sas"].as_array().unwrap();
        let hashes = vector["expected"]["hashes"].as_array().unwrap();
        assert_eq!(sas.len(), hashes.len());
        for (sas, hash) in sas.iter().zip(hashes) {
            let sas: [u8; 4] = unhex(sas.as_str().unwrap()).try_into().unwrap();
            assert_eq!(verdict_hash(&sas).to_vec(), unhex(hash.as_str().unwrap()));
        }
    }

    #[test]
    fn verdict_hashes_tell_two_sas_apart() {
        assert_ne!(verdict_hash(&[1, 2, 3, 4]), verdict_hash(&[1, 2, 3, 5]));
    }
}
