// SPDX-License-Identifier: Apache-2.0
//! Where a pairing stands after it was stored, and the status notices that tell the contact.
//!
//! A record's state stays one of the stored codes; Waiting and Ended are derived from its facts.
//! The inviter waits until it hears the contact in the pairing; a contact that claims the
//! status notices says it finished with `pair-finished`, and each side's words verdict travels
//! as `pair-match` or `pair-mismatch` carrying a hash of the SAS, so a verdict counts only for
//! the pairing whose words it judged. Status notices go only through the pairing's mailbox,
//! sealed and signed like every contact message, and only to a contact that claimed them
//! (feature bit 3). They are retried for seven days and then dropped without a word. An inviter
//! that never hears the contact during seven days of collecting ends the pairing.

use std::time::Duration;

use blake2::Blake2b256;
use blake2::digest::Digest;
use jiff::Timestamp;
use lepic_contact::{Content, MessageType};
use lepic_node::NodeApi;
use lepic_store::{
    ContactId, ContactRecord, ContactState, PairingEndReason, Repositories, StatusKind,
    StatusNotice, StoreError, StoredStatusNotice, VERDICT_LEN, WalletStore,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{ContactError, ContactRelays, LockedRng};
use crate::ContactBook;
use lepic_primitives::error_chain::ErrorChain;
use lepic_wallet::event::{ContactChange, ContactUpdate, Event};
use lepic_wallet::notice::{NOTICE_VERSION, notice_length, pad_object, unpaired_notice_to};
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// The feature bit of a contact that sends and reads the pairing status notices, and makes
/// its inviter wait until it is heard.
pub const STATUS_NOTICES: u32 = lepic_epicbox::marker::features::STATUS_NOTICES;

/// How long a status notice is retried before it is dropped.
pub const STATUS_RETRY_FOR: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Collecting time after which an inviter that never heard the contact ends the pairing.
pub const NEVER_FINISHED_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The most one gap between two collects adds to that collecting time. A wallet that collects
/// in the foreground, or wakes in the background every quarter of an hour or so, counts its
/// gaps in full; time the app was closed counts for at most this.
pub const HEARD_WAIT_MAX_GAP: Duration = Duration::from_secs(60 * 60);

/// Waits before the next try of a status notice, one step per failed try; the last repeats.
const RETRY: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_secs(2 * 60),
    Duration::from_secs(10 * 60),
    Duration::from_secs(30 * 60),
];

const VERDICT_DOMAIN: &[u8] = b"lepic-wallet pairing verdict v1";

const FINISHED: &str = "pair-finished";
const MATCH: &str = "pair-match";
const MISMATCH: &str = "pair-mismatch";

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

/// A status notice as read from a contact's mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusMessage {
    Finished,
    Match([u8; VERDICT_LEN]),
    Mismatch([u8; VERDICT_LEN]),
}

#[derive(Serialize)]
struct Written<'a> {
    lepic: u64,
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sas: Option<String>,
}

#[derive(Deserialize)]
struct Read {
    lepic: u64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    sas: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex32(text: &str) -> Option<[u8; VERDICT_LEN]> {
    if text.len() != VERDICT_LEN.saturating_mul(2) {
        return None;
    }
    let mut out = [0u8; VERDICT_LEN];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The text of a status notice, padded to `length`.
pub(crate) fn status_text(message: StatusMessage, length: usize) -> String {
    let (kind, sas) = match message {
        StatusMessage::Finished => (FINISHED, None),
        StatusMessage::Match(hash) => (MATCH, Some(hex(&hash))),
        StatusMessage::Mismatch(hash) => (MISMATCH, Some(hex(&hash))),
    };
    let written = Written {
        lepic: NOTICE_VERSION,
        kind,
        sas,
    };
    // A struct of strings and a number always serializes.
    pad_object(&serde_json::to_string(&written).unwrap_or_default(), length)
}

/// Reads a status notice; `None` for anything else.
pub(crate) fn parse_status(text: &str) -> Option<StatusMessage> {
    if text.len() > lepic_wallet::notice::MAX_NOTICE_LEN || !text.trim_start().starts_with('{') {
        return None;
    }
    let read: Read = serde_json::from_str(text).ok()?;
    if read.lepic != NOTICE_VERSION {
        return None;
    }
    let sas = read.sas.as_deref().and_then(unhex32);
    match read.kind.as_str() {
        FINISHED => Some(StatusMessage::Finished),
        MATCH => sas.map(StatusMessage::Match),
        MISMATCH => sas.map(StatusMessage::Mismatch),
        _ => None,
    }
}

fn retry_after(attempts: u32) -> Duration {
    let step = usize::try_from(attempts.saturating_sub(1)).unwrap_or(usize::MAX);
    RETRY
        .get(step)
        .or(RETRY.last())
        .copied()
        .unwrap_or_default()
}

/// What to tell the contact of `record` in a status notice.
pub(crate) enum Tell {
    Status(StatusMessage),
    Unpaired,
}

impl Tell {
    const fn kind(&self) -> StatusKind {
        match self {
            Self::Status(StatusMessage::Finished) => StatusKind::Finished,
            Self::Status(StatusMessage::Match(_)) => StatusKind::Match,
            Self::Status(StatusMessage::Mismatch(_)) => StatusKind::Mismatch,
            Self::Unpaired => StatusKind::Unpaired,
        }
    }
}

/// The payments key this pairing proved, as compat rows are keyed.
pub(crate) fn proven_key(
    record: &ContactRecord,
    network: lepic_primitives::params::Network,
) -> Option<String> {
    let network = lepic_wallet::inbox::relay_network(network);
    let address = record.facts.payments_address.as_deref()?;
    lepic_epicbox::EpicboxAddress::parse_key(address, network)
        .ok()
        .map(|key| lepic_epicbox::EpicboxAddress::key_text_of(&key, network))
}

/// Learns from a pairing that proved the contact's payments key: the address proof works with
/// that key, and the features the pairing claimed are the key's claim.
pub(crate) fn learn_from_pairing(
    repos: &mut dyn Repositories,
    record: &ContactRecord,
    network: lepic_primitives::params::Network,
    now: Timestamp,
) -> Result<(), StoreError> {
    let Some(key) = proven_key(record, network) else {
        return Ok(());
    };
    if record.facts.peer_features != 0 {
        lepic_wallet::peer_compat::record_claim(repos, &key, now, record.facts.peer_features)?;
    }
    lepic_wallet::peer_compat::record_works(
        repos,
        &key,
        lepic_epicbox::marker::features::ADDRESS_PROOF,
        true,
    )
}

/// Seals `tell` for the contact of `record` and queues it in the store's status outbox, due at
/// once. Nothing is queued for a pairing with no peer card or mailbox.
pub(crate) fn queue_status(
    repos: &mut dyn Repositories,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    rng: &lepic_wallet::SharedRng,
    record: &ContactRecord,
    tell: &Tell,
    now: Timestamp,
) -> Result<bool, ContactError> {
    let Some(mailbox) = repos.contact_mailbox(record.contact_id)? else {
        return Ok(false);
    };
    if record.peer.is_none() {
        return Ok(false);
    }
    let class = super::private::class_of(repos, record)?;
    let mut guard = rng.lock();
    let mut rng = LockedRng(&mut **guard);
    let length = notice_length(&mut rng);
    let text = match tell {
        Tell::Status(message) => status_text(*message, length),
        Tell::Unpaired => unpaired_notice_to(length),
    };
    let envelope = super::invoices::seal_to_record(
        keychain,
        network,
        record,
        &class,
        Content::new(MessageType::Notice, text.into_bytes()),
        now,
        &mut rng,
    )?;
    drop(guard);
    repos.enqueue_status_notice(&StatusNotice {
        contact_id: record.contact_id,
        kind: tell.kind(),
        payload: lepic_contact::armor(&envelope),
        destination: mailbox.peer_mailbox,
        attempts: 0,
        next_try_at: now,
        created_at: now,
        expires_at: now.checked_add(STATUS_RETRY_FOR).unwrap_or(now),
        delivered_at: None,
    })?;
    Ok(true)
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

/// Drops what waited to go to the contact through the pairing: its slate outbox entries.
pub(crate) fn drop_contact_outbox(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
) -> Result<(), StoreError> {
    for stored in repos.contact_outbox(contact_id)? {
        repos.delete_contact_outbox(stored.id)?;
    }
    Ok(())
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
        message: StatusMessage,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
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
                    // The status notices work with the key this pairing proved.
                    if let Some(key) = proven_key(&record, network) {
                        lepic_wallet::peer_compat::record_works(repos, &key, STATUS_NOTICES, true)?;
                    }
                    match message {
                        StatusMessage::Finished => {}
                        StatusMessage::Match(hash) => {
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
                        StatusMessage::Mismatch(hash) => {
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
    /// drain that started at `started` just reached, and ends those that waited
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
                                &Tell::Unpaired,
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

    /// Posts every status notice that is due and drops those past their seven days, without
    /// an event either way. Returns how many reached their relay.
    pub(crate) async fn deliver_status(
        &self,
        relays: &ContactRelays,
        all: bool,
    ) -> Result<usize, ContactError> {
        let session = self.wallet.session()?;
        let due = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |ports, _| {
                let now = ports.clock.now();
                let until = if all {
                    now.checked_add(STATUS_RETRY_FOR).unwrap_or(now)
                } else {
                    now
                };
                Ok(session.store.write(|repos| {
                    let mut due = Vec::new();
                    for stored in repos.due_status_notices(until)? {
                        if stored.notice.expires_at <= now {
                            repos.delete_status_notice(stored.id)?;
                        } else {
                            due.push(stored);
                        }
                    }
                    Ok::<_, StoreError>(due)
                })?)
            })
            .await?
        };
        let mut delivered = 0usize;
        for StoredStatusNotice { id, mut notice } in due {
            let posted = self.post_status(relays, &notice).await;
            let now = self.wallet.ports().clock.now();
            notice.attempts = notice.attempts.saturating_add(1);
            match posted {
                Ok(()) => {
                    notice.delivered_at = Some(now);
                    delivered = delivered.saturating_add(1);
                }
                Err(error) => {
                    debug!(error = %ErrorChain(&error), attempt = notice.attempts, "pairing status not delivered");
                    notice.next_try_at =
                        now.checked_add(retry_after(notice.attempts)).unwrap_or(now);
                }
            }
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |_, _| {
                Ok(session.store.write(|repos| {
                    if notice.delivered_at.is_some() {
                        repos.delete_status_notice(id)
                    } else {
                        repos.update_status_notice(id, &notice)
                    }
                })?)
            })
            .await?;
        }
        Ok(delivered)
    }

    /// Posts a status notice from our mailbox of its pairing, or, once the record is removed,
    /// from a mailbox of no pairing: the envelope is signed and the contact checks that, not the
    /// relay's sender.
    async fn post_status(
        &self,
        relays: &ContactRelays,
        notice: &StatusNotice,
    ) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let contact_id = notice.contact_id;
        let found = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |_, _| {
                session.store.read(|repos| {
                    let Some(record) = repos.contact(contact_id)? else {
                        return Ok::<_, ContactError>(None);
                    };
                    let Some(mailbox) = repos.contact_mailbox(contact_id)? else {
                        return Ok(None);
                    };
                    let class = super::private::class_of(repos, &record)?;
                    Ok(Some((record, mailbox, class)))
                })
            })
            .await?
        };
        let to =
            lepic_epicbox::EpicboxAddress::parse(&notice.destination, relays.epicbox.network())
                .map_err(|_| ContactError::RelayAddress)?;
        let endpoint = super::relay::endpoint_of_address(&to, relays)?;
        let (from, onion) = match found {
            Some((record, mailbox, class)) => {
                let keys =
                    super::private::record_keys(&session.keychain, network, &record, &class)?;
                let home = super::relay::endpoint_for(&mailbox.home_relay, relays)?;
                (
                    super::keys::box_identity(&keys, network, &home)?,
                    mailbox.onion,
                )
            }
            None => {
                let seed = super::new_id(&mut LockedRng(&mut **self.wallet.ports().rng.lock()));
                let (_, from) = super::keys::pairing_mailbox(&seed, network, &endpoint)?;
                (from, None)
            }
        };
        super::relay::mailbox_client(relays, endpoint, onion.as_deref())
            .post(&from, &to, &notice.payload)
            .await
            .map_err(ContactError::Relay)
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
    fn status_notices_read_back_and_are_padded() {
        let hash = verdict_hash(&[1, 2, 3, 4]);
        for message in [
            StatusMessage::Finished,
            StatusMessage::Match(hash),
            StatusMessage::Mismatch(hash),
        ] {
            for length in lepic_wallet::notice::NOTICE_LENGTHS {
                let text = status_text(message, length);
                assert_eq!(text.len(), length);
                assert_eq!(parse_status(&text), Some(message));
            }
        }
    }

    #[test]
    fn a_verdict_without_its_hash_or_of_another_version_is_not_one() {
        for text in [
            r#"{"lepic":1,"type":"pair-match"}"#,
            r#"{"lepic":1,"type":"pair-mismatch","sas":"00"}"#,
            r#"{"lepic":2,"type":"pair-finished"}"#,
            r#"{"lepic":1,"type":"unpaired"}"#,
            "pair-finished",
        ] {
            assert_eq!(parse_status(text), None, "{text}");
        }
    }

    #[test]
    fn verdict_hashes_tell_two_sas_apart() {
        assert_ne!(verdict_hash(&[1, 2, 3, 4]), verdict_hash(&[1, 2, 3, 5]));
    }
}
