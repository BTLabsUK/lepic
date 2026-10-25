//! Re-pairing after a restore, the key check (RFC 0002 7.8). X holds an old record for a contact
//! and has paired with it again; over the new pairing it asks whether the other side (Y) still
//! holds the old keys. Y answers found with a proof by the old slot key, X answers restored with a
//! proof by its old key, and both fold the new pairing into the old record. Without a proven
//! answer within a day, the old record stays as it was and the new pairing shows keys-changed.

use std::time::Duration;

use jiff::Timestamp;
use lepic_contact::{
    ContactCard, KeyCheckAnswer, SealedEnvelope, VerifyingKey, accept_found, accept_restored,
    open_key_check, open_key_check_answer, seal_found, seal_key_check, seal_not_found,
    seal_restored,
};
use lepic_epicbox::{EpicboxAddress, Handled};
use lepic_node::NodeApi;
use lepic_store::{
    ContactId, ContactMailbox, ContactRecord, ContactState, Repositories, SealMode, SlateStage,
    StoreError, WalletStore,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::invoices::drop_contact_invoices;
use super::keys::{CardDetails, contact_keys, contact_network, enc_secret, our_card, signing_key};
use super::pairing::{peer_card, same_keys};
use super::{ContactError, ContactRelays, LockedRng, new_id, pairing_id_of};
use crate::account::parent_key_id;
use crate::event::{ContactEvent, Event};
use crate::inbox::relay_network;
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// A check is started and answered only within this long of the new pairing, and an open check
/// waits this long for its answer.
pub const KEY_CHECK_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

const SENT_PREFIX: &str = "contact.kc.sent.";
const DONE_PREFIX: &str = "contact.kc.done.";
const SLOT_PREFIX: &str = "contact.kc.slot.";
const FOUND_PREFIX: &str = "contact.kc.found.";
const FOLD_PREFIX: &str = "contact.fold.";
const CHANGED_PREFIX: &str = "contact.kc.changed.";

/// What the user chooses for a new pairing whose key check failed (RFC 0002 7.8, step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysDecision {
    /// Keep the old record; the new pairing is deleted.
    KeepOld,
    /// Use the new keys; the old record is deleted and the new pairing stays, not verified.
    UseNew,
}

/// X's open check, kept on the new pairing.
#[derive(Serialize, Deserialize)]
struct SentCheck {
    old: String,
    envelope: String,
    at: i64,
}

/// Y's found answer, kept on the new pairing until X restores.
#[derive(Serialize, Deserialize)]
struct FoundAnswer {
    slot: u32,
    salt: String,
    card: String,
    envelope: String,
    record: Option<String>,
    /// When it was sent; a restored answer is taken only within a day of it.
    #[serde(default)]
    at: i64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn id_of(text: &str) -> Option<ContactId> {
    unhex(text)?.try_into().ok().map(ContactId)
}

fn key(prefix: &str, id: ContactId) -> String {
    format!("{prefix}{}", hex(&id.0))
}

fn slot_key(record: &ContactRecord, slot: u32) -> String {
    format!("{SLOT_PREFIX}{}.{slot}", record.account.0)
}

fn json<T: Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|_| StoreError::Corrupt {
        record: lepic_store::Record::Contact,
        field: "key check",
    })
}

fn read<T: for<'de> Deserialize<'de>>(
    repos: &dyn Repositories,
    key: &str,
) -> Result<Option<T>, StoreError> {
    Ok(repos
        .setting(key)?
        .and_then(|text| serde_json::from_str(&text).ok()))
}

fn within_window(created: Timestamp, now: Timestamp) -> bool {
    created
        .checked_add(KEY_CHECK_WINDOW)
        .is_ok_and(|end| end > now)
}

fn paired(record: &ContactRecord) -> bool {
    matches!(record.state, ContactState::Paired | ContactState::Verified) && record.peer.is_some()
}

/// A recent use of the slot's one check a day, if any.
fn slot_used(
    repos: &dyn Repositories,
    record: &ContactRecord,
    slot: u32,
    now: Timestamp,
) -> Result<bool, StoreError> {
    Ok(repos
        .setting(&slot_key(record, slot))?
        .and_then(|text| text.parse::<i64>().ok())
        .and_then(|at| Timestamp::from_second(at).ok())
        .is_some_and(|at| within_window(at, now)))
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Starts the key check (RFC 0002 7.8): the user added the new pairing `new` to an
    /// address-book contact that already has the pairing `old`. The check goes over the new
    /// pairing; [`Wallet::contacts_collect`] takes the answer. Found, the old record keeps its
    /// keys and trust and the new pairing goes ([`Event::ContactKeysRestored`]); not found or
    /// unanswered within a day, the old record stays and the new pairing shows keys-changed
    /// ([`Event::ContactKeysChanged`]).
    ///
    /// Fails with [`ContactError::UnknownContact`] unless both are paired, and with
    /// [`ContactError::KeyCheckRefused`] when the new pairing is older than a day, or the new
    /// pairing or the old slot had a check within the last day.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contact_key_check(
        &self,
        relays: &ContactRelays,
        new: ContactId,
        old: ContactId,
    ) -> Result<(), ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let session = self.session()?;
        let envelope = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let fresh = repos
                        .contact(new)?
                        .filter(paired)
                        .ok_or(ContactError::UnknownContact)?;
                    let stale = repos
                        .contact(old)?
                        .filter(paired)
                        .ok_or(ContactError::UnknownContact)?;
                    if new == old
                        || !within_window(fresh.created_at, now)
                        || repos.setting(&key(DONE_PREFIX, new))?.is_some()
                        || slot_used(repos, &stale, stale.slot, now)?
                    {
                        return Err(ContactError::KeyCheckRefused);
                    }
                    let new_peer = card_of(&fresh, net)?;
                    let old_peer = card_of(&stale, net)?;
                    let keys = contact_keys(
                        &session.keychain,
                        network,
                        fresh.account,
                        fresh.slot,
                        fresh.box_salt,
                    )?;
                    let envelope = seal_key_check(
                        &new_peer,
                        &old_peer,
                        &signing_key(&keys),
                        &mut LockedRng(&mut **ports.rng.lock()),
                    )
                    .map_err(ContactError::Encode)?;
                    repos.put_setting(&key(DONE_PREFIX, new), "x")?;
                    repos
                        .put_setting(&slot_key(&stale, stale.slot), &now.as_second().to_string())?;
                    repos.put_setting(
                        &key(SENT_PREFIX, new),
                        &json(&SentCheck {
                            old: hex(&old.0),
                            envelope: hex(&envelope),
                            at: now.as_second(),
                        })?,
                    )?;
                    Ok(envelope)
                })
            })
            .await?;
        self.enqueue_for_contact(
            new,
            Uuid::from_bytes(new.0),
            SlateStage::Standard1,
            &envelope,
        )
        .await?;
        self.deliver_soon(relays).await;
        info!("key check sent");
        Ok(())
    }

    /// Resolves a new pairing in keys-changed (RFC 0002 7.8, step 7). Fails with
    /// [`ContactError::UnknownContact`] when `new` is not in keys-changed.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contact_keys_resolve(
        &self,
        new: ContactId,
        decision: KeysDecision,
    ) -> Result<(), ContactError> {
        let session = self.session()?;
        self.contact_work(move |_, _| {
            session.store.write(|repos| {
                let mut record = repos
                    .contact(new)?
                    .filter(|record| record.state == ContactState::KeysChanged)
                    .ok_or(ContactError::UnknownContact)?;
                let old = repos
                    .setting(&key(CHANGED_PREFIX, new))?
                    .and_then(|text| id_of(&text));
                match decision {
                    KeysDecision::KeepOld => {
                        drop_contact_invoices(repos, new)?;
                        repos.delete_contact(new)?;
                    }
                    KeysDecision::UseNew => {
                        if let Some(old) = old {
                            drop_contact_invoices(repos, old)?;
                            repos.delete_contact(old)?;
                        }
                        record.state = ContactState::Paired;
                        record.verified_at = None;
                        repos.put_contact(&record)?;
                    }
                }
                repos.delete_setting(&key(CHANGED_PREFIX, new))?;
                Ok(())
            })
        })
        .await?;
        info!("changed keys resolved");
        Ok(())
    }

    /// Y's side: a key check arrived over the new pairing `record`. Searches its own records,
    /// then every slot, and answers found with a proof, or not found.
    pub(crate) async fn take_key_check(
        &self,
        record: &ContactRecord,
        envelope: &[u8],
    ) -> Result<Handled, ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let new = record.contact_id;
        let record = record.clone();
        let check_envelope = envelope.to_vec();
        let session = self.session()?;
        let answer = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    if !within_window(record.created_at, now)
                        || repos.setting(&key(DONE_PREFIX, new))?.is_some()
                    {
                        debug!("key check outside its window or repeated dropped");
                        return Ok(None);
                    }
                    let new_peer = card_of(&record, net)?;
                    let keys = contact_keys(
                        &session.keychain,
                        network,
                        record.account,
                        record.slot,
                        record.box_salt,
                    )?;
                    let sealed = SealedEnvelope::decode(&check_envelope, net)
                        .map_err(ContactError::StoredData)?;
                    let Ok(check) = open_key_check(&sealed, &enc_secret(&keys), new_peer.sig_key())
                    else {
                        return Ok(None);
                    };
                    repos.put_setting(&key(DONE_PREFIX, new), "y")?;
                    let n_y = signing_key(&keys).verifying_key();
                    let n_x = *new_peer.sig_key();
                    let root = session
                        .keychain
                        .contact_root(&parent_key_id(record.account)?, network)
                        .map_err(ContactError::Keys)?;
                    let mut found: Option<(u32, Option<ContactRecord>)> = None;
                    for other in repos.contacts()? {
                        if other.contact_id == new
                            || other.account != record.account
                            || other.peer.is_none()
                        {
                            continue;
                        }
                        let hint = root.hint_key(other.slot).map_err(ContactError::Keys)?;
                        let tag =
                            lepic_keychain::key_check_tag(&hint, n_y.as_bytes(), n_x.as_bytes());
                        if tag == check.tag {
                            found = Some((other.slot, Some(other)));
                            break;
                        }
                    }
                    if found.is_none() {
                        // A slot any record holds, a shown card or a pending invite included,
                        // is never taken a second time.
                        let held: Vec<u32> = repos
                            .contacts()?
                            .iter()
                            .filter(|other| other.account == record.account)
                            .map(|other| other.slot)
                            .collect();
                        found = root
                            .find_slot_by_tag(&check.tag, n_y.as_bytes(), n_x.as_bytes())
                            .map_err(ContactError::Keys)?
                            .filter(|slot| !held.contains(slot))
                            .map(|slot| (slot, None));
                    }
                    let mut rng = LockedRng(&mut **ports.rng.lock());
                    let Some((slot, existing)) = found else {
                        let envelope = seal_not_found(&new_peer, &signing_key(&keys), &mut rng)
                            .map_err(ContactError::Encode)?;
                        return Ok(Some(envelope));
                    };
                    if slot_used(repos, &record, slot, now)? {
                        debug!("key check for a slot checked in the last day dropped");
                        return Ok(None);
                    }
                    repos.put_setting(&slot_key(&record, slot), &now.as_second().to_string())?;
                    let salt = existing
                        .as_ref()
                        .map_or_else(|| new_id(&mut rng), |old| old.box_salt);
                    let old_keys =
                        contact_keys(&session.keychain, network, record.account, slot, salt)?;
                    let refreshed = match &existing {
                        Some(old) => {
                            let own = ContactCard::decode(&old.own_card, net)
                                .map_err(ContactError::StoredData)?;
                            let mut fields = own.fields().clone();
                            fields.seq = check.seq.max(fields.seq).saturating_add(1);
                            ContactCard::sign(net, fields, &signing_key(&old_keys))
                                .map_err(ContactError::Encode)?
                        }
                        None => {
                            let own = ContactCard::decode(&record.own_card, net)
                                .map_err(ContactError::StoredData)?;
                            let home = EpicboxAddress::parse(
                                own.fields().mailbox.as_str(),
                                relay_network(network),
                            )
                            .map_err(|_| ContactError::RelayAddress)?;
                            let mailbox = EpicboxAddress::new(
                                *old_keys.box_public_key(),
                                relay_network(network),
                                home.domain().clone(),
                                home.port(),
                            );
                            our_card(
                                &old_keys,
                                network,
                                &mailbox,
                                &CardDetails {
                                    kind: own.fields().kind,
                                    name: own.fields().name.as_str(),
                                    seq: check.seq.saturating_add(1),
                                },
                            )?
                        }
                    };
                    let envelope = seal_found(
                        &new_peer,
                        &signing_key(&keys),
                        &check_envelope,
                        &refreshed,
                        &signing_key(&old_keys),
                        &mut rng,
                    )
                    .map_err(ContactError::Encode)?;
                    repos.put_setting(
                        &key(FOUND_PREFIX, new),
                        &json(&FoundAnswer {
                            slot,
                            salt: hex(&salt),
                            card: hex(refreshed.as_bytes()),
                            envelope: hex(&envelope),
                            record: existing.map(|old| hex(&old.contact_id.0)),
                            at: now.as_second(),
                        })?,
                    )?;
                    Ok(Some(envelope))
                })
            })
            .await?;
        if let Some(envelope) = answer {
            self.enqueue_for_contact(
                new,
                Uuid::from_bytes(new.0),
                SlateStage::Standard2,
                &envelope,
            )
            .await?;
            info!("key check answered");
        }
        Ok(Handled::Stored)
    }

    /// A key check answer arrived over the new pairing `record`: X takes not found or found, Y
    /// takes restored.
    pub(crate) async fn take_key_check_answer(
        &self,
        record: &ContactRecord,
        envelope: &[u8],
    ) -> Result<Handled, ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let new = record.contact_id;
        let session = self.session()?;
        let new_peer = card_of(record, net)?;
        let keys = contact_keys(
            &session.keychain,
            network,
            record.account,
            record.slot,
            record.box_salt,
        )?;
        let sealed = SealedEnvelope::decode(envelope, net).map_err(ContactError::StoredData)?;
        let Ok(answer) = open_key_check_answer(&sealed, &enc_secret(&keys), new_peer.sig_key())
        else {
            return Ok(Handled::Stored);
        };
        let own_new = signing_key(&keys).verifying_key();
        match answer {
            KeyCheckAnswer::Restored(_) => {
                self.take_restored(record, &answer, &new_peer, &own_new)
                    .await?;
            }
            KeyCheckAnswer::NotFound => {
                if self.close_check(new).await? {
                    info!("key check not found");
                    self.emit(Event::ContactKeysChanged(ContactEvent { contact_id: new }));
                }
            }
            KeyCheckAnswer::Found(_) => {
                self.take_found(record, &answer, envelope, &new_peer, &own_new)
                    .await?;
            }
        }
        Ok(Handled::Stored)
    }

    /// X's side of a found answer (steps 4 and 5).
    async fn take_found(
        &self,
        record: &ContactRecord,
        answer: &KeyCheckAnswer,
        found_envelope: &[u8],
        new_peer: &ContactCard,
        own_new: &VerifyingKey,
    ) -> Result<(), ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let new = record.contact_id;
        let session = self.session()?;
        let answer = answer.clone();
        let found_envelope = found_envelope.to_vec();
        let new_peer = new_peer.clone();
        let own_new = *own_new;
        let new_record = record.clone();
        let restored = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let Some(sent) = read::<SentCheck>(repos, &key(SENT_PREFIX, new))? else {
                        return Ok(None);
                    };
                    let sent_at = Timestamp::from_second(sent.at)
                        .map_err(|_| ContactError::KeyCheckRefused)?;
                    if !within_window(sent_at, now) {
                        return Ok(None);
                    }
                    let (Some(old_id), Some(check_envelope)) =
                        (id_of(&sent.old), unhex(&sent.envelope))
                    else {
                        return Ok(None);
                    };
                    let Some(mut old) = repos.contact(old_id)? else {
                        return Ok(None);
                    };
                    let stored_old_card = card_of(&old, net)?;
                    let Ok(refreshed) = accept_found(
                        &answer,
                        &check_envelope,
                        new_peer.sig_key(),
                        &own_new,
                        &stored_old_card,
                    ) else {
                        warn!("key check answer without a valid proof refused");
                        return Ok(None);
                    };
                    let old_keys = contact_keys(
                        &session.keychain,
                        network,
                        old.account,
                        old.slot,
                        old.box_salt,
                    )?;
                    let new_keys = contact_keys(
                        &session.keychain,
                        network,
                        new_record.account,
                        new_record.slot,
                        new_record.box_salt,
                    )?;
                    let own_old = ContactCard::decode(&old.own_card, net)
                        .map_err(ContactError::StoredData)?;
                    let envelope = seal_restored(
                        &new_peer,
                        &signing_key(&new_keys),
                        &found_envelope,
                        &own_old,
                        &signing_key(&old_keys),
                        &mut LockedRng(&mut **ports.rng.lock()),
                    )
                    .map_err(ContactError::Encode)?;
                    old.peer = Some(peer_card(&refreshed));
                    if new_record.state == ContactState::Verified
                        && old.state != ContactState::Verified
                    {
                        old.state = ContactState::Verified;
                        old.verified_at = new_record.verified_at.or(Some(now));
                    }
                    old.updated_at = now;
                    repos.put_contact(&old)?;
                    if let Some(mut mailbox) = repos.contact_mailbox(old_id)? {
                        let peer_mailbox = refreshed.fields().mailbox.as_str().to_owned();
                        repos.redirect_contact_outbox(old_id, &peer_mailbox)?;
                        mailbox.peer_mailbox = peer_mailbox;
                        repos.put_contact_mailbox(&mailbox)?;
                    }
                    repos.delete_setting(&key(SENT_PREFIX, new))?;
                    repos.put_setting(&key(FOLD_PREFIX, new), "1")?;
                    Ok(Some((old_id, envelope)))
                })
            })
            .await?;
        if let Some((old_id, envelope)) = restored {
            self.enqueue_for_contact(
                new,
                Uuid::from_bytes(new.0),
                SlateStage::Standard1,
                &envelope,
            )
            .await?;
            info!("contact keys restored");
            self.emit(Event::ContactKeysRestored(ContactEvent {
                contact_id: old_id,
            }));
        }
        Ok(())
    }

    /// Y's side of a restored answer (step 6).
    async fn take_restored(
        &self,
        record: &ContactRecord,
        answer: &KeyCheckAnswer,
        new_peer: &ContactCard,
        own_new: &VerifyingKey,
    ) -> Result<(), ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let new = record.contact_id;
        let session = self.session()?;
        let answer = answer.clone();
        let new_peer = new_peer.clone();
        let own_new = *own_new;
        let new_record = record.clone();
        let restored = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let Some(found) = read::<FoundAnswer>(repos, &key(FOUND_PREFIX, new))? else {
                        return Ok(None);
                    };
                    let fresh =
                        Timestamp::from_second(found.at).is_ok_and(|at| within_window(at, now));
                    if !fresh {
                        repos.delete_setting(&key(FOUND_PREFIX, new))?;
                        return Ok(None);
                    }
                    let (Some(found_envelope), Some(card), Some(salt)) = (
                        unhex(&found.envelope),
                        unhex(&found.card),
                        unhex(&found.salt).and_then(|salt| <[u8; 16]>::try_from(salt).ok()),
                    ) else {
                        return Ok(None);
                    };
                    let Ok(old_card) = accept_restored(
                        &answer,
                        &found_envelope,
                        new_peer.sig_key(),
                        &own_new,
                        net,
                    ) else {
                        warn!("restored answer without a valid proof refused");
                        return Ok(None);
                    };
                    let existing = found.record.as_deref().and_then(id_of);
                    let existing = existing.map(|id| repos.contact(id)).transpose()?.flatten();
                    // A kept record keeps its keys: the restored card must carry exactly the
                    // keys it holds for X, or anyone who knows our card for the slot could take
                    // over a verified contact. A record made again after a restore takes the
                    // card only with its proof, and only when no other record holds its key.
                    let keys_fit = match existing.as_ref().and_then(|record| record.peer.as_ref()) {
                        Some(stored) => same_keys(stored, &old_card),
                        None => {
                            existing.is_none()
                                && repos
                                    .contact_by_peer_sig_key(&old_card.sig_key().to_bytes())?
                                    .is_none()
                        }
                    };
                    if !keys_fit {
                        warn!("restored answer with keys the record does not hold refused");
                        repos.delete_setting(&key(FOUND_PREFIX, new))?;
                        return Ok(None);
                    }
                    let mut kept = match existing {
                        Some(record) => record,
                        None => ContactRecord {
                            contact_id: ContactId(new_id(&mut LockedRng(&mut **ports.rng.lock()))),
                            account: new_record.account,
                            slot: found.slot,
                            box_salt: salt,
                            own_card: card.clone(),
                            peer: None,
                            alternate: None,
                            label: new_record.label.clone(),
                            state: new_record.state,
                            sas: new_record.sas,
                            verified_at: new_record.verified_at,
                            allow_invoices: false,
                            seal: SealMode::On,
                            last_sealed_in: None,
                            app_contact: new_record.app_contact.clone(),
                            imported_from_backup: false,
                            created_at: now,
                            updated_at: now,
                        },
                    };
                    kept.own_card = card.clone();
                    kept.peer = Some(peer_card(&old_card));
                    if new_record.state == ContactState::Verified {
                        kept.state = ContactState::Verified;
                        kept.verified_at = new_record.verified_at;
                    }
                    kept.updated_at = now;
                    repos.put_contact(&kept)?;
                    let own = ContactCard::decode(&card, net).map_err(ContactError::StoredData)?;
                    let peer_mailbox = old_card.fields().mailbox.as_str().to_owned();
                    // A kept record keeps its home relay; a record made again takes the new
                    // pairing's, where its card's mailbox is.
                    let mailbox = match repos.contact_mailbox(kept.contact_id)? {
                        Some(mut mailbox) => {
                            if mailbox.peer_mailbox != peer_mailbox {
                                repos.redirect_contact_outbox(kept.contact_id, &peer_mailbox)?;
                            }
                            mailbox.peer_mailbox = peer_mailbox;
                            mailbox
                        }
                        None => {
                            let (home_relay, onion) = match repos.contact_mailbox(new)? {
                                Some(mailbox) => (mailbox.home_relay, mailbox.onion),
                                None => (String::new(), None),
                            };
                            ContactMailbox {
                                contact_id: kept.contact_id,
                                peer_mailbox,
                                our_mailbox: own.fields().mailbox.as_str().to_owned(),
                                home_relay,
                                onion,
                                previous: None,
                                backoff: Vec::new(),
                            }
                        }
                    };
                    repos.put_contact_mailbox(&mailbox)?;
                    repos.raise_contact_slot_counter(kept.account, found.slot.saturating_add(1))?;
                    repos.delete_setting(&key(FOUND_PREFIX, new))?;
                    repos.put_setting(&key(FOLD_PREFIX, new), "1")?;
                    Ok(Some(kept.contact_id))
                })
            })
            .await?;
        if let Some(kept) = restored {
            info!("contact keys restored");
            self.emit(Event::ContactKeysRestored(ContactEvent {
                contact_id: kept,
            }));
        }
        Ok(())
    }

    /// Ends an open check on the new pairing `new` as not found: the new pairing goes to
    /// keys-changed and the old record stays. Returns whether a check was open.
    async fn close_check(&self, new: ContactId) -> Result<bool, ContactError> {
        let session = self.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.write(|repos| {
                let Some(sent) = read::<SentCheck>(repos, &key(SENT_PREFIX, new))? else {
                    return Ok::<_, StoreError>(false);
                };
                if let Some(record) = repos.contact(new)? {
                    end_check(repos, record, &sent)?;
                }
                Ok(true)
            })?)
        })
        .await
    }

    /// Ends checks that went unanswered for a day, and removes new pairings folded into an old
    /// record once nothing for them waits in the outbox.
    pub(crate) async fn tend_key_checks(&self) -> Result<(), ContactError> {
        let session = self.session()?;
        let changed = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                Ok(session.store.write(|repos| {
                    let mut changed = Vec::new();
                    for record in repos.contacts()? {
                        let id = record.contact_id;
                        if repos.setting(&key(FOLD_PREFIX, id))?.is_some()
                            && repos.contact_outbox(id)?.iter().all(|entry| {
                                entry.entry.state != lepic_store::ContactOutboxState::Queued
                            })
                        {
                            super::pairing::end_pending(repos, pairing_id_of(id))?;
                            drop_contact_invoices(repos, id)?;
                            repos.delete_contact(id)?;
                            repos.delete_setting(&key(FOLD_PREFIX, id))?;
                            continue;
                        }
                        // A found answer nobody restored within a day is forgotten.
                        if let Some(found) = read::<FoundAnswer>(repos, &key(FOUND_PREFIX, id))?
                            && Timestamp::from_second(found.at)
                                .is_ok_and(|at| !within_window(at, now))
                        {
                            repos.delete_setting(&key(FOUND_PREFIX, id))?;
                        }
                        let Some(sent) = read::<SentCheck>(repos, &key(SENT_PREFIX, id))? else {
                            continue;
                        };
                        let expired =
                            Timestamp::from_second(sent.at).is_ok_and(|at| !within_window(at, now));
                        if expired {
                            end_check(repos, record, &sent)?;
                            changed.push(id);
                        }
                    }
                    Ok::<_, StoreError>(changed)
                })?)
            })
            .await?;
        for contact_id in changed {
            info!("key check unanswered");
            self.emit(Event::ContactKeysChanged(ContactEvent { contact_id }));
        }
        Ok(())
    }
}

/// Ends the open check `sent` on the new pairing `record` as not found: the pairing goes to
/// keys-changed with its trust reset, and the check is closed, so a later found answer is
/// refused. The old record's id is kept for [`Wallet::contact_keys_resolve`].
fn end_check(
    repos: &mut dyn Repositories,
    mut record: ContactRecord,
    sent: &SentCheck,
) -> Result<(), StoreError> {
    let id = record.contact_id;
    record.state = ContactState::KeysChanged;
    record.allow_invoices = false;
    record.verified_at = None;
    drop_contact_invoices(repos, id)?;
    repos.put_contact(&record)?;
    repos.put_setting(&key(CHANGED_PREFIX, id), &sent.old)?;
    repos.delete_setting(&key(SENT_PREFIX, id))
}

/// The peer card a record holds.
fn card_of(
    record: &ContactRecord,
    net: lepic_contact::Network,
) -> Result<ContactCard, ContactError> {
    let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
    ContactCard::decode(&peer.bytes, net).map_err(ContactError::StoredData)
}
