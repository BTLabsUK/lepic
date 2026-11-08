// SPDX-License-Identifier: Apache-2.0
//! Re-pairing after a restore, the key check (RFC 0002 7.8). X holds an old record for a contact
//! and has paired with it again; over the new pairing it asks whether the other side (Y) still
//! holds the old keys. Y answers found with a proof by the old slot key, X answers restored with a
//! proof by its old key, and both fold the new pairing into the old record. Without a proven
//! answer within a day, the old record stays as it was and the new pairing shows keys-changed.

use crate::hex;
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
use crate::ContactBook;
use lepic_methods::epicbox::relay_network;
use lepic_wallet::account::parent_key_id;
use lepic_wallet::event::{ContactEvent, Event};
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// A check is started and answered only within this long of the new pairing, and an open check
/// waits this long for its answer.
pub const KEY_CHECK_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

const SENT_PREFIX: &str = "contact.kc.sent.";
const DONE_PREFIX: &str = "contact.kc.done.";
const SLOT_PREFIX: &str = "contact.kc.slot.";
const FOUND_PREFIX: &str = "contact.kc.found.";
const FOLD_PREFIX: &str = "contact.fold.";
const CHANGED_PREFIX: &str = "contact.kc.changed.";

/// How a key check started by [`Wallet::contact_key_check`] stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheckStart {
    /// The check is on its way, or was already; its answer comes with a collect.
    Sent,
    /// No check may run for these pairings now: the new pairing is past its day, or the old
    /// slot was checked in the last day. The new pairing shows keys-changed at once
    /// ([`Event::ContactKeysChanged`]) and the user decides as for an unanswered check.
    KeysChanged,
}

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

fn id_of(text: &str) -> Option<ContactId> {
    hex::unhex(text)?.try_into().ok().map(ContactId)
}

fn key(prefix: &str, id: ContactId) -> String {
    format!("{prefix}{}", hex::encode(&id.0))
}

/// Deletes the key check settings kept for the pairing `id`, which is being removed. The marks
/// of a checked slot stay, as the slot stays used.
pub(crate) fn delete_contact_settings(
    repos: &mut dyn Repositories,
    id: ContactId,
) -> Result<(), StoreError> {
    for prefix in [
        SENT_PREFIX,
        DONE_PREFIX,
        FOUND_PREFIX,
        FOLD_PREFIX,
        CHANGED_PREFIX,
    ] {
        repos.delete_setting(&key(prefix, id))?;
    }
    Ok(())
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

/// Whether the record takes part in a key check: paired, not private, and never an ended
/// pairing.
fn paired(record: &ContactRecord) -> bool {
    matches!(record.state, ContactState::Paired | ContactState::Verified)
        && record.peer.is_some()
        && record.facts.ended_reason.is_none()
        && !super::private::is_private(record)
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

impl<N, S, V> ContactBook<'_, N, S, V>
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
    /// ([`Event::ContactKeysChanged`]). When no check may run (one a day per slot, within a
    /// day of the new pairing), the new pairing shows keys-changed at once and this returns
    /// [`KeyCheckStart::KeysChanged`]: a contact that restored its wallet must not stay on the
    /// old pairing, which nobody reads any more. Asked again for a check on its way, this
    /// returns [`KeyCheckStart::Sent`] and sends nothing.
    ///
    /// Fails with [`ContactError::Ended`] when either pairing ended, with
    /// [`ContactError::UnknownContact`] unless both are paired and differ, and with
    /// [`ContactError::KeyCheckRefused`] when the new pairing's check already ended.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_key_check(
        &self,
        relays: &ContactRelays,
        new: ContactId,
        old: ContactId,
    ) -> Result<KeyCheckStart, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let envelope = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    for id in [new, old] {
                        if repos
                            .contact(id)?
                            .is_some_and(|record| record.facts.ended_reason.is_some())
                        {
                            return Err(ContactError::Ended);
                        }
                    }
                    let fresh = repos
                        .contact(new)?
                        .filter(paired)
                        .ok_or(ContactError::UnknownContact)?;
                    let stale = repos
                        .contact(old)?
                        .filter(paired)
                        .ok_or(ContactError::UnknownContact)?;
                    if new == old {
                        return Err(ContactError::UnknownContact);
                    }
                    if repos.setting(&key(DONE_PREFIX, new))?.is_some() {
                        if repos.setting(&key(SENT_PREFIX, new))?.is_some() {
                            return Ok(None);
                        }
                        return Err(ContactError::KeyCheckRefused);
                    }
                    if !within_window(fresh.created_at, now)
                        || slot_used(repos, &stale, stale.slot, now)?
                    {
                        repos.put_setting(&key(DONE_PREFIX, new), "x")?;
                        end_check(
                            repos,
                            fresh,
                            &SentCheck {
                                old: hex::encode(&old.0),
                                envelope: String::new(),
                                at: now.as_second(),
                            },
                        )?;
                        return Ok(Some(None));
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
                            old: hex::encode(&old.0),
                            envelope: hex::encode(&envelope),
                            at: now.as_second(),
                        })?,
                    )?;
                    Ok(Some(Some(envelope)))
                })
            })
            .await?;
        let envelope = match envelope {
            None => return Ok(KeyCheckStart::Sent),
            Some(None) => {
                info!("key check not allowed now; keys changed");
                self.wallet
                    .emit(Event::ContactKeysChanged(ContactEvent { contact_id: new }));
                return Ok(KeyCheckStart::KeysChanged);
            }
            Some(Some(envelope)) => envelope,
        };
        self.enqueue_for_contact(
            new,
            Uuid::from_bytes(new.0),
            SlateStage::Standard1,
            &envelope,
        )
        .await?;
        self.deliver_soon(relays).await;
        info!("key check sent");
        Ok(KeyCheckStart::Sent)
    }

    /// Resolves a new pairing in keys-changed (RFC 0002 7.8, step 7). Fails with
    /// [`ContactError::UnknownContact`] when `new` is not in keys-changed.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contact_keys_resolve(
        &self,
        new: ContactId,
        decision: KeysDecision,
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
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
                        super::quarantine::delete_contact_entries(repos, new)?;
                        repos.delete_contact(new)?;
                        super::private::delete_secrets(repos, new)?;
                    }
                    KeysDecision::UseNew => {
                        if let Some(old) = old {
                            drop_contact_invoices(repos, old)?;
                            super::quarantine::delete_contact_entries(repos, old)?;
                            repos.delete_contact(old)?;
                            super::private::delete_secrets(repos, old)?;
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
        let network = self.wallet.config().network;
        let new = record.contact_id;
        let record = record.clone();
        let check_envelope = envelope.to_vec();
        let session = self.wallet.session()?;
        let answer = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    answer_key_check(
                        repos,
                        &ports.rng,
                        &session.keychain,
                        network,
                        &record,
                        &check_envelope,
                        now,
                    )
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
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let new = record.contact_id;
        let session = self.wallet.session()?;
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
                    self.wallet
                        .emit(Event::ContactKeysChanged(ContactEvent { contact_id: new }));
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
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let new = record.contact_id;
        let session = self.wallet.session()?;
        let answer = answer.clone();
        let found_envelope = found_envelope.to_vec();
        let new_peer = new_peer.clone();
        let own_new = *own_new;
        let new_record = record.clone();
        let restored = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let Some((old_id, check_envelope)) = open_sent_check(repos, new, now)? else {
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
                    let old_keys = keys_of(&session.keychain, network, &old)?;
                    let new_keys = keys_of(&session.keychain, network, &new_record)?;
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
                    redirect_to_card(repos, old_id, &refreshed)?;
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
            self.wallet.emit(Event::ContactKeysRestored(ContactEvent {
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
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let new = record.contact_id;
        let session = self.wallet.session()?;
        let answer = answer.clone();
        let new_peer = new_peer.clone();
        let own_new = *own_new;
        let new_record = record.clone();
        let restored = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let Some(found) = fresh_found(repos, new, now)? else {
                        return Ok(None);
                    };
                    let (Some(found_envelope), Some(card), Some(salt)) = (
                        hex::unhex(&found.envelope),
                        hex::unhex(&found.card),
                        hex::unhex(&found.salt).and_then(|salt| <[u8; 16]>::try_from(salt).ok()),
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
                    let keys_fit = restored_keys_fit(repos, existing.as_ref(), &old_card)?;
                    if !keys_fit {
                        warn!("restored answer with keys the record does not hold refused");
                        repos.delete_setting(&key(FOUND_PREFIX, new))?;
                        return Ok(None);
                    }
                    let mut kept = match existing {
                        Some(record) => record,
                        None => remade_record(
                            ContactId(new_id(&mut LockedRng(&mut **ports.rng.lock()))),
                            &new_record,
                            found.slot,
                            salt,
                            card.clone(),
                            now,
                        ),
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
                    let mailbox = restored_mailbox(repos, kept.contact_id, new, &old_card, &own)?;
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
            self.wallet.emit(Event::ContactKeysRestored(ContactEvent {
                contact_id: kept,
            }));
        }
        Ok(())
    }

    /// Ends an open check on the new pairing `new` as not found: the new pairing goes to
    /// keys-changed and the old record stays. Returns whether a check was open.
    async fn close_check(&self, new: ContactId) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
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
        let session = self.wallet.session()?;
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
                            super::quarantine::delete_contact_entries(repos, id)?;
                            repos.delete_contact(id)?;
                            super::private::delete_secrets(repos, id)?;
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
            self.wallet
                .emit(Event::ContactKeysChanged(ContactEvent { contact_id }));
        }
        Ok(())
    }
}

/// Y's answer to the key check `check_envelope` over the new pairing `record`, decided and kept
/// in one store transaction: `None` sends nothing.
fn answer_key_check(
    repos: &mut dyn Repositories,
    rng: &lepic_wallet::SharedRng,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    record: &ContactRecord,
    check_envelope: &[u8],
    now: Timestamp,
) -> Result<Option<Vec<u8>>, ContactError> {
    let net = contact_network(network);
    let new = record.contact_id;
    if !within_window(record.created_at, now) || repos.setting(&key(DONE_PREFIX, new))?.is_some() {
        debug!("key check outside its window or repeated dropped");
        return Ok(None);
    }
    let new_peer = card_of(record, net)?;
    let keys = keys_of(keychain, network, record)?;
    let sealed = SealedEnvelope::decode(check_envelope, net).map_err(ContactError::StoredData)?;
    let Ok(check) = open_key_check(&sealed, &enc_secret(&keys), new_peer.sig_key()) else {
        return Ok(None);
    };
    repos.put_setting(&key(DONE_PREFIX, new), "y")?;
    let n_y = signing_key(&keys).verifying_key();
    let n_x = *new_peer.sig_key();
    let root =
        crate::key_schedule::contact_root(keychain, &parent_key_id(record.account)?, network)
            .map_err(ContactError::Keys)?;
    let found = find_checked_slot(repos, &root, record, &check, &n_y, &n_x)?;
    let mut rng = LockedRng(&mut **rng.lock());
    let Some((slot, existing)) = found else {
        let envelope = seal_not_found(&new_peer, &signing_key(&keys), &mut rng)
            .map_err(ContactError::Encode)?;
        return Ok(Some(envelope));
    };
    if slot_used(repos, record, slot, now)? {
        debug!("key check for a slot checked in the last day dropped");
        return Ok(None);
    }
    repos.put_setting(&slot_key(record, slot), &now.as_second().to_string())?;
    let salt = existing
        .as_ref()
        .map_or_else(|| new_id(&mut rng), |old| old.box_salt);
    let old_keys = contact_keys(keychain, network, record.account, slot, salt)?;
    let refreshed = refreshed_card(network, record, existing.as_ref(), &old_keys, check.seq)?;
    let envelope = seal_found(
        &new_peer,
        &signing_key(&keys),
        check_envelope,
        &refreshed,
        &signing_key(&old_keys),
        &mut rng,
    )
    .map_err(ContactError::Encode)?;
    repos.put_setting(
        &key(FOUND_PREFIX, new),
        &json(&FoundAnswer {
            slot,
            salt: hex::encode(&salt),
            card: hex::encode(refreshed.as_bytes()),
            envelope: hex::encode(&envelope),
            record: existing.map(|old| hex::encode(&old.contact_id.0)),
            at: now.as_second(),
        })?,
    )?;
    Ok(Some(envelope))
}

/// The slot a key check names with its tag: one of the account's records, or else a slot no
/// record of the account holds.
fn find_checked_slot(
    repos: &dyn Repositories,
    root: &crate::key_schedule::ContactRoot,
    record: &ContactRecord,
    check: &lepic_contact::KeyCheck,
    n_y: &VerifyingKey,
    n_x: &VerifyingKey,
) -> Result<Option<(u32, Option<ContactRecord>)>, ContactError> {
    for other in repos.contacts()? {
        if other.contact_id == record.contact_id
            || other.account != record.account
            || other.peer.is_none()
        {
            continue;
        }
        let hint = root.hint_key(other.slot).map_err(ContactError::Keys)?;
        let tag = crate::key_schedule::key_check_tag(&hint, n_y.as_bytes(), n_x.as_bytes());
        if tag == check.tag {
            return Ok(Some((other.slot, Some(other))));
        }
    }
    // A slot any record holds, a shown card or a pending invite included,
    // is never taken a second time.
    let held: Vec<u32> = repos
        .contacts()?
        .iter()
        .filter(|other| other.account == record.account)
        .map(|other| other.slot)
        .collect();
    Ok(root
        .find_slot_by_tag(&check.tag, n_y.as_bytes(), n_x.as_bytes())
        .map_err(ContactError::Keys)?
        .filter(|slot| !held.contains(slot))
        .map(|slot| (slot, None)))
}

/// Our card for the slot a key check found, under its keys `old_keys`: the kept record's card
/// re-signed, or one made again on the new pairing's relay, past the check's sequence number.
fn refreshed_card(
    network: lepic_primitives::params::Network,
    record: &ContactRecord,
    existing: Option<&ContactRecord>,
    old_keys: &crate::key_schedule::ContactKeys,
    check_seq: u32,
) -> Result<ContactCard, ContactError> {
    let net = contact_network(network);
    Ok(match existing {
        Some(old) => {
            let own = ContactCard::decode(&old.own_card, net).map_err(ContactError::StoredData)?;
            let mut fields = own.fields().clone();
            fields.seq = check_seq.max(fields.seq).saturating_add(1);
            ContactCard::sign(net, fields, &signing_key(old_keys)).map_err(ContactError::Encode)?
        }
        None => {
            let own =
                ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
            let home = EpicboxAddress::parse(own.fields().mailbox.as_str(), relay_network(network))
                .map_err(|_| ContactError::RelayAddress)?;
            let mailbox = EpicboxAddress::new(
                *old_keys.box_public_key(),
                relay_network(network),
                home.domain().clone(),
                home.port(),
            );
            our_card(
                old_keys,
                network,
                &mailbox,
                &CardDetails {
                    kind: own.fields().kind,
                    name: own.fields().name.as_str(),
                    seq: check_seq.saturating_add(1),
                    payments_address: own.fields().payments_address.clone(),
                },
            )?
        }
    })
}

/// Our keys for a record, from its slot and box salt.
fn keys_of(
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    record: &ContactRecord,
) -> Result<crate::key_schedule::ContactKeys, ContactError> {
    contact_keys(
        keychain,
        network,
        record.account,
        record.slot,
        record.box_salt,
    )
}

/// The old record and the check envelope of X's open check on the new pairing `new`, while the
/// check is within its day.
fn open_sent_check(
    repos: &dyn Repositories,
    new: ContactId,
    now: Timestamp,
) -> Result<Option<(ContactId, Vec<u8>)>, ContactError> {
    let Some(sent) = read::<SentCheck>(repos, &key(SENT_PREFIX, new))? else {
        return Ok(None);
    };
    let sent_at = Timestamp::from_second(sent.at).map_err(|_| ContactError::KeyCheckRefused)?;
    if !within_window(sent_at, now) {
        return Ok(None);
    }
    let (Some(old_id), Some(check_envelope)) = (id_of(&sent.old), hex::unhex(&sent.envelope))
    else {
        return Ok(None);
    };
    Ok(Some((old_id, check_envelope)))
}

/// Points the contact's mailbox and its queued outbox at the mailbox `card` names.
fn redirect_to_card(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    card: &ContactCard,
) -> Result<(), StoreError> {
    if let Some(mut mailbox) = repos.contact_mailbox(contact_id)? {
        let peer_mailbox = card.fields().mailbox.as_str().to_owned();
        repos.redirect_contact_outbox(contact_id, &peer_mailbox)?;
        mailbox.peer_mailbox = peer_mailbox;
        repos.put_contact_mailbox(&mailbox)?;
    }
    Ok(())
}

/// Y's found answer on the new pairing `new`, while a restored answer may still be taken; a
/// found answer past its day is forgotten.
fn fresh_found(
    repos: &mut dyn Repositories,
    new: ContactId,
    now: Timestamp,
) -> Result<Option<FoundAnswer>, StoreError> {
    let Some(found) = read::<FoundAnswer>(repos, &key(FOUND_PREFIX, new))? else {
        return Ok(None);
    };
    let fresh = Timestamp::from_second(found.at).is_ok_and(|at| within_window(at, now));
    if !fresh {
        repos.delete_setting(&key(FOUND_PREFIX, new))?;
        return Ok(None);
    }
    Ok(Some(found))
}

/// Whether a restored answer's `old_card` may go into the record. A kept record keeps its
/// keys: the restored card must carry exactly the keys it holds for X, or anyone who knows our
/// card for the slot could take over a verified contact. A record made again after a restore
/// takes the card only with its proof, and only when no other record holds its key.
fn restored_keys_fit(
    repos: &dyn Repositories,
    existing: Option<&ContactRecord>,
    old_card: &ContactCard,
) -> Result<bool, StoreError> {
    Ok(match existing.and_then(|record| record.peer.as_ref()) {
        Some(stored) => same_keys(stored, old_card),
        None => {
            existing.is_none()
                && repos
                    .contact_by_peer_sig_key(&old_card.sig_key().to_bytes())?
                    .is_none()
        }
    })
}

/// The record of a slot a restore found that no record held, made again from the new pairing
/// `new_record`, with our card `own_card` for the slot.
fn remade_record(
    contact_id: ContactId,
    new_record: &ContactRecord,
    slot: u32,
    box_salt: [u8; 16],
    own_card: Vec<u8>,
    now: Timestamp,
) -> ContactRecord {
    ContactRecord {
        contact_id,
        account: new_record.account,
        slot,
        box_salt,
        own_card,
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
        facts: new_record.facts.clone(),
    }
}

/// The mailbox of the record `kept` after a restore, pointed at the mailbox of `old_card`. A
/// kept record keeps its home relay; a record made again takes the new pairing's, where its
/// card's mailbox is.
fn restored_mailbox(
    repos: &mut dyn Repositories,
    kept: ContactId,
    new: ContactId,
    old_card: &ContactCard,
    own: &ContactCard,
) -> Result<ContactMailbox, StoreError> {
    let peer_mailbox = old_card.fields().mailbox.as_str().to_owned();
    Ok(match repos.contact_mailbox(kept)? {
        Some(mut mailbox) => {
            if mailbox.peer_mailbox != peer_mailbox {
                repos.redirect_contact_outbox(kept, &peer_mailbox)?;
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
                contact_id: kept,
                peer_mailbox,
                our_mailbox: own.fields().mailbox.as_str().to_owned(),
                home_relay,
                onion,
                previous: None,
                backoff: Vec::new(),
            }
        }
    })
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
