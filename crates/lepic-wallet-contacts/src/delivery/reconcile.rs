// SPDX-License-Identifier: Apache-2.0
//! The watch set, kept equal to the records its rows come from: the mailboxes of the paired
//! contacts, of their old box salts and previous homes, of the pairings in progress, of the
//! epic1 links and payments, and of the in-person codes.

use std::collections::{HashMap, HashSet};

use jiff::Timestamp;
use lepic_epicbox::{Identity, RelayEndpoint};
use lepic_primitives::params::Network;
use lepic_store::{
    ContactRecord, MAX_RELAY_LEN, MailClass, PairingEndReason, PairingRole, Repositories, WatchRow,
};

use super::epicbox::mail_relays;
use super::watch::{MailboxKeys, REPLACED_PREFIX, Unresolved};
use crate::collect::{Job, OldSalt, box_keys, old_salt_key};
use crate::epic1::{address_relays, epic1_rows};
use crate::in_person::in_person_rows;
use crate::key_schedule::ContactKeys;
use crate::keys::{box_identity, contact_network, pairing_mailbox};
use crate::pairing::pending_deadline;
use crate::relay::{endpoint_for, host_text, mailbox_host};
use crate::{ContactError, ContactRelays, LATE_DRAIN_WAIT, hex};

/// The classes of the contacts' and pairings' rows.
pub(crate) const CONTACT_CLASSES: [MailClass; 3] = [
    MailClass::Contact,
    MailClass::Pairing,
    MailClass::PreviousHome,
];

/// The watch set after [`reconcile`], and the mailbox each contact row names.
pub(crate) struct Reconciled {
    /// Every row of the watch set, of every class.
    pub(crate) set: Vec<WatchRow>,
    pub(crate) mailboxes: Mailboxes,
}

/// The mailbox of each row of the set, by key reference and relay.
#[derive(Default)]
pub(crate) struct Mailboxes(HashMap<(String, String), Resolved>);

struct Resolved {
    /// `None` when the row's relay cannot be reached as written.
    identity: Option<Identity>,
    onion: Option<String>,
    job: Job,
}

impl Mailboxes {
    /// Whose mailbox the row of `key_ref` on `relay` is.
    pub(crate) fn job(&self, key_ref: &str, relay: &str) -> Option<Job> {
        self.get(key_ref, relay).map(|resolved| resolved.job)
    }

    /// Adds the row of the wallet's own native mailbox `job`, whose key [`Self::resolve_native`]
    /// derives. A row already known keeps what it has.
    pub(crate) fn add_native(&mut self, row: &WatchRow, job: Job) {
        self.0
            .entry((row.key_ref.clone(), row.relay.clone()))
            .or_insert(Resolved {
                identity: None,
                onion: None,
                job,
            });
    }

    /// Derives with `derive` the key of each native mailbox, by its relay and job, that has
    /// none yet. One `derive` cannot give stays without, and its row is not watched.
    pub(crate) fn resolve_native(&mut self, mut derive: impl FnMut(&str, Job) -> Option<Identity>) {
        for ((_, relay), resolved) in &mut self.0 {
            if resolved.identity.is_none() && resolved.job.is_native() {
                resolved.identity = derive(relay, resolved.job);
            }
        }
    }

    fn get(&self, key_ref: &str, relay: &str) -> Option<&Resolved> {
        self.0.get(&(key_ref.to_owned(), relay.to_owned()))
    }
}

impl MailboxKeys for Mailboxes {
    fn identity(&self, row: &WatchRow) -> Result<Identity, Unresolved> {
        self.get(&row.key_ref, &row.relay)
            .and_then(|resolved| resolved.identity.clone())
            .ok_or(Unresolved)
    }

    fn onion(&self, row: &WatchRow) -> Option<String> {
        self.get(&row.key_ref, &row.relay)
            .and_then(|resolved| resolved.onion.clone())
    }
}

/// The rows the records call for, each `(key_ref, relay)` once, the first kept.
#[derive(Default)]
struct Derived {
    rows: Vec<WatchRow>,
    places: HashSet<(String, String)>,
    mailboxes: Mailboxes,
}

impl Derived {
    fn add(&mut self, row: WatchRow, resolved: Resolved) {
        if !self.place(&row) {
            return;
        }
        self.mailboxes
            .0
            .entry((row.key_ref.clone(), row.relay.clone()))
            .or_insert(resolved);
        self.rows.push(row);
    }

    /// Adds a row of the wallet's own native mailboxes, whose key is derived after the write.
    fn add_native(&mut self, row: WatchRow, job: Job) {
        if self.place(&row) {
            self.mailboxes.add_native(&row, job);
            self.rows.push(row);
        }
    }

    /// Whether `row` is the first at its place and on a relay the store can hold.
    fn place(&mut self, row: &WatchRow) -> bool {
        // A relay the store cannot hold names no mailbox the wallet can reach.
        if row.relay.is_empty() || row.relay.len() > MAX_RELAY_LEN {
            return false;
        }
        self.places.insert((row.key_ref.clone(), row.relay.clone()))
    }
}

/// Makes the watch set equal to the records: per pairing in progress one row on each relay mail
/// to it can reach, and per paired contact one for its current mailbox and one for an old box
/// salt while it is read on each of those relays, and one for the previous home while it is
/// drained. Mail goes to every relay of the list, so a previous home the list still holds is
/// read as any relay of the list is, drained or not; the drain is for one the list lacks.
/// Contacts with no peer, pairings ended by our side's mismatch and private pairings whose
/// keys do not open get none. The rows of the epic1
/// addresses and payments and of the in-person codes are those [`epic1_rows`] and
/// [`in_person_rows`] give; their keys are left to [`Mailboxes::resolve_native`]. A row no
/// record backs is removed. The replaced marks earlier builds stored are deleted. Returns the set
/// as it stands after the change.
pub(crate) fn reconcile(
    repos: &mut dyn Repositories,
    keychain: &lepic_keychain::Keychain,
    network: Network,
    relays: &ContactRelays,
    now: Timestamp,
) -> Result<Reconciled, ContactError> {
    let mut derived = Derived::default();
    pairing_rows(&*repos, network, relays, &mut derived)?;
    for record in repos.contacts()? {
        contact_rows(
            &*repos,
            keychain,
            network,
            relays,
            now,
            &record,
            &mut derived,
        )?;
    }
    for (row, job) in epic1_rows(&*repos, &address_relays(relays))?
        .into_iter()
        .chain(in_person_rows(&*repos)?)
    {
        derived.add_native(row, job);
    }
    let Derived {
        rows,
        places,
        mailboxes,
    } = derived;
    let mut stored: HashMap<(String, String), WatchRow> = HashMap::new();
    for row in repos.watch_set()? {
        let place = (row.key_ref.clone(), row.relay.clone());
        if places.contains(&place) {
            stored.insert(place, row);
        } else {
            repos.delete_watch(&row.key_ref, &row.relay)?;
        }
    }
    for row in rows {
        if stored.get(&(row.key_ref.clone(), row.relay.clone())) != Some(&row) {
            repos.put_watch(&row)?;
        }
    }
    // Earlier builds marked a row whose mailbox another socket of the wallet took over, and
    // left it out until an open; the mux's hold-off does that now.
    for (key, _) in repos.settings_with_prefix(REPLACED_PREFIX)? {
        repos.delete_setting(&key)?;
    }
    Ok(Reconciled {
        set: repos.watch_set()?,
        mailboxes,
    })
}

/// The relays a `pairing:` or `contact:` row is watched on, each as the row names it, with its
/// endpoint and whether it is `hint`: those of [`mail_relays`] with `hint`, the relay the invite
/// or the card names, which is where the peer's mail can arrive. A hint the wallet cannot reach
/// as written keeps its row, unresolved, as before.
fn mail_places(relays: &ContactRelays, hint: &str) -> Vec<(String, Option<RelayEndpoint>, bool)> {
    let hint_endpoint = endpoint_for(hint, relays).ok();
    let hint_host = hint_endpoint.as_ref().map(host_text);
    let mut places: Vec<(String, Option<RelayEndpoint>, bool)> =
        mail_relays(relays, hint_endpoint.as_ref())
            .into_iter()
            .map(|endpoint| {
                let is_hint = hint_host.as_deref() == Some(host_text(&endpoint).as_str());
                (mailbox_host(&endpoint), Some(endpoint), is_hint)
            })
            .collect();
    if hint_endpoint.is_none() {
        places.push((hint.to_owned(), None, true));
    }
    places
}

/// The reply mailbox of each invite we made and the confirm mailbox of each we answered, on each
/// relay of [`mail_places`] for the invite's relay, until the pairing's wait for a late read ends.
fn pairing_rows(
    repos: &dyn Repositories,
    network: Network,
    relays: &ContactRelays,
    derived: &mut Derived,
) -> Result<(), ContactError> {
    for pending in repos.pending_pairings()? {
        let (seed, job) = match pending.role {
            PairingRole::Inviter => (pending.secrets.code, Job::Reply(pending.pairing_id)),
            PairingRole::Invitee => (pending.secrets.rc, Job::Confirm(pending.pairing_id)),
        };
        let Some(seed) = seed else {
            continue;
        };
        let invite = lepic_contact::Invite::decode(&pending.invite, contact_network(network))
            .map_err(ContactError::StoredData)?;
        let onion = invite
            .fields()
            .onion
            .as_ref()
            .map(|onion| onion.as_str().to_owned());
        let key_ref = format!("pairing:{}", hex::encode(&pending.pairing_id.0));
        let expires_at = pending_deadline(&pending)
            .and_then(|deadline| deadline.checked_add(LATE_DRAIN_WAIT).ok());
        for (relay, endpoint, is_hint) in mail_places(relays, invite.fields().home_relay.as_str()) {
            let identity = match endpoint {
                Some(endpoint) => Some(pairing_mailbox(&seed, network, &endpoint)?.0),
                None => None,
            };
            derived.add(
                WatchRow {
                    key_ref: key_ref.clone(),
                    relay,
                    class: MailClass::Pairing,
                    expires_at,
                },
                Resolved {
                    identity,
                    onion: onion.clone().filter(|_| is_hint),
                    job,
                },
            );
        }
    }
    Ok(())
}

/// The rows of one contact: its current mailbox and the mailbox of an old box salt, each on every
/// relay of [`mail_places`] for its home, and its previous home while it is drained. A previous
/// home among those places already has its row and keeps it after the drain.
fn contact_rows(
    repos: &dyn Repositories,
    keychain: &lepic_keychain::Keychain,
    network: Network,
    relays: &ContactRelays,
    now: Timestamp,
    record: &ContactRecord,
    derived: &mut Derived,
) -> Result<(), ContactError> {
    if record.peer.is_none() {
        return Ok(());
    }
    // A pairing ended by this side's mismatch finalizes nothing: an answer waiting in its
    // mailbox stays there, and the send it answers can still be cancelled.
    if record.facts.ended_reason == Some(PairingEndReason::Mismatch) {
        return Ok(());
    }
    let Some(mailbox) = repos.contact_mailbox(record.contact_id)? else {
        return Ok(());
    };
    let id = record.contact_id;
    let id_hex = hex::encode(&id.0);
    let Some(keys) = box_keys(repos, keychain, network, record, record.box_salt)? else {
        return Ok(());
    };
    let at = |keys: &ContactKeys, relay: &str| -> Result<Option<Identity>, ContactError> {
        match endpoint_for(relay, relays) {
            Ok(endpoint) => box_identity(keys, network, &endpoint).map(Some),
            Err(_) => Ok(None),
        }
    };
    let places = mail_places(relays, &mailbox.home_relay);
    let mut add_box =
        |key_ref: String, keys: &ContactKeys, current: bool| -> Result<(), ContactError> {
            for (relay, endpoint, is_hint) in &places {
                let identity = match endpoint {
                    Some(endpoint) => Some(box_identity(keys, network, endpoint)?),
                    None => None,
                };
                derived.add(
                    WatchRow {
                        key_ref: key_ref.clone(),
                        relay: relay.clone(),
                        class: MailClass::Contact,
                        expires_at: None,
                    },
                    Resolved {
                        identity,
                        onion: mailbox.onion.clone().filter(|_| *is_hint),
                        job: Job::Contact(id, current),
                    },
                );
            }
            Ok(())
        };
    add_box(format!("contact:{id_hex}"), &keys, true)?;
    let old_salt = repos
        .setting(&old_salt_key(id))?
        .and_then(|text| serde_json::from_str::<OldSalt>(&text).ok())
        .and_then(|old| hex::decode_array(&old.salt).ok());
    if let Some(salt) = old_salt
        && let Some(old_keys) = box_keys(repos, keychain, network, record, salt)?
    {
        add_box(format!("contact-old-salt:{id_hex}"), &old_keys, false)?;
    }
    if let Some(previous) = mailbox.previous.filter(|previous| previous.until > now) {
        derived.add(
            WatchRow {
                key_ref: format!("contact:{id_hex}"),
                relay: previous.relay.clone(),
                class: MailClass::PreviousHome,
                expires_at: Some(previous.until),
            },
            Resolved {
                identity: at(&keys, &previous.relay)?,
                onion: None,
                job: Job::Contact(id, false),
            },
        );
    }
    Ok(())
}
