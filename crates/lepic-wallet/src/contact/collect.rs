//! Collecting: one-off drains of the pairing mailboxes and the contact mailboxes, grouped by
//! relay, with per-relay backoff (RFC 0002 8.2 to 8.5).

use std::collections::BTreeMap;
use std::time::Duration;

use blake2::Blake2b256;
use blake2::digest::Digest;
use jiff::Timestamp;
use lepic_contact::{ContactCard, MessageType, SealedEnvelope, dearmor, looks_sealed};
use lepic_epicbox::{
    EpicboxAddress, Handled, Identity, MAX_MAILBOXES_PER_DRAIN, MailboxContent, MailboxError,
    MailboxHandler, MailboxMessage, RelayEndpoint,
};
use lepic_node::NodeApi;
use lepic_store::{
    ContactId, ContactRecord, ContactState, PairingId, PairingRole, Repositories, SealMode,
    StoreError, WalletStore,
};
use lepic_transport::transport::BoxFuture;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use super::keys::{box_identity, contact_keys, contact_network, enc_secret, pairing_mailbox};
use super::pairing::{Taken, peer_card};
use super::relay::{check_online, endpoint_for, host_text, mailbox_client};
use super::{
    CLOCK_SKEW, ContactError, ContactRelays, PairingFailure, UPDATES_PER_CONTACT_PER_DAY,
    UPDATES_PER_HOUR,
};
use crate::event::{ContactEvent, Event, FailedPairing, UnreachableRelay};
use crate::inbox::{ErrorChain, relay_network};
use crate::ports::{SecretVault, StoreOpener};
use crate::wallet::Wallet;

/// What started a collecting cycle (RFC 0002 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectTrigger {
    /// The app opened or resumed, or the wallet was unlocked: every mailbox.
    Open,
    /// The foreground tick: the mailboxes of contacts with something pending, or all of them
    /// when they sit on at most three relays.
    Foreground,
    /// The user pulled to refresh: every mailbox.
    Pull,
    /// A push wake-up: every mailbox.
    Push,
}

/// What one collecting cycle did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectReport {
    /// Mailboxes drained.
    pub mailboxes: usize,
    /// Messages handed out by the relays.
    pub messages: usize,
    /// Pairings that completed.
    pub paired: usize,
    /// Relays that did not answer, as `domain:port`; they back off.
    pub unreachable: Vec<String>,
}

/// Relays that keep failing wait this long before the next try, one step per failure.
const BACKOFF: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_secs(2 * 60),
    Duration::from_secs(10 * 60),
    Duration::from_secs(30 * 60),
];

/// Contacts that had something in the last day count as active for the foreground tick.
const ACTIVE: Duration = Duration::from_secs(24 * 60 * 60);

/// After a service moved its home relay, its old one is drained this long (RFC 0002 8.5).
const PREVIOUS_HOME_KEPT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A card shown in person and never scanned back is forgotten after this.
const SHOWN_CARD_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// Envelopes seen are remembered as long as a relay keeps a message, and a little longer.
const SEEN_LIFETIME: Duration = Duration::from_secs(8 * 24 * 60 * 60);

/// Relays with fewer distinct contact mailboxes than this are drained in full on every tick.
const FEW_RELAYS: usize = 3;

const IN_PERSON_PREFIX: &str = "contact.inperson.";
const OLD_SALT_PREFIX: &str = "contact.oldsalt.";

/// The setting that marks a contact paired in person whose mailbox has not moved yet.
pub(crate) fn in_person_key(contact_id: ContactId) -> String {
    format!("{IN_PERSON_PREFIX}{}", hex(&contact_id.0))
}

fn old_salt_key(contact_id: ContactId) -> String {
    format!("{OLD_SALT_PREFIX}{}", hex(&contact_id.0))
}

/// The box salt of a mailbox moved away from after an in-person pairing, read until `until`.
#[derive(Serialize, Deserialize)]
struct OldSalt {
    salt: String,
    until: i64,
}
const BACKOFF_KEY: &str = "contact.backoff";
const UPDATES_KEY: &str = "contact.updates";
const CURSOR_KEY: &str = "contact.cursor";

/// Which mailbox a drained message came from.
#[derive(Debug, Clone, Copy)]
enum Job {
    Reply(PairingId),
    Confirm(PairingId),
    Contact(ContactId),
}

struct Mailbox {
    job: Job,
    identity: Identity,
    relay: RelayEndpoint,
    onion: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Backoffs(BTreeMap<String, (u32, i64)>);

#[derive(Default, Serialize, Deserialize)]
struct Updates {
    per_contact: BTreeMap<String, Vec<i64>>,
    all: Vec<i64>,
}

fn read_json<T: Default + for<'de> Deserialize<'de>>(
    repos: &dyn Repositories,
    key: &str,
) -> Result<T, StoreError> {
    Ok(repos
        .setting(key)?
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default())
}

fn write_json<T: Serialize>(
    repos: &mut dyn Repositories,
    key: &str,
    value: &T,
) -> Result<(), StoreError> {
    let text = serde_json::to_string(value).map_err(|_| StoreError::Corrupt {
        record: lepic_store::Record::Contact,
        field: "collecting state",
    })?;
    repos.put_setting(key, &text)
}

fn envelope_hash(envelope: &[u8]) -> [u8; 32] {
    Blake2b256::digest(envelope).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A relay's `domain:port`, the port explicit.
fn relay_host(address: &EpicboxAddress) -> String {
    format!(
        "{}:{}",
        address.domain(),
        address.port().unwrap_or(lepic_epicbox::DEFAULT_PORT)
    )
}

/// Whether a service may move its home relay to the relay of `address`: a built-in relay, or a
/// named host (never an IP address) on the default port.
fn acceptable_home(
    address: &EpicboxAddress,
    relays: &ContactRelays,
    network: lepic_primitives::params::Network,
) -> bool {
    let port = address.port().unwrap_or(lepic_epicbox::DEFAULT_PORT);
    let built_in = relays
        .built_in
        .iter()
        .chain(lepic_epicbox::built_in_relays(relay_network(network)).iter())
        .any(|known| known.domain() == address.domain() && known.port() == port);
    let domain = address.domain().as_str();
    let ip_literal = domain.parse::<std::net::IpAddr>().is_ok()
        || domain
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::Ipv6Addr>()
            .is_ok();
    built_in || (!ip_literal && port == lepic_epicbox::DEFAULT_PORT)
}

fn unhex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Collects the pairing and contact mailboxes once (RFC 0002 8.4): each relay is drained on
    /// one connection of its own, at most 50 mailboxes in a cycle, taken in turn across cycles.
    /// Cycles, pairing links entered by hand and outbox runs take turns, never overlapping.
    /// A relay that does not answer backs off for 30 s, 2 min, 10 min, then 30 min, and raises
    /// [`Event::HomeRelayUnreachable`]. Replies to this wallet's invites pair and raise
    /// [`Event::PairingReplied`], confirms raise [`Event::PairingConfirmed`], contact updates
    /// raise [`Event::ContactUpdated`]. Pairings past their time end with
    /// [`Event::PairingFailed`]. Messages are acknowledged only once their effect is stored.
    ///
    /// Fails with [`ContactError::Offline`] or [`ContactError::EpicboxOff`] before connecting,
    /// with [`ContactError::NetworkMismatch`], and as the store does. A relay that fails is
    /// reported, not returned as an error.
    #[instrument(skip_all, fields(wallet = %self.config().name))]
    pub async fn contacts_collect(
        &self,
        relays: &ContactRelays,
        trigger: CollectTrigger,
    ) -> Result<CollectReport, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let _turn = self.contact_turn().await;
        let expired = self.end_expired_pairings().await?;
        for contact_id in expired {
            self.emit(Event::PairingFailed(FailedPairing {
                contact_id,
                reason: PairingFailure::Expired,
            }));
        }
        self.tend_key_checks().await?;
        self.prune_outbox().await?;
        self.forget_old_envelopes().await?;
        self.move_in_person_mailboxes(relays).await?;
        let mailboxes = self.mailboxes_to_collect(relays, trigger).await?;
        let mut by_relay: BTreeMap<String, Vec<Mailbox>> = BTreeMap::new();
        for mailbox in mailboxes {
            by_relay
                .entry(host_text(&mailbox.relay))
                .or_default()
                .push(mailbox);
        }
        let mut report = CollectReport::default();
        let mut told = std::collections::BTreeSet::new();
        for (host, mailboxes) in by_relay {
            let Some(first) = mailboxes.first() else {
                continue;
            };
            let client = mailbox_client(relays, first.relay.clone(), first.onion.as_deref());
            let identities: Vec<Identity> = mailboxes
                .iter()
                .map(|mailbox| mailbox.identity.clone())
                .collect();
            let jobs: Vec<Job> = mailboxes.iter().map(|mailbox| mailbox.job).collect();
            let mut handler = Collector {
                wallet: self,
                relays,
                jobs,
                messages: 0,
                paired: 0,
                told: &mut told,
            };
            report.mailboxes = report.mailboxes.saturating_add(identities.len());
            match client.drain_once(&identities, &mut handler).await {
                Ok(_) => self.relay_answered(&host).await?,
                Err(error @ (MailboxError::Unreachable(_) | MailboxError::Lost(_))) => {
                    warn!(relay = %host, error = %ErrorChain(&error), "home relay not answering");
                    self.relay_failed(&host).await?;
                    self.emit(Event::HomeRelayUnreachable(UnreachableRelay {
                        relay: host.clone(),
                    }));
                    report.unreachable.push(host);
                }
                Err(error) => {
                    warn!(relay = %host, error = %ErrorChain(&error), "mailbox drain failed");
                }
            }
            report.messages = report.messages.saturating_add(handler.messages);
            report.paired = report.paired.saturating_add(handler.paired);
        }
        debug!(count = report.mailboxes, "contact mailboxes collected");
        // Already this run's turn: the outbox runs without taking it again.
        if let Err(error) = self.deliver_outbox(relays).await {
            warn!(error = %ErrorChain(&error), "contact outbox not run");
        }
        Ok(report)
    }

    /// Ends pairings past their time: an invite after its expiry and the clock skew, an answer
    /// whose confirm did not come within the wait, and a card shown in person but never paired.
    async fn end_expired_pairings(&self) -> Result<Vec<ContactId>, ContactError> {
        let session = self.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.write(|repos| {
                let mut ended = Vec::new();
                for pending in repos.pending_pairings()? {
                    let deadline = match pending.role {
                        PairingRole::Inviter => pending.expires_at.checked_add(CLOCK_SKEW).ok(),
                        PairingRole::Invitee => Some(pending.expires_at),
                    };
                    if deadline.is_some_and(|deadline| deadline > now) {
                        continue;
                    }
                    repos.delete_pending_pairing(pending.pairing_id)?;
                    repos.delete_setting(&super::pairing::confirm_key(pending.pairing_id))?;
                    let paired = repos
                        .contact(pending.contact_id)?
                        .is_some_and(|record| record.peer.is_some());
                    if !paired {
                        repos.delete_contact(pending.contact_id)?;
                        ended.push(pending.contact_id);
                    }
                }
                let pending_ids: Vec<ContactId> = repos
                    .pending_pairings()?
                    .iter()
                    .map(|pending| pending.contact_id)
                    .collect();
                for record in repos.contacts()? {
                    let shown_card = record.peer.is_none()
                        && record.state == ContactState::PendingInvite
                        && !pending_ids.contains(&record.contact_id);
                    let old = record
                        .created_at
                        .checked_add(SHOWN_CARD_LIFETIME)
                        .is_ok_and(|end| end <= now);
                    if shown_card && old {
                        repos.delete_contact(record.contact_id)?;
                    }
                }
                Ok::<_, StoreError>(ended)
            })?)
        })
        .await
    }

    /// The mailboxes this cycle drains: every pending pairing's, then the contacts' in turn,
    /// leaving out relays in backoff, at most [`MAX_MAILBOXES_PER_DRAIN`] in all.
    async fn mailboxes_to_collect(
        &self,
        relays: &ContactRelays,
        trigger: CollectTrigger,
    ) -> Result<Vec<Mailbox>, ContactError> {
        let network = self.config().network;
        let session = self.session()?;
        let relays_for_work = relays.clone();
        self.contact_work(move |ports, _| {
            let relays = relays_for_work;
            let now = ports.clock.now();
            session.store.write(|repos| {
                let backoffs: Backoffs = read_json(repos, BACKOFF_KEY)?;
                let waiting = |host: &str| {
                    backoffs
                        .0
                        .get(host)
                        .is_some_and(|(_, until)| *until > now.as_second())
                };
                let mut mailboxes = Vec::new();
                for pending in repos.pending_pairings()? {
                    let invite =
                        lepic_contact::Invite::decode(&pending.invite, contact_network(network))
                            .map_err(ContactError::Decode)?;
                    let home = endpoint_for(invite.fields().home_relay.as_str(), &relays)?;
                    let (seed, job) = match pending.role {
                        PairingRole::Inviter => {
                            (pending.secrets.code, Job::Reply(pending.pairing_id))
                        }
                        PairingRole::Invitee => {
                            (pending.secrets.rc, Job::Confirm(pending.pairing_id))
                        }
                    };
                    let Some(seed) = seed else {
                        continue;
                    };
                    if waiting(&host_text(&home)) {
                        continue;
                    }
                    let (identity, _) = pairing_mailbox(seed, network, &home)?;
                    mailboxes.push(Mailbox {
                        job,
                        identity,
                        relay: home,
                        onion: invite
                            .fields()
                            .onion
                            .as_ref()
                            .map(|onion| onion.as_str().to_owned()),
                    });
                }
                let mut contacts = Vec::new();
                for record in repos.contacts()? {
                    if record.peer.is_none() {
                        continue;
                    }
                    let Some(mailbox) = repos.contact_mailbox(record.contact_id)? else {
                        continue;
                    };
                    let home = endpoint_for(&mailbox.home_relay, &relays)?;
                    if let Some(previous) = mailbox.previous.filter(|previous| previous.until > now)
                    {
                        let old = endpoint_for(&previous.relay, &relays)?;
                        contacts.push((record.clone(), old, None, record.box_salt));
                    }
                    let old_salt = repos
                        .setting(&old_salt_key(record.contact_id))?
                        .and_then(|text| serde_json::from_str::<OldSalt>(&text).ok())
                        .filter(|old| old.until > now.as_second())
                        .and_then(|old| unhex16(&old.salt));
                    if let Some(salt) = old_salt {
                        contacts.push((record.clone(), home.clone(), mailbox.onion.clone(), salt));
                    }
                    let salt = record.box_salt;
                    contacts.push((record, home, mailbox.onion, salt));
                }
                if trigger == CollectTrigger::Foreground {
                    let distinct: std::collections::BTreeSet<String> = contacts
                        .iter()
                        .map(|(_, home, _, _)| host_text(home))
                        .collect();
                    if distinct.len() > FEW_RELAYS {
                        contacts.retain(|(record, _, _, _)| active(record, now));
                    }
                }
                let room = MAX_MAILBOXES_PER_DRAIN.saturating_sub(mailboxes.len());
                let cursor = repos
                    .setting(CURSOR_KEY)?
                    .and_then(|text| text.parse::<usize>().ok())
                    .unwrap_or(0);
                let count = contacts.len();
                let start = cursor.checked_rem(count).unwrap_or(0);
                contacts.rotate_left(start);
                let taken = room.min(count);
                let next = start.saturating_add(taken).checked_rem(count).unwrap_or(0);
                repos.put_setting(CURSOR_KEY, &next.to_string())?;
                for (record, home, onion, salt) in contacts.into_iter().take(taken) {
                    if waiting(&host_text(&home)) {
                        continue;
                    }
                    let keys = contact_keys(
                        &session.keychain,
                        network,
                        record.account,
                        record.slot,
                        salt,
                    )?;
                    mailboxes.push(Mailbox {
                        job: Job::Contact(record.contact_id),
                        identity: box_identity(&keys, network, &home)?,
                        relay: home,
                        onion,
                    });
                }
                Ok(mailboxes)
            })
        })
        .await
    }

    async fn relay_answered(&self, host: &str) -> Result<(), ContactError> {
        let session = self.session()?;
        let host = host.to_owned();
        self.contact_work(move |_, _| {
            Ok(session.store.write(|repos| {
                let mut backoffs: Backoffs = read_json(repos, BACKOFF_KEY)?;
                if backoffs.0.remove(&host).is_some() {
                    write_json(repos, BACKOFF_KEY, &backoffs)?;
                }
                Ok::<_, StoreError>(())
            })?)
        })
        .await
    }

    async fn relay_failed(&self, host: &str) -> Result<(), ContactError> {
        let session = self.session()?;
        let host = host.to_owned();
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.write(|repos| {
                let mut backoffs: Backoffs = read_json(repos, BACKOFF_KEY)?;
                let failures = backoffs.0.get(&host).map_or(0, |(failures, _)| *failures);
                let step = BACKOFF
                    .get(usize::try_from(failures).unwrap_or(usize::MAX))
                    .or(BACKOFF.last())
                    .copied()
                    .unwrap_or_default();
                let until = now.checked_add(step).map_or(i64::MAX, Timestamp::as_second);
                backoffs.0.insert(host, (failures.saturating_add(1), until));
                write_json(repos, BACKOFF_KEY, &backoffs)?;
                Ok::<_, StoreError>(())
            })?)
        })
        .await
    }

    /// Whether an envelope with `hash` was handled before.
    async fn seen_before(&self, hash: [u8; 32]) -> Result<bool, ContactError> {
        let session = self.session()?;
        self.contact_work(move |_, _| Ok(session.store.read(|repos| repos.envelope_seen(&hash))?))
            .await
    }

    /// Remembers that an envelope with `hash` was handled.
    async fn remember(&self, hash: [u8; 32]) -> Result<(), ContactError> {
        let session = self.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session
                .store
                .write(|repos| repos.remember_envelope(&hash, now))?)
        })
        .await
    }

    /// Forgets envelopes seen longer ago than a relay keeps a message, and a little longer.
    async fn forget_old_envelopes(&self) -> Result<(), ContactError> {
        let session = self.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            let cutoff = now.checked_sub(SEEN_LIFETIME).unwrap_or(now);
            session
                .store
                .write(|repos| repos.forget_envelopes_before(cutoff))?;
            Ok(())
        })
        .await
    }

    /// Takes an envelope from a contact's mailbox. It must be signed by the contact's recorded
    /// key; an anonymous one is dropped and never attributed. A contact update or a newer card in
    /// the envelope refreshes the record within the limits of RFC 0002 8.5.
    async fn take_contact_message(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        envelope: &[u8],
        told: &mut std::collections::BTreeSet<ContactId>,
    ) -> Result<Handled, ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let session = self.session()?;
        let record = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |_, _| {
                Ok(session.store.read(|repos| repos.contact(contact_id))?)
            })
            .await?
        };
        let Some(record) = record else {
            return Ok(Handled::Stored);
        };
        let Some(peer) = &record.peer else {
            return Ok(Handled::Stored);
        };
        let Ok(recorded) = lepic_contact::VerifyingKey::from_bytes(&peer.sig_key) else {
            return Ok(Handled::Stored);
        };
        let keys = contact_keys(
            &session.keychain,
            network,
            record.account,
            record.slot,
            record.box_salt,
        )?;
        let Ok(sealed) = SealedEnvelope::decode(envelope, net) else {
            debug!("undecodable envelope in a contact mailbox dropped");
            return Ok(Handled::Stored);
        };
        let opened = match sealed.open_from(&enc_secret(&keys), &recorded) {
            Ok(opened) => opened,
            Err(lepic_contact::DecodeError::KeyChanged) => {
                // Signed by a key that is not the contact's: never the contact's news.
                info!("envelope signed by another key dropped");
                return Ok(Handled::Stored);
            }
            Err(lepic_contact::DecodeError::CannotOpen) => {
                debug!("envelope in a contact mailbox did not open");
                // Once a cycle per contact, however much junk the mailbox holds.
                if told.insert(contact_id) {
                    self.emit(Event::SealedUnopenable(ContactEvent { contact_id }));
                }
                return Ok(Handled::Stored);
            }
            Err(_) => {
                debug!("malformed envelope in a contact mailbox dropped");
                return Ok(Handled::Stored);
            }
        };
        if opened.sender.is_none() {
            debug!("anonymous envelope in a contact mailbox dropped");
            return Ok(Handled::Stored);
        }
        let update = match opened.content.kind {
            MessageType::ContactUpdate => {
                match lepic_contact::open_contact_update(&sealed, &enc_secret(&keys), &recorded) {
                    Ok(card) => Some((card, Some(relays))),
                    Err(_) => return Ok(Handled::Stored),
                }
            }
            _ => opened.content.card.clone().map(|card| (card, None)),
        };
        if let Some((card, update)) = update {
            self.refresh_card(contact_id, card, update).await?;
        }
        self.mark_sealed_in(contact_id).await?;
        let record = {
            let session = self.session()?;
            self.contact_work(move |_, _| {
                Ok(session.store.read(|repos| repos.contact(contact_id))?)
            })
            .await?
        };
        let Some(record) = record else {
            return Ok(Handled::Stored);
        };
        Ok(match opened.content.kind {
            MessageType::ContactUpdate => Handled::Stored,
            MessageType::Slate => self.take_contact_slate(&record, opened.content).await?,
            MessageType::Notice => {
                self.take_contact_notice(&record, &opened.content.body)
                    .await?
            }
            MessageType::KeyCheck => self.take_key_check(&record, envelope).await?,
            MessageType::KeyCheckAnswer => self.take_key_check_answer(&record, envelope).await?,
            MessageType::PairingReply | MessageType::PairingConfirm => Handled::Stored,
        })
    }

    /// Replaces the contact's card with `card` when it carries the same keys and kind and a
    /// higher sequence number. Only a contact update (`update` holds the relays) may change the
    /// card's mailbox, within the limits of RFC 0002 8.5: a person's mailbox stays on its relay,
    /// and a service moves its home relay only to a built-in relay or a named host on the
    /// default port. After a move, our new card goes to the contact at once in a contact update.
    /// A card in any other envelope that names another mailbox is ignored.
    pub(crate) async fn refresh_card(
        &self,
        contact_id: ContactId,
        card: ContactCard,
        update: Option<&ContactRelays>,
    ) -> Result<(), ContactError> {
        let session = self.session()?;
        let network = self.config().network;
        let net = contact_network(network);
        let relays = update.cloned();
        let updated = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let Some(mut record) = repos.contact(contact_id)? else {
                        return Ok(false);
                    };
                    let Some(peer) = &record.peer else {
                        return Ok(false);
                    };
                    let fields = card.fields();
                    // Addresses may change by a card; keys and kind never do (RFC 0002 8.5).
                    if !super::pairing::same_keys(peer, &card)
                        || super::pairing::store_kind(fields.kind) != peer.kind
                        || fields.seq <= peer.seq
                    {
                        return Ok(false);
                    }
                    let service = peer.kind != lepic_store::ContactKind::Person;
                    let Some(mut mailbox) = repos.contact_mailbox(contact_id)? else {
                        return Ok(false);
                    };
                    let peer_mailbox = fields.mailbox.as_str().to_owned();
                    let moved = peer_mailbox != mailbox.peer_mailbox;
                    let Some(relays) = relays.as_ref() else {
                        if moved {
                            debug!("card naming another mailbox outside an update ignored");
                            return Ok(false);
                        }
                        record.peer = Some(peer_card(&card));
                        repos.put_contact(&record)?;
                        return Ok(true);
                    };
                    if !within_update_limits(repos, contact_id, now.as_second())? {
                        debug!("contact update over the limits dropped");
                        return Ok(false);
                    }
                    let relay = EpicboxAddress::parse(&peer_mailbox, relay_network(network))
                        .map_err(|_| ContactError::RelayAddress)?;
                    let old_relay =
                        EpicboxAddress::parse(&mailbox.peer_mailbox, relay_network(network))
                            .ok()
                            .map(|old| relay_host(&old));
                    let new_host = relay_host(&relay);
                    let other_relay = old_relay.as_deref() != Some(new_host.as_str());
                    if other_relay && (!service || !acceptable_home(&relay, relays, network)) {
                        debug!("contact update to a relay it may not move to dropped");
                        return Ok(false);
                    }
                    record.peer = Some(peer_card(&card));
                    if moved {
                        repos.redirect_contact_outbox(contact_id, &peer_mailbox)?;
                    }
                    let mut announce = None;
                    // A service moves its home relay with an update; people re-pair instead.
                    if service && new_host != mailbox.home_relay {
                        let keys = contact_keys(
                            &session.keychain,
                            network,
                            record.account,
                            record.slot,
                            record.box_salt,
                        )?;
                        let ours = EpicboxAddress::new(
                            *keys.box_public_key(),
                            relay_network(network),
                            relay.domain().clone(),
                            relay.port(),
                        );
                        let own = ContactCard::decode(&record.own_card, net)
                            .map_err(ContactError::Decode)?;
                        let mut own_fields = own.fields().clone();
                        own_fields.mailbox = lepic_contact::MailboxAddress::new(&ours.to_string())
                            .map_err(ContactError::Name)?;
                        own_fields.seq = own_fields.seq.saturating_add(1);
                        let signer = super::keys::signing_key(&keys);
                        let own_card = ContactCard::sign(net, own_fields, &signer)
                            .map_err(ContactError::Encode)?;
                        announce = Some(
                            lepic_contact::seal_contact_update(
                                &card,
                                &own_card,
                                &signer,
                                &mut super::LockedRng(&mut **ports.rng.lock()),
                            )
                            .map_err(ContactError::Encode)?,
                        );
                        record.own_card = own_card.as_bytes().to_vec();
                        mailbox.previous = Some(lepic_store::PreviousHome {
                            relay: mailbox.home_relay.clone(),
                            peer_mailbox: mailbox.peer_mailbox.clone(),
                            our_mailbox: mailbox.our_mailbox.clone(),
                            until: now.checked_add(PREVIOUS_HOME_KEPT).unwrap_or(now),
                        });
                        mailbox.home_relay = new_host;
                        mailbox.our_mailbox = ours.to_string();
                        info!("contact home relay moved");
                    }
                    mailbox.peer_mailbox = peer_mailbox.clone();
                    repos.put_contact(&record)?;
                    repos.put_contact_mailbox(&mailbox)?;
                    // Our new mailbox reaches the contact at once, in the same write.
                    if let Some(envelope) = announce {
                        repos.enqueue_contact_outbox(&lepic_store::ContactOutboxEntry {
                            contact_id,
                            slate_id: uuid::Uuid::from_bytes(contact_id.0),
                            stage: lepic_store::SlateStage::Standard1,
                            payload: lepic_contact::armor(&envelope),
                            destination: peer_mailbox,
                            attempts: 0,
                            next_try_at: now,
                            state: lepic_store::ContactOutboxState::Queued,
                            created_at: now,
                            delivered_at: None,
                        })?;
                    }
                    Ok(true)
                })
            })
            .await?;
        if updated {
            info!("contact updated");
            self.emit(Event::ContactUpdated(ContactEvent { contact_id }));
        }
        Ok(())
    }

    /// Moves our mailbox of each contact paired in person to one from a fresh box salt and
    /// tells the contact with a contact update (RFC 0002 7.4): anyone who saw the card QR knows
    /// the old one. The old mailbox is still read for [`PREVIOUS_HOME_KEPT`].
    async fn move_in_person_mailboxes(&self, relays: &ContactRelays) -> Result<(), ContactError> {
        let network = self.config().network;
        let net = contact_network(network);
        let session = self.session()?;
        let relays = relays.clone();
        let updates = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let mut updates = Vec::new();
                    for record in repos.contacts()? {
                        let flag = in_person_key(record.contact_id);
                        if repos.setting(&flag)?.is_none() {
                            continue;
                        }
                        repos.delete_setting(&flag)?;
                        let (Some(peer), Some(mut mailbox)) = (
                            record.peer.clone(),
                            repos.contact_mailbox(record.contact_id)?,
                        ) else {
                            continue;
                        };
                        let home = endpoint_for(&mailbox.home_relay, &relays)?;
                        let mut rng = super::LockedRng(&mut **ports.rng.lock());
                        let salt = super::new_id(&mut rng);
                        let keys = contact_keys(
                            &session.keychain,
                            network,
                            record.account,
                            record.slot,
                            salt,
                        )?;
                        let ours = box_identity(&keys, network, &home)?;
                        let own = ContactCard::decode(&record.own_card, net)
                            .map_err(ContactError::Decode)?;
                        let mut fields = own.fields().clone();
                        fields.mailbox =
                            lepic_contact::MailboxAddress::new(&ours.address().to_string())
                                .map_err(ContactError::Name)?;
                        fields.seq = fields.seq.saturating_add(1);
                        let signer = super::keys::signing_key(&keys);
                        let card = ContactCard::sign(net, fields, &signer)
                            .map_err(ContactError::Encode)?;
                        let peer_card =
                            ContactCard::decode(&peer.bytes, net).map_err(ContactError::Decode)?;
                        let envelope = lepic_contact::seal_contact_update(
                            &peer_card, &card, &signer, &mut rng,
                        )
                        .map_err(ContactError::Encode)?;
                        let old = OldSalt {
                            salt: hex(&record.box_salt),
                            until: now
                                .checked_add(PREVIOUS_HOME_KEPT)
                                .unwrap_or(now)
                                .as_second(),
                        };
                        write_json(repos, &old_salt_key(record.contact_id), &old)?;
                        let mut record = record;
                        record.box_salt = salt;
                        record.own_card = card.as_bytes().to_vec();
                        record.updated_at = now;
                        repos.put_contact(&record)?;
                        mailbox.our_mailbox = ours.address().to_string();
                        repos.put_contact_mailbox(&mailbox)?;
                        updates.push((record.contact_id, envelope));
                    }
                    Ok(updates)
                })
            })
            .await?;
        for (contact_id, envelope) in updates {
            self.enqueue_for_contact(
                contact_id,
                uuid::Uuid::from_bytes(contact_id.0),
                lepic_store::SlateStage::Standard1,
                &envelope,
            )
            .await?;
            info!("in-person mailbox moved");
        }
        Ok(())
    }

    pub(crate) async fn mark_sealed_in(&self, contact_id: ContactId) -> Result<(), ContactError> {
        let session = self.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.write(|repos| {
                if let Some(mut record) = repos.contact(contact_id)? {
                    record.last_sealed_in = Some(now);
                    if record.seal == SealMode::Degraded {
                        record.seal = SealMode::On;
                    }
                    repos.put_contact(&record)?;
                }
                Ok::<_, StoreError>(())
            })?)
        })
        .await
    }
}

fn active(record: &ContactRecord, now: Timestamp) -> bool {
    let recent = |time: Timestamp| time.checked_add(ACTIVE).is_ok_and(|end| end > now);
    recent(record.created_at) || record.last_sealed_in.is_some_and(recent)
}

/// Counts an update against the per-contact and overall limits, and returns whether it fits.
fn within_update_limits(
    repos: &mut dyn Repositories,
    contact_id: ContactId,
    now: i64,
) -> Result<bool, StoreError> {
    let day_ago = now.saturating_sub(24 * 60 * 60);
    let hour_ago = now.saturating_sub(60 * 60);
    let mut updates: Updates = read_json(repos, UPDATES_KEY)?;
    updates.all.retain(|at| *at > hour_ago);
    for times in updates.per_contact.values_mut() {
        times.retain(|at| *at > day_ago);
    }
    updates.per_contact.retain(|_, times| !times.is_empty());
    let key = hex(&contact_id.0);
    let mine = updates.per_contact.get(&key).map_or(0, Vec::len);
    if mine >= UPDATES_PER_CONTACT_PER_DAY || updates.all.len() >= UPDATES_PER_HOUR {
        write_json(repos, UPDATES_KEY, &updates)?;
        return Ok(false);
    }
    updates.per_contact.entry(key).or_default().push(now);
    updates.all.push(now);
    write_json(repos, UPDATES_KEY, &updates)?;
    Ok(true)
}

/// Hands each drained message to the engine and acknowledges it once its effect is stored.
struct Collector<'a, N, S: StoreOpener, V> {
    wallet: &'a Wallet<N, S, V>,
    relays: &'a ContactRelays,
    jobs: Vec<Job>,
    messages: usize,
    paired: usize,
    /// Contacts already reported with [`Event::SealedUnopenable`] this cycle.
    told: &'a mut std::collections::BTreeSet<ContactId>,
}

impl<N, S, V> MailboxHandler for Collector<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            self.messages = self.messages.saturating_add(1);
            let Some(job) = self.jobs.get(message.mailbox()).copied() else {
                return Handled::Stored;
            };
            let MailboxContent::Opened(received) = message.into_content() else {
                return Handled::Stored;
            };
            let text = received.plaintext.expose_str();
            if !looks_sealed(text) {
                debug!("plain payload in a pairing or contact mailbox dropped");
                return Handled::Stored;
            }
            let Ok(envelope) = dearmor(text) else {
                return Handled::Stored;
            };
            match self.take(job, &envelope).await {
                Ok(handled) => handled,
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "mailbox message kept for later");
                    Handled::Later
                }
            }
        })
    }
}

impl<N, S, V> Collector<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    async fn take(&mut self, job: Job, envelope: &[u8]) -> Result<Handled, ContactError> {
        let hash = envelope_hash(envelope);
        if self.wallet.seen_before(hash).await? {
            return Ok(Handled::Stored);
        }
        let handled = match job {
            Job::Reply(pairing_id) => {
                let taken = self
                    .wallet
                    .take_reply(self.relays, pairing_id, envelope, false)
                    .await;
                self.count(taken)?
            }
            Job::Confirm(pairing_id) => {
                let taken = self.wallet.take_confirm(pairing_id, envelope).await;
                self.count(taken)?
            }
            Job::Contact(contact_id) => {
                self.wallet
                    .take_contact_message(self.relays, contact_id, envelope, self.told)
                    .await?
            }
        };
        if handled == Handled::Stored {
            self.wallet.remember(hash).await?;
        }
        Ok(handled)
    }

    fn count(&mut self, taken: Result<Taken, ContactError>) -> Result<Handled, ContactError> {
        if matches!(taken, Ok(Taken::Paired(_))) {
            self.paired = self.paired.saturating_add(1);
        }
        taken.map(|_| Handled::Stored)
    }
}
