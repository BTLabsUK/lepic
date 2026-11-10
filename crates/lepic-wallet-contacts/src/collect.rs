// SPDX-License-Identifier: Apache-2.0
//! Collecting: one-off drains of the pairing mailboxes and the contact mailboxes, grouped by
//! relay, with per-relay backoff (RFC 0002 8.2 to 8.5).

use crate::hex;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use blake2::Blake2b256;
use blake2::digest::Digest;
use jiff::Timestamp;
use lepic_contact::{
    ContactCard, MessageType, Opened, PaymentFile, SealedEnvelope, classify, dearmor,
};
use lepic_epicbox::{
    EpicboxAddress, Handled, Identity, MAX_MAILBOXES_PER_DRAIN, MailboxContent, MailboxEnd,
    MailboxError, MailboxHandler, MailboxMessage, RelayEndpoint,
};
use lepic_node::NodeApi;
use lepic_store::{
    ContactId, ContactOutboxState, ContactRecord, ContactState, PairingId, PairingRole,
    PendingInvoiceStatus, Repositories, SealMode, StoreError, TxDirection, TxState, WalletStore,
};
use lepic_transport::transport::BoxFuture;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use super::keys::{box_identity, contact_keys, contact_network, enc_secret, pairing_mailbox};
use super::pairing::{Taken, peer_card};
use super::quarantine::{Message, QuarantineReason};
use super::relay::{check_online, endpoint_for, host_text, mailbox_client};
use super::{
    ContactError, ContactRelays, LATE_DRAIN_WAIT, PairingFailure, UPDATES_PER_CONTACT_PER_DAY,
    UPDATES_PER_HOUR,
};
use crate::ContactBook;
use lepic_methods::epicbox::relay_network;
use lepic_primitives::error_chain::ErrorChain;
use lepic_wallet::WalletPolicy;
use lepic_wallet::event::{
    ContactChange, ContactEvent, ContactUpdate, Event, FailedPairing, RelayMoveRequest,
    UnreachableRelay,
};
use lepic_wallet::ports::{SecretVault, StoreOpener};

/// What started a collecting cycle (RFC 0002 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectTrigger {
    /// The app opened or resumed, or the wallet was unlocked: every mailbox, and relays in
    /// backoff and the whole outbox are tried at once.
    Open,
    /// The foreground tick: the mailboxes of contacts with something pending, or all of them
    /// when they sit on at most three relays.
    Foreground,
    /// The user pulled to refresh, or ran collect in the CLI: as [`CollectTrigger::Open`].
    Pull,
    /// A push wake-up: every mailbox; relay backoff and outbox retry times are kept, since
    /// pushes can come in bursts.
    Push,
}

/// What one collecting cycle did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectReport {
    /// Mailboxes drained.
    pub mailboxes: usize,
    /// Mailboxes whose drain stopped at the per-mailbox message limit; the rest wait for the
    /// next collect.
    pub capped: usize,
    /// Mailboxes whose drain stopped because a message was kept for later.
    pub kept: usize,
    /// Mailboxes whose drain stopped because the relay refused an acknowledgement.
    pub refused: usize,
    /// Mailboxes the drain's time ran out on.
    pub timed_out: usize,
    /// Mailboxes the drain ended before, including those of a relay that failed.
    pub not_reached: usize,
    /// Messages handed out by the relays.
    pub messages: usize,
    /// Pairings that completed.
    pub paired: usize,
    /// Pairings in progress that ended with nothing stored: expired, refused by the inviter,
    /// or changed on the way. Each also raised [`Event::PairingFailed`].
    pub failed: Vec<FailedPairing>,
    /// Outbox entries that reached their relay in this cycle.
    pub delivered: usize,
    /// Relays that did not answer, as `domain:port`; they back off.
    pub unreachable: Vec<String>,
    /// Pairings that ended in this cycle; their records are kept. Each also raised
    /// [`Event::ContactUpdated`] or [`Event::ContactUnpaired`].
    pub ended: Vec<super::EndedPairing>,
    /// Contact messages kept in quarantine in this cycle.
    pub quarantined: usize,
    /// Contact messages lost to the quarantine's cap in this cycle: entries that went to make
    /// room, and messages too large to keep.
    pub quarantine_dropped: usize,
    /// Notices for a slate this wallet does not hold yet, kept to apply when it arrives
    /// (ADR 0049).
    pub buffered: usize,
    /// Answers taken from the reply mailboxes of in-person codes.
    pub in_person: usize,
    /// Payments taken at epic1 link mailboxes and answers to epic1 payments finalized.
    pub epic1: usize,
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

/// After a contact moved to another relay, our mailbox on the old one is drained this long (RFC
/// 0002 8.5).
const PREVIOUS_HOME_KEPT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A card shown in person and never scanned back is forgotten after this.
const SHOWN_CARD_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// A slate, notice or payload sealed longer ago than this is refused, however it arrives.
const MAX_ENVELOPE_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How far ahead of our clock a sender's may be.
const MAX_CLOCK_AHEAD: Duration = Duration::from_secs(24 * 60 * 60);

/// Envelopes seen are remembered longer than one is accepted after it was sealed, so one that
/// arrives again is always recognised.
const SEEN_LIFETIME: Duration =
    Duration::from_secs(MAX_ENVELOPE_AGE.as_secs() + MAX_CLOCK_AHEAD.as_secs() + 24 * 60 * 60);

/// Relays with fewer distinct contact mailboxes than this are drained in full on every tick.
const FEW_RELAYS: usize = 3;

const IN_PERSON_PREFIX: &str = "contact.inperson.";
const OLD_SALT_PREFIX: &str = "contact.oldsalt.";
const STAMPED_PREFIX: &str = "contact.stamped.";
const HELD_PREFIX: &str = "contact.held.";

/// A hold count is forgotten this long after the message was first held, whether or not it came
/// back: one that never comes back would otherwise keep its row forever. How often and how long
/// a failing message is held are the host's ([`WalletPolicy::contact_hold_attempts`] and
/// [`WalletPolicy::contact_hold_patience`]), within this bound.
const HELD_FORGOTTEN: Duration = WalletPolicy::MAX_CONTACT_HOLD_PATIENCE;

/// How long a hold count is kept while the host keeps a quarantine: past the week a relay keeps a
/// message, so a wallet that collects rarely still reaches the hold bound of a message that keeps
/// coming back.
const HELD_KEPT_FOR_QUARANTINE: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// The setting that holds the hold count of the envelope with `hash`.
pub(crate) fn held_key(hash: [u8; 32]) -> String {
    format!("{HELD_PREFIX}{}", hex::encode(&hash))
}

/// The setting that marks a contact whose envelopes carry their send time: from then on one
/// without it is refused.
pub(crate) fn stamped_key(contact_id: ContactId) -> String {
    format!("{STAMPED_PREFIX}{}", hex::encode(&contact_id.0))
}

/// The send time to seal into an envelope sealed at `now`.
pub(crate) fn send_time(now: Timestamp) -> Option<u64> {
    u64::try_from(now.as_second()).ok()
}

/// The setting that marks a contact paired in person whose mailbox has not moved yet.
pub(crate) fn in_person_key(contact_id: ContactId) -> String {
    format!("{IN_PERSON_PREFIX}{}", hex::encode(&contact_id.0))
}

fn old_salt_key(contact_id: ContactId) -> String {
    format!("{OLD_SALT_PREFIX}{}", hex::encode(&contact_id.0))
}

/// The box salt of a mailbox moved away from after an in-person pairing. It is read until the
/// contact writes to the new mailbox, which shows it took our new card.
#[derive(Serialize, Deserialize)]
struct OldSalt {
    salt: String,
}
const BACKOFF_KEY: &str = "contact.backoff";
const UPDATES_KEY: &str = "contact.updates";
const CURSOR_KEY: &str = "contact.cursor";
/// The turn of the pairings in progress, as [`CURSOR_KEY`] is the contacts'.
const PENDING_CURSOR_KEY: &str = "contact.pending_cursor";
/// The part of a cycle kept for the contacts while more pairings are in progress than fit.
const CONTACT_SHARE: usize = MAX_MAILBOXES_PER_DRAIN / 2;

/// Which mailbox a drained message came from.
#[derive(Debug, Clone, Copy)]
enum Job {
    Reply(PairingId),
    Confirm(PairingId),
    /// A contact's mailbox; `true` for the one our current card names.
    Contact(ContactId, bool),
}

struct Mailbox {
    job: Job,
    identity: Identity,
    relay: RelayEndpoint,
    onion: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Backoffs(BTreeMap<String, (u32, i64)>);

impl Backoffs {
    /// Whether `host` waits out its backoff at `now`.
    fn waiting(&self, host: &str, now: Timestamp) -> bool {
        self.0
            .get(host)
            .is_some_and(|(_, until)| *until > now.as_second())
    }

    /// Whether `host` waits out its backoff at `now` for a pairing in progress. A pairing lasts
    /// minutes: its relay is tried again after the first backoff step however often it failed.
    fn pending_waiting(&self, host: &str, now: Timestamp) -> bool {
        self.0.get(host).is_some_and(|(failures, until)| {
            let index = usize::try_from(*failures)
                .unwrap_or(usize::MAX)
                .clamp(1, BACKOFF.len())
                .saturating_sub(1);
            let step = BACKOFF.get(index).map_or(0, Duration::as_secs);
            let first = BACKOFF.first().map_or(0, Duration::as_secs);
            let failed_at = until.saturating_sub(i64::try_from(step).unwrap_or(0));
            failed_at.saturating_add(i64::try_from(first).unwrap_or(0)) > now.as_second()
        })
    }
}

/// A contact mailbox to drain: the record, the relay and onion it is on, the box salt it is
/// read with, and which of the contact's mailboxes it is.
type ContactBox = (
    ContactRecord,
    RelayEndpoint,
    Option<String>,
    [u8; 16],
    BoxRead,
);

/// Which of a contact's mailboxes a drain reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoxRead {
    /// The one our current card names.
    Current,
    /// The one of an old box salt, read until the contact writes to the current one.
    OldSalt,
    /// Ours on a previous home relay, read until its drain ends.
    PreviousHome,
}

#[derive(Default, Serialize, Deserialize)]
struct Updates {
    per_contact: BTreeMap<String, Vec<i64>>,
    all: Vec<i64>,
}

/// Collecting state under `key`. It only paces relays and contact updates, so a damaged value
/// starts afresh, which the next write repairs.
fn read_json<T: Default + for<'de> Deserialize<'de>>(
    repos: &dyn Repositories,
    key: &str,
) -> Result<T, StoreError> {
    let Some(text) = repos.setting(key)? else {
        return Ok(T::default());
    };
    Ok(serde_json::from_str(&text).unwrap_or_else(|_| {
        warn!("contact collecting state not readable, started afresh");
        T::default()
    }))
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

pub(crate) fn envelope_hash(envelope: &[u8]) -> [u8; 32] {
    Blake2b256::digest(envelope).into()
}

/// A relay's `domain:port`, the port explicit.
fn relay_host(address: &EpicboxAddress) -> String {
    format!(
        "{}:{}",
        address.domain(),
        address.port().unwrap_or(lepic_epicbox::DEFAULT_PORT)
    )
}

/// The relay host the contact's stored card names when the contact asked to move there: another
/// host than the one of the mailbox we deliver to, and than our home relay. `None` when the card
/// names no other host or its mailbox does not parse.
fn requested_host(
    card: &ContactCard,
    mailbox: &lepic_store::ContactMailbox,
    network: lepic_primitives::params::Network,
) -> Option<String> {
    let parse = |text: &str| EpicboxAddress::parse(text, relay_network(network)).ok();
    let named = relay_host(&parse(card.fields().mailbox.as_str())?);
    let current = parse(&mailbox.peer_mailbox).map(|address| relay_host(&address));
    (current.as_deref() != Some(named.as_str()) && named != mailbox.home_relay).then_some(named)
}

/// The relay host a contact asked to move to and has not been moved to, from its stored card
/// and its mailbox; see [`requested_host`].
pub(crate) fn requested_relay(
    record: &ContactRecord,
    mailbox: &lepic_store::ContactMailbox,
    network: lepic_primitives::params::Network,
) -> Option<String> {
    let card = ContactCard::decode(&record.peer.as_ref()?.bytes, contact_network(network)).ok()?;
    requested_host(&card, mailbox, network)
}

/// Ends the pairing in progress `pending`, past its deadline, and says what ended: `None` when
/// it is kept, else the failure to report, if any. A pairing the inviter holds already ends
/// quietly once its confirm left; one whose confirm never left is kept for another try unless
/// `last`, and then removed, since the invitee cannot have finished it. Any other ends with
/// its record.
fn end_late_pairing(
    repos: &mut dyn Repositories,
    pending: &lepic_store::PendingPairing,
    last: bool,
) -> Result<Option<Option<FailedPairing>>, StoreError> {
    let contact_id = pending.contact_id;
    // A cancelled invite was kept only to refuse late replies: it ends without a word.
    if pending.cancelled_at.is_some() {
        super::pairing::end_pending(repos, pending.pairing_id)?;
        repos.delete_contact(contact_id)?;
        super::private::delete_secrets(repos, contact_id)?;
        return Ok(Some(None));
    }
    let paired = repos
        .contact(contact_id)?
        .is_some_and(|record| record.peer.is_some());
    let reason = if paired {
        let out = repos
            .setting(&super::pairing::confirm_out_key(pending.pairing_id))?
            .is_some();
        if out {
            super::pairing::end_pending(repos, pending.pairing_id)?;
            return Ok(Some(None));
        }
        if !last {
            return Ok(None);
        }
        PairingFailure::NotConfirmed
    } else {
        match pending.role {
            PairingRole::Inviter => PairingFailure::Expired,
            PairingRole::Invitee => PairingFailure::NotConfirmed,
        }
    };
    super::pairing::end_pending(repos, pending.pairing_id)?;
    super::invoices::drop_contact_invoices(repos, contact_id)?;
    super::quarantine::delete_contact_entries(repos, contact_id)?;
    repos.delete_contact(contact_id)?;
    super::private::delete_secrets(repos, contact_id)?;
    Ok(Some(Some(FailedPairing { contact_id, reason })))
}

impl<N, S, V> ContactBook<'_, N, S, V>
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
    pub async fn contacts_collect(
        &self,
        relays: &ContactRelays,
        trigger: CollectTrigger,
    ) -> Result<CollectReport, ContactError> {
        self.contacts_collect_only(relays, trigger, None).await
    }

    /// [`Wallet::contacts_collect`] with only the mailboxes of the contacts in `only` drained,
    /// their pairings in progress included, when it is given: a cheap look at a few pairings.
    /// The turn the other contacts take across cycles is left as it was; everything else a
    /// cycle does runs as it always does.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    // One cycle in its order: the steps share the report and the turn.
    #[allow(clippy::too_many_lines)]
    pub async fn contacts_collect_only(
        &self,
        relays: &ContactRelays,
        trigger: CollectTrigger,
        only: Option<&[ContactId]>,
    ) -> Result<CollectReport, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let _turn = self.wallet.contact_turn().await;
        let mut report = CollectReport::default();
        // The user's own triggers retry at once what waits: relays in backoff and outbox
        // entries not yet due (RFC 0002 12.4). The foreground tick and push wake-ups, which
        // can come in bursts, keep the waits.
        let explicit = matches!(trigger, CollectTrigger::Open | CollectTrigger::Pull);
        if explicit {
            self.reset_backoff().await?;
        }
        for failed in self.end_expired_pairings().await? {
            self.wallet.emit(Event::PairingFailed(failed));
            report.failed.push(failed);
        }
        self.tend_key_checks().await?;
        self.prune_outbox().await?;
        self.forget_old_envelopes().await?;
        self.move_in_person_mailboxes(relays).await?;
        self.send_address_cards(relays).await?;
        let only = only.map(|ids| ids.iter().copied().collect::<BTreeSet<ContactId>>());
        let mailboxes = self.mailboxes_to_collect(relays, trigger, only).await?;
        let mut by_relay: BTreeMap<String, Vec<Mailbox>> = BTreeMap::new();
        for mailbox in mailboxes {
            by_relay
                .entry(host_text(&mailbox.relay))
                .or_default()
                .push(mailbox);
        }
        let ended_before = self.ended_since(&BTreeSet::new()).await?;
        let ended_before: BTreeSet<ContactId> =
            ended_before.iter().map(|ended| ended.contact_id).collect();
        let mut told = Told::default();
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
            let pairings: Vec<PairingId> = jobs
                .iter()
                .filter_map(|job| match job {
                    Job::Reply(pairing_id) | Job::Confirm(pairing_id) => Some(*pairing_id),
                    Job::Contact(..) => None,
                })
                .collect();
            let contacts: Vec<ContactId> = jobs
                .iter()
                .filter_map(|job| match job {
                    Job::Contact(contact_id, true) => Some(*contact_id),
                    _ => None,
                })
                .collect();
            let started = self.wallet.ports().clock.now();
            let mut handler = Collector {
                wallet: self,
                relays,
                jobs,
                messages: 0,
                paired: 0,
                failed: Vec::new(),
                told: &mut told,
            };
            report.mailboxes = report.mailboxes.saturating_add(identities.len());
            let drained = client.drain_once(&identities, &mut handler).await;
            report.messages = report.messages.saturating_add(handler.messages);
            report.paired = report.paired.saturating_add(handler.paired);
            report.failed.append(&mut handler.failed);
            match drained {
                Ok(drain) => {
                    for mailbox in &drain.mailboxes {
                        match mailbox.end {
                            MailboxEnd::Capped => report.capped = report.capped.saturating_add(1),
                            MailboxEnd::Kept => report.kept = report.kept.saturating_add(1),
                            MailboxEnd::Refused => {
                                report.refused = report.refused.saturating_add(1);
                            }
                            MailboxEnd::TimedOut => {
                                report.timed_out = report.timed_out.saturating_add(1);
                            }
                            MailboxEnd::NotReached => {
                                report.not_reached = report.not_reached.saturating_add(1);
                            }
                            _ => {}
                        }
                    }
                    self.relay_answered(&host).await?;
                    // The relay held everything that reached it by `started`: what is past
                    // its deadline then has had its last chance.
                    for failed in self.end_drained_pairings(pairings, started).await? {
                        self.wallet.emit(Event::PairingFailed(failed));
                        report.failed.push(failed);
                    }
                    // The wait for an unheard contact counts only after a drain that reached
                    // its relay, so a wallet that cannot collect never ends a pairing.
                    let mut ended = self.count_heard_wait(contacts, started).await?;
                    report.ended.append(&mut ended);
                }
                Err(error @ (MailboxError::Unreachable(_) | MailboxError::Lost(_))) => {
                    warn!(peer_relay = %host, error = %ErrorChain(&error), "home relay not answering");
                    report.not_reached = report.not_reached.saturating_add(identities.len());
                    self.relay_failed(&host).await?;
                    self.wallet
                        .emit(Event::HomeRelayUnreachable(UnreachableRelay {
                            relay: host.clone(),
                        }));
                    report.unreachable.push(host);
                }
                Err(error) => {
                    warn!(peer_relay = %host, error = %ErrorChain(&error), "mailbox drain failed");
                    report.not_reached = report.not_reached.saturating_add(identities.len());
                }
            }
        }
        report.quarantined = told.quarantined;
        report.quarantine_dropped = told.quarantine_dropped;
        report.buffered = told.buffered;
        debug!(count = report.mailboxes, "contact mailboxes collected");
        for ended in self.ended_since(&ended_before).await? {
            if !report.ended.contains(&ended) {
                report.ended.push(ended);
            }
        }
        match self.collect_in_person(relays).await {
            Ok(taken) => report.in_person = taken,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "in-person reply mailboxes not collected");
            }
        }
        match self.collect_epic1(relays).await {
            Ok(taken) => report.epic1 = taken,
            Err(error) => {
                warn!(error = %ErrorChain(&error), "epic1 mailboxes not collected");
            }
        }
        if let Err(error) = self.repost_replies(relays).await {
            warn!(error = %ErrorChain(&error), "pairing replies not posted again");
        }
        if let Err(error) = self.deliver_status(relays, explicit).await {
            warn!(error = %ErrorChain(&error), "pairing status not delivered");
        }
        // Already this run's turn: the outbox runs without taking it again.
        match self.deliver_outbox(relays, explicit).await {
            Ok(outbox) => report.delivered = outbox.delivered,
            Err(error) => warn!(error = %ErrorChain(&error), "contact outbox not run"),
        }
        Ok(report)
    }

    /// The ended pairings, leaving out those in `before`.
    async fn ended_since(
        &self,
        before: &BTreeSet<ContactId>,
    ) -> Result<Vec<super::EndedPairing>, ContactError> {
        let session = self.wallet.session()?;
        let before = before.clone();
        self.contact_work(move |_, _| {
            Ok(session.store.read(|repos| {
                Ok::<_, StoreError>(
                    repos
                        .contacts()?
                        .into_iter()
                        .filter(|record| !before.contains(&record.contact_id))
                        .filter_map(|record| {
                            record.facts.ended_reason.map(|reason| super::EndedPairing {
                                contact_id: record.contact_id,
                                reason,
                            })
                        })
                        .collect(),
                )
            })?)
        })
        .await
    }

    /// Ends pairings in progress that waited [`LATE_DRAIN_WAIT`] past their deadline (an
    /// invite's expiry and the clock skew, an answer's wait for its confirm) with no drain of
    /// their home relay, and cards shown in person but never paired.
    async fn end_expired_pairings(&self) -> Result<Vec<FailedPairing>, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session.store.write(|repos| {
                let mut ended = Vec::new();
                for pending in repos.pending_pairings()? {
                    let end = super::pairing::pending_deadline(&pending)
                        .and_then(|deadline| deadline.checked_add(LATE_DRAIN_WAIT).ok());
                    if end.is_some_and(|end| end > now) {
                        continue;
                    }
                    if let Some(Some(failed)) = end_late_pairing(repos, &pending, true)? {
                        ended.push(failed);
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
                        super::private::delete_secrets(repos, record.contact_id)?;
                    }
                }
                Ok::<_, StoreError>(ended)
            })?)
        })
        .await
    }

    /// Ends the pairings in progress among `pairings` whose deadline had passed when a drain of
    /// their home relay started at `started`: that drain was their last chance. An inviter
    /// whose confirm has not left yet keeps its pairing until [`LATE_DRAIN_WAIT`] runs out.
    async fn end_drained_pairings(
        &self,
        pairings: Vec<PairingId>,
        started: Timestamp,
    ) -> Result<Vec<FailedPairing>, ContactError> {
        if pairings.is_empty() {
            return Ok(Vec::new());
        }
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session.store.write(|repos| {
                let mut ended = Vec::new();
                for pairing_id in pairings {
                    let Some(pending) = repos.pending_pairing(pairing_id)? else {
                        continue;
                    };
                    let past = super::pairing::pending_deadline(&pending)
                        .is_some_and(|deadline| deadline <= started);
                    if !past {
                        continue;
                    }
                    if let Some(Some(failed)) = end_late_pairing(repos, &pending, false)? {
                        ended.push(failed);
                    }
                }
                Ok::<_, StoreError>(ended)
            })?)
        })
        .await
    }

    /// The mailboxes this cycle drains: the pending pairings', then the contacts', each in turn
    /// across cycles, leaving out relays in backoff, at most [`MAX_MAILBOXES_PER_DRAIN`] in all.
    /// Pairings take what the contacts leave, and at least all but [`CONTACT_SHARE`]. With
    /// `only`, just those of the contacts it holds, without moving the turns.
    async fn mailboxes_to_collect(
        &self,
        relays: &ContactRelays,
        trigger: CollectTrigger,
        only: Option<BTreeSet<ContactId>>,
    ) -> Result<Vec<Mailbox>, ContactError> {
        let network = self.wallet.config().network;
        let session = self.wallet.session()?;
        let relays_for_work = relays.clone();
        self.contact_work(move |ports, _| {
            let relays = relays_for_work;
            let now = ports.clock.now();
            session.store.write(|repos| {
                let backoffs: Backoffs = read_json(repos, BACKOFF_KEY)?;
                let wanted = |contact_id: ContactId| {
                    only.as_ref().is_none_or(|only| only.contains(&contact_id))
                };
                let mut pending =
                    pending_mailboxes(repos, network, &relays, &backoffs, now, &wanted)?;
                let mut contacts = contact_mailboxes(repos, &relays, now, &wanted)?;
                if trigger == CollectTrigger::Foreground {
                    keep_active_when_many(repos, &mut contacts, now)?;
                }
                let pending_room =
                    MAX_MAILBOXES_PER_DRAIN.saturating_sub(contacts.len().min(CONTACT_SHARE));
                let pending_taken = pending.len().min(pending_room);
                let taken = contacts
                    .len()
                    .min(MAX_MAILBOXES_PER_DRAIN.saturating_sub(pending_taken));
                if only.is_none() {
                    take_turn(repos, PENDING_CURSOR_KEY, &mut pending, pending_taken)?;
                    take_turn(repos, CURSOR_KEY, &mut contacts, taken)?;
                }
                pending.truncate(pending_taken);
                let mut mailboxes = pending;
                for (record, home, onion, salt, read) in contacts.into_iter().take(taken) {
                    if backoffs.waiting(&host_text(&home), now) {
                        continue;
                    }
                    let Some(keys) = box_keys(repos, &session.keychain, network, &record, salt)?
                    else {
                        continue;
                    };
                    mailboxes.push(Mailbox {
                        job: Job::Contact(record.contact_id, read == BoxRead::Current),
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

    /// Forgets every relay's backoff, so an explicit trigger tries them all at once.
    async fn reset_backoff(&self) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .write(|repos| write_json(repos, BACKOFF_KEY, &Backoffs::default()))?)
        })
        .await
    }

    async fn relay_answered(&self, host: &str) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
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
        let session = self.wallet.session()?;
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
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| Ok(session.store.read(|repos| repos.envelope_seen(&hash))?))
            .await
    }

    /// Remembers that an envelope with `hash` was handled.
    async fn remember(&self, hash: [u8; 32]) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            Ok(session
                .store
                .write(|repos| repos.remember_envelope(&hash, now))?)
        })
        .await
    }

    /// Counts one more hold of the envelope with `hash` and returns whether it may still be
    /// held: no more than [`WalletPolicy::contact_hold_attempts`] holds so far, and within
    /// [`WalletPolicy::contact_hold_patience`] of the first. The count is kept as
    /// `first-seen seconds:holds` under the envelope's hash.
    async fn count_hold(&self, hash: [u8; 32]) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        let policy = self.wallet.config().policy;
        self.contact_work(move |ports, _| {
            let now = u64::try_from(ports.clock.now().as_second()).unwrap_or(0);
            let key = held_key(hash);
            session.store.write(|repos| {
                let (first, holds) = repos
                    .setting(&key)?
                    .and_then(|text| {
                        let (first, holds) = text.split_once(':')?;
                        Some((first.parse::<u64>().ok()?, holds.parse::<u32>().ok()?))
                    })
                    .unwrap_or((now, 0));
                let holds = holds.saturating_add(1);
                let expired = hold_expired(first, holds, now, &policy);
                if expired {
                    repos.delete_setting(&key)?;
                } else {
                    repos.put_setting(&key, &format!("{first}:{holds}"))?;
                }
                Ok::<_, ContactError>(!expired)
            })
        })
        .await
    }

    /// Forgets the hold count of a settled envelope.
    async fn clear_hold(&self, hash: [u8; 32]) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            let key = held_key(hash);
            Ok(session.store.write(|repos| repos.delete_setting(&key))?)
        })
        .await
    }

    /// Forgets envelopes seen longer ago than a relay keeps a message, and a little longer, the
    /// payload acknowledgement marks and parked payloads as old, and the hold counts of messages
    /// first held longer ago than [`HELD_FORGOTTEN`], or [`HELD_KEPT_FOR_QUARANTINE`] while the
    /// host keeps a quarantine.
    async fn forget_old_envelopes(&self) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let policy = self.wallet.config().policy;
        let patience = policy.contact_hold_patience;
        let kept = match policy.quarantine_max_bytes {
            Some(_) => HELD_KEPT_FOR_QUARANTINE,
            None => HELD_FORGOTTEN,
        };
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            let cutoff = now.checked_sub(SEEN_LIFETIME).unwrap_or(now);
            let seconds = u64::try_from(now.as_second()).unwrap_or(0);
            session.store.write(|repos| {
                repos.forget_envelopes_before(cutoff)?;
                super::payload::forget_old_marks(repos, now, SEEN_LIFETIME)?;
                for (key, value) in repos.settings_with_prefix(HELD_PREFIX)? {
                    if hold_forgotten(&value, seconds, patience, kept) {
                        repos.delete_setting(&key)?;
                    }
                }
                Ok::<_, StoreError>(())
            })?;
            Ok(())
        })
        .await
    }

    /// Whether an envelope of the contact sealed at `sent_at` may be taken: sealed within
    /// [`MAX_ENVELOPE_AGE`] and not ahead of our clock by more than [`MAX_CLOCK_AHEAD`]. One
    /// without a send time is taken only from a contact that never sent one with it, as a
    /// wallet sealing before send times existed does.
    async fn sent_recently(
        &self,
        contact_id: ContactId,
        sent_at: Option<u64>,
    ) -> Result<bool, ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |ports, _| {
            let key = stamped_key(contact_id);
            let Some(sent_at) = sent_at else {
                let stamped = session.store.read(|repos| repos.setting(&key))?.is_some();
                if stamped {
                    warn!("envelope without a send time dropped");
                }
                return Ok(!stamped);
            };
            let now = u64::try_from(ports.clock.now().as_second()).unwrap_or(0);
            if sent_at > now.saturating_add(MAX_CLOCK_AHEAD.as_secs()) {
                warn!("envelope sealed ahead of our clock dropped");
                return Ok(false);
            }
            if now.saturating_sub(sent_at) > MAX_ENVELOPE_AGE.as_secs() {
                warn!("envelope sealed too long ago dropped");
                return Ok(false);
            }
            session.store.write(|repos| {
                if repos.setting(&key)?.is_none() {
                    repos.put_setting(&key, "1")?;
                }
                Ok::<_, StoreError>(())
            })?;
            Ok(true)
        })
        .await
    }

    /// Takes an envelope from a contact's mailbox. It must be signed by the contact's recorded
    /// key; an anonymous one is dropped and never attributed. A contact update or a newer card in
    /// the envelope refreshes the record within the limits of RFC 0002 8.5.
    pub(crate) async fn take_contact_message(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        current: bool,
        envelope: &[u8],
        told: &mut Told,
    ) -> Result<Handled, ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let found = {
            let session = std::sync::Arc::clone(&session);
            self.contact_work(move |_, _| {
                Ok(session.store.read(|repos| {
                    let Some(record) = repos.contact(contact_id)? else {
                        return Ok::<_, StoreError>(None);
                    };
                    let class = super::private::class_of(repos, &record)?;
                    Ok(Some((record, class)))
                })?)
            })
            .await?
        };
        let Some((record, class)) = found else {
            return Ok(Handled::Stored);
        };
        let Some(peer) = &record.peer else {
            return Ok(Handled::Stored);
        };
        let Ok(recorded) = lepic_contact::VerifyingKey::from_bytes(&peer.sig_key) else {
            return Ok(Handled::Stored);
        };
        if matches!(class, super::private::RecordClass::Unreadable) {
            warn!("envelope for a private pairing whose secrets do not open dropped");
            return Ok(Handled::Stored);
        }
        let keys = super::private::record_keys(&session.keychain, network, &record, &class)?;
        let Ok(sealed) = SealedEnvelope::decode(envelope, net) else {
            debug!("undecodable envelope in a contact mailbox dropped");
            return Ok(Handled::Stored);
        };
        let channel = class.private().and_then(|secrets| secrets.channel.clone());
        if class.private().is_some() && channel.is_none() {
            return Ok(Handled::Stored);
        }
        let Some((opened, native)) = self.open_contact_envelope(
            &sealed,
            &keys,
            &recorded,
            channel.as_ref(),
            contact_id,
            &mut told.unopenable,
        ) else {
            return Ok(Handled::Stored);
        };
        if !carries(channel.is_some(), opened.content.kind) {
            warn!("message of a kind its pairing does not carry dropped");
            return Ok(Handled::Stored);
        }
        if timed(opened.content.kind)
            && !self
                .sent_recently(contact_id, opened.content.sent_at)
                .await?
        {
            return Ok(Handled::Stored);
        }
        told.opened = true;
        // Ended is final: only answers to this wallet's own sends still settle.
        let ended = record.facts.ended_reason.is_some();
        if ended && opened.content.kind != MessageType::Slate {
            debug!("message for an ended pairing dropped");
            return Ok(Handled::Stored);
        }
        if !ended {
            self.heard(contact_id).await?;
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
            // Only a contact update carries the proof of the address its card names.
            let extras = if update.is_some() {
                lepic_contact::PairingExtras {
                    address_proof: opened.content.address_proof,
                    features: opened.content.features,
                    domain: opened.content.domain.clone(),
                }
            } else {
                lepic_contact::PairingExtras::default()
            };
            self.refresh_card_with(contact_id, card, update, extras)
                .await?;
        }
        self.mark_sealed_in(contact_id).await?;
        if current {
            self.forget_old_salt(contact_id).await?;
        }
        self.dispatch_contact_message(relays, contact_id, opened, native, envelope, told)
            .await
    }

    /// Hands an opened message from a contact to the engine part that takes its kind, against
    /// the contact's record as stored now. `native` marks a `lepic.v1` slate.
    async fn dispatch_contact_message(
        &self,
        relays: &ContactRelays,
        contact_id: ContactId,
        opened: Opened,
        native: bool,
        envelope: &[u8],
        told: &mut Told,
    ) -> Result<Handled, ContactError> {
        let record = {
            let session = self.wallet.session()?;
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
            MessageType::Slate => {
                self.take_contact_slate(&record, opened.content, native, told)
                    .await?
            }
            MessageType::Notice => {
                self.take_contact_notice(&record, &opened.content.body, told)
                    .await?
            }
            MessageType::KeyCheck => self.take_key_check(&record, envelope).await?,
            MessageType::KeyCheckAnswer => self.take_key_check_answer(&record, envelope).await?,
            MessageType::AppPayload => {
                self.take_contact_payload(&record, opened.content, envelope, &mut told.parked)
                    .await?
            }
            MessageType::ContactCheck => self.take_contact_check(relays, &record).await?,
            MessageType::PairingReply | MessageType::PairingConfirm => Handled::Stored,
        })
    }

    /// Opens an envelope from a contact's mailbox, signed by the contact's `recorded` key and
    /// under `channel` for a private pairing; `None` drops it. The contact is told to the host
    /// as sealed unopenable once a cycle, in `told`. The flag marks a native slate (type `0A`),
    /// which only a base pairing carries.
    fn open_contact_envelope(
        &self,
        sealed: &SealedEnvelope<'_>,
        keys: &crate::key_schedule::ContactKeys,
        recorded: &lepic_contact::VerifyingKey,
        channel: Option<&lepic_contact::ChannelKey>,
        contact_id: ContactId,
        told: &mut std::collections::BTreeSet<ContactId>,
    ) -> Option<(Opened, bool)> {
        let opened = match channel {
            None => super::native::open_any_from(sealed, &enc_secret(keys), recorded),
            Some(channel) => sealed
                .open_from_psk(&enc_secret(keys), recorded, channel)
                .map(|opened| (opened, false)),
        };
        let opened = match opened {
            Ok(opened) => opened,
            Err(lepic_contact::DecodeError::KeyChanged) => {
                // Signed by a key that is not the contact's: never the contact's news.
                info!("envelope signed by another key dropped");
                return None;
            }
            Err(lepic_contact::DecodeError::CannotOpen) => {
                debug!("envelope in a contact mailbox did not open");
                // Once a cycle per contact, however much junk the mailbox holds.
                if told.insert(contact_id) {
                    self.wallet
                        .emit(Event::SealedUnopenable(ContactEvent { contact_id }));
                }
                return None;
            }
            Err(_) => {
                debug!("malformed envelope in a contact mailbox dropped");
                return None;
            }
        };
        if opened.0.sender.is_none() {
            debug!("anonymous envelope in a contact mailbox dropped");
            return None;
        }
        Some(opened)
    }

    /// Replaces the contact's card with `card` when it carries the same keys and kind and a
    /// higher sequence number. Only a contact update (`update` holds the relays) may change the
    /// card's mailbox, within the update limits of RFC 0002 8.5, and only on the same relay: a
    /// card naming a mailbox on another relay is stored, the mailbox in use stays, and
    /// [`Event::ContactRelayMoveRequested`] tells the host, which may apply the move with
    /// [`ContactBook::apply_relay_move`]. What the contact is plays no part. A card in any
    /// other envelope that names another mailbox is ignored.
    pub(crate) async fn refresh_card(
        &self,
        contact_id: ContactId,
        card: ContactCard,
        update: Option<&ContactRelays>,
    ) -> Result<(), ContactError> {
        self.refresh_card_with(
            contact_id,
            card,
            update,
            lepic_contact::PairingExtras::default(),
        )
        .await
    }

    /// [`Self::refresh_card`] with what the update carried beside the card: a proof that
    /// verifies sets the contact's payments address to the one the card names; without one,
    /// or with one that does not verify, the stored address stays.
    async fn refresh_card_with(
        &self,
        contact_id: ContactId,
        card: ContactCard,
        update: Option<&ContactRelays>,
        extras: lepic_contact::PairingExtras,
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        let news = CardNews {
            contact_id,
            card,
            relays: update.cloned(),
            extras,
        };
        let updated = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let address = |repos: &dyn Repositories| {
                        Ok::<_, StoreError>(
                            repos
                                .contact(contact_id)?
                                .and_then(|record| record.facts.payments_address),
                        )
                    };
                    let before = address(repos)?;
                    let stored = store_card_news(repos, &session.keychain, network, news, now)?;
                    let moved = stored != CardStored::Unchanged && address(repos)? != before;
                    if moved && let Some(record) = repos.contact(contact_id)? {
                        super::status::learn_from_pairing(repos, &record, network, now)?;
                    }
                    Ok::<_, ContactError>((stored, moved))
                })
            })
            .await?;
        let (stored, moved) = updated;
        if stored != CardStored::Unchanged {
            info!("contact updated");
            self.wallet.emit(Event::ContactUpdated(ContactUpdate::of(
                contact_id,
                ContactChange::Card,
            )));
        }
        if moved {
            self.wallet.emit(Event::ContactUpdated(ContactUpdate::of(
                contact_id,
                ContactChange::Address,
            )));
        }
        if let CardStored::MoveRequested(host) = stored {
            self.wallet
                .emit(Event::ContactRelayMoveRequested(RelayMoveRequest {
                    contact_id,
                    host,
                }));
        }
        Ok(())
    }

    /// Moves a contact to the relay its card asked for in a contact update, which raised
    /// [`Event::ContactRelayMoveRequested`]: the contact's mailbox there takes our messages,
    /// the outbox is redirected, our own card is re-signed for our mailbox on that relay and
    /// queued for the contact in a contact update, and our previous mailbox is still collected
    /// for seven days. Which relays to follow is the host's choice; nothing here judges `host`.
    ///
    /// Fails with [`ContactError::RelayMoveNotRequested`] unless `host` (`domain:port`) is the
    /// relay of the mailbox the contact's stored card names and differs from the relay in use,
    /// that is unless it is the contact's [`ContactView::requested_relay`];
    /// [`ContactError::UnknownContact`]; [`ContactError::Ended`] for a pairing that ended; and as
    /// the store does.
    ///
    /// [`ContactView::requested_relay`]: crate::ContactView::requested_relay
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn apply_relay_move(
        &self,
        contact_id: ContactId,
        host: &str,
    ) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        let host = host.to_owned();
        self.contact_work(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| {
                store_relay_move(
                    repos,
                    &ports.rng,
                    &session.keychain,
                    network,
                    contact_id,
                    &host,
                    now,
                )
            })
        })
        .await?;
        info!("contact home relay moved");
        Ok(())
    }

    /// Moves our mailbox of each contact paired in person to one from a fresh box salt and
    /// tells the contact with a contact update (RFC 0002 7.4): anyone who saw the card QR knows
    /// the old one. The old mailbox is still read until the contact writes to the new one.
    async fn move_in_person_mailboxes(&self, relays: &ContactRelays) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        let session = self.wallet.session()?;
        let relays = relays.clone();
        let moved = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let mut moved = 0usize;
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
                            .map_err(ContactError::StoredData)?;
                        let mut fields = own.fields().clone();
                        fields.mailbox =
                            lepic_contact::MailboxAddress::new(&ours.address().to_string())
                                .map_err(ContactError::Name)?;
                        fields.seq = fields.seq.saturating_add(1);
                        let signer = super::keys::signing_key(&keys);
                        let card = ContactCard::sign(net, fields, &signer)
                            .map_err(ContactError::Encode)?;
                        let peer_card = ContactCard::decode(&peer.bytes, net)
                            .map_err(ContactError::StoredData)?;
                        let envelope = lepic_contact::seal_contact_update(
                            &peer_card, &card, &signer, &mut rng,
                        )
                        .map_err(ContactError::Encode)?;
                        let old = OldSalt {
                            salt: hex::encode(&record.box_salt),
                        };
                        write_json(repos, &old_salt_key(record.contact_id), &old)?;
                        let mut record = record;
                        record.box_salt = salt;
                        record.own_card = card.as_bytes().to_vec();
                        record.updated_at = now;
                        repos.put_contact(&record)?;
                        mailbox.our_mailbox = ours.address().to_string();
                        // The update is queued in the same write as the move, so the move is
                        // never made without it.
                        repos.enqueue_contact_outbox(&lepic_store::ContactOutboxEntry {
                            contact_id: record.contact_id,
                            slate_id: uuid::Uuid::from_bytes(record.contact_id.0),
                            stage: lepic_store::SlateStage::Standard1,
                            payload: lepic_contact::armor(&envelope),
                            destination: mailbox.peer_mailbox.clone(),
                            attempts: 0,
                            next_try_at: now,
                            state: lepic_store::ContactOutboxState::Queued,
                            created_at: now,
                            delivered_at: None,
                        })?;
                        repos.put_contact_mailbox(&mailbox)?;
                        moved = moved.saturating_add(1);
                    }
                    Ok(moved)
                })
            })
            .await?;
        if moved > 0 {
            info!(count = moved, "in-person mailboxes moved");
        }
        Ok(())
    }

    /// Gives every contact pairing our card with the new payments address (tag 09) and its
    /// proof after the wallet's relay changed, once for each payments address. Queued in one
    /// write per contact.
    async fn send_address_cards(&self, relays: &ContactRelays) -> Result<(), ContactError> {
        let network = self.wallet.config().network;
        let features = self.wallet.config().pairing_features();
        let session = self.wallet.session()?;
        let payments = super::address_proof::Payments::of(&session.keychain, network, relays)?;
        let domain = super::address_proof::domain_signer(
            &session.keychain,
            network,
            self.wallet.config().domain.as_deref(),
        )?;
        let sent = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                session.store.write(|repos| {
                    let at = super::address_proof::CardUpdate {
                        keychain: &session.keychain,
                        network,
                        payments: &payments,
                        features,
                        domain: domain.as_ref(),
                        now,
                    };
                    super::address_proof::queue_address_cards(repos, &ports.rng, &at)
                })
            })
            .await?;
        if sent > 0 {
            info!(count = sent, "address cards queued");
        }
        Ok(())
    }

    /// The contact wrote to the mailbox our current card names, so it took our new card: the
    /// mailbox of the old box salt is no longer read.
    async fn forget_old_salt(&self, contact_id: ContactId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
        self.contact_work(move |_, _| {
            Ok(session
                .store
                .write(|repos| repos.delete_setting(&old_salt_key(contact_id)))?)
        })
        .await
    }

    pub(crate) async fn mark_sealed_in(&self, contact_id: ContactId) -> Result<(), ContactError> {
        let session = self.wallet.session()?;
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

/// Whether something waits on the contact (RFC 0002 8.4): an outbox entry not yet delivered,
/// a slate this wallet exchanged with it whose transaction waits for an answer or a posting,
/// such as a payment sent through its mailbox, or an invoice from it waiting for the user.
fn has_pending(repos: &dyn Repositories, contact_id: ContactId) -> Result<bool, StoreError> {
    for stored in repos.contact_outbox(contact_id)? {
        if stored.entry.state == ContactOutboxState::Queued {
            return Ok(true);
        }
        for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
            if repos
                .transaction_by_slate(stored.entry.slate_id, direction)?
                .is_some_and(|tx| matches!(tx.entry.state, TxState::Sent | TxState::Received))
            {
                return Ok(true);
            }
        }
    }
    for invoice in repos.pending_invoices()? {
        if invoice.status == PendingInvoiceStatus::Parked
            && lepic_wallet::contact_link::slate_contact(repos, invoice.slate_id)?
                == Some(contact_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Turns `items` to this cycle's start, kept under `key`, and moves the start past the `taken`
/// first of them.
fn take_turn<T>(
    repos: &mut dyn Repositories,
    key: &str,
    items: &mut [T],
    taken: usize,
) -> Result<(), StoreError> {
    let count = items.len();
    let cursor = repos
        .setting(key)?
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(0);
    let start = cursor.checked_rem(count).unwrap_or(0);
    items.rotate_left(start);
    let next = start.saturating_add(taken).checked_rem(count).unwrap_or(0);
    repos.put_setting(key, &next.to_string())
}

/// The reply and confirm mailboxes of the pairings in progress `wanted` holds, leaving out
/// relays in backoff.
fn pending_mailboxes(
    repos: &dyn Repositories,
    network: lepic_primitives::params::Network,
    relays: &ContactRelays,
    backoffs: &Backoffs,
    now: Timestamp,
    wanted: &impl Fn(ContactId) -> bool,
) -> Result<Vec<Mailbox>, ContactError> {
    let mut mailboxes = Vec::new();
    for pending in repos.pending_pairings()? {
        if !wanted(pending.contact_id) {
            continue;
        }
        let invite = lepic_contact::Invite::decode(&pending.invite, contact_network(network))
            .map_err(ContactError::StoredData)?;
        let home = endpoint_for(invite.fields().home_relay.as_str(), relays)?;
        let (seed, job) = match pending.role {
            PairingRole::Inviter => (pending.secrets.code, Job::Reply(pending.pairing_id)),
            PairingRole::Invitee => (pending.secrets.rc, Job::Confirm(pending.pairing_id)),
        };
        let Some(seed) = seed else {
            continue;
        };
        if backoffs.pending_waiting(&host_text(&home), now) {
            continue;
        }
        let (identity, _) = pairing_mailbox(&seed, network, &home)?;
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
    Ok(mailboxes)
}

/// The mailboxes of the paired contacts `wanted` holds: our previous home while it is drained,
/// after following a contact's move or moving our own, the mailbox of an old box salt while it
/// is read, and the current one.
fn contact_mailboxes(
    repos: &dyn Repositories,
    relays: &ContactRelays,
    now: Timestamp,
    wanted: &impl Fn(ContactId) -> bool,
) -> Result<Vec<ContactBox>, ContactError> {
    let mut contacts = Vec::new();
    for record in repos.contacts()? {
        if record.peer.is_none() || !wanted(record.contact_id) {
            continue;
        }
        // A pairing ended by this side's mismatch finalizes nothing: an answer waiting in its
        // mailbox stays there, and the send it answers can still be cancelled.
        if record.facts.ended_reason == Some(lepic_store::PairingEndReason::Mismatch) {
            continue;
        }
        let Some(mailbox) = repos.contact_mailbox(record.contact_id)? else {
            continue;
        };
        let home = endpoint_for(&mailbox.home_relay, relays)?;
        if let Some(previous) = mailbox.previous.filter(|previous| previous.until > now) {
            let old = endpoint_for(&previous.relay, relays)?;
            contacts.push((
                record.clone(),
                old,
                None,
                record.box_salt,
                BoxRead::PreviousHome,
            ));
        }
        let old_salt = repos
            .setting(&old_salt_key(record.contact_id))?
            .and_then(|text| serde_json::from_str::<OldSalt>(&text).ok())
            .and_then(|old| hex::decode_array(&old.salt).ok());
        if let Some(salt) = old_salt {
            contacts.push((
                record.clone(),
                home.clone(),
                mailbox.onion.clone(),
                salt,
                BoxRead::OldSalt,
            ));
        }
        let salt = record.box_salt;
        contacts.push((record, home, mailbox.onion, salt, BoxRead::Current));
    }
    Ok(contacts)
}

/// Keeps only the active contacts, those something waits on, and previous homes still drained
/// when the mailboxes are on more than [`FEW_RELAYS`] relays. A contact that missed our move is
/// inactive by nature: it is away, and writes only to our previous home when it is back.
fn keep_active_when_many(
    repos: &dyn Repositories,
    contacts: &mut Vec<ContactBox>,
    now: Timestamp,
) -> Result<(), StoreError> {
    let distinct: std::collections::BTreeSet<String> = contacts
        .iter()
        .map(|(_, home, _, _, _)| host_text(home))
        .collect();
    if distinct.len() > FEW_RELAYS {
        let mut pending = Vec::new();
        for (record, _, _, _, _) in contacts.iter() {
            if !pending.contains(&record.contact_id) && has_pending(repos, record.contact_id)? {
                pending.push(record.contact_id);
            }
        }
        contacts.retain(|(record, _, _, _, read)| {
            *read == BoxRead::PreviousHome
                || active(record, now)
                || pending.contains(&record.contact_id)
        });
    }
    Ok(())
}

/// Our keys for the contact's mailbox read with `salt`; `None` for a private pairing whose
/// secrets do not open, since nothing is taken through it.
fn box_keys(
    repos: &dyn Repositories,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    record: &ContactRecord,
    salt: [u8; 16],
) -> Result<Option<crate::key_schedule::ContactKeys>, ContactError> {
    Ok(Some(match super::private::class_of(repos, record)? {
        super::private::RecordClass::Contact => {
            contact_keys(keychain, network, record.account, record.slot, salt)?
        }
        class @ super::private::RecordClass::Private(_) => {
            super::private::record_keys(keychain, network, record, &class)?
        }
        super::private::RecordClass::Unreadable => return Ok(None),
    }))
}

/// Whether a message of `kind` is taken only when sealed recently. Updates and key checks
/// carry their own order: a card's seq, a check's open state.
fn timed(kind: MessageType) -> bool {
    matches!(
        kind,
        MessageType::Slate
            | MessageType::Notice
            | MessageType::AppPayload
            | MessageType::ContactCheck
    )
}

/// Whether a pairing carries a message of `kind`: a private pairing carries the host app's
/// payloads and the unpaired notice only; a contact carries every kind, payloads included.
fn carries(private: bool, kind: MessageType) -> bool {
    match (private, kind) {
        (true, MessageType::AppPayload | MessageType::Notice) | (false, _) => true,
        (true, _) => false,
    }
}

/// A card to refresh a contact's record with, and the relays when it came in a contact update.
struct CardNews {
    contact_id: ContactId,
    card: ContactCard,
    relays: Option<ContactRelays>,
    extras: lepic_contact::PairingExtras,
}

/// What storing a card did to the contact's record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CardStored {
    /// Nothing changed.
    Unchanged,
    /// The newer card was stored, and the mailbox moved with it when it stayed on its relay.
    Updated,
    /// The newer card was stored; it names a mailbox on another relay, `domain:port`, and the
    /// mailbox stays until the host applies the move.
    MoveRequested(String),
}

/// Stores the card of `news` as [`ContactBook::refresh_card`] describes.
fn store_card_news(
    repos: &mut dyn Repositories,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    news: CardNews,
    now: Timestamp,
) -> Result<CardStored, ContactError> {
    let CardNews {
        contact_id,
        card,
        relays,
        extras,
    } = news;
    let Some(mut record) = repos.contact(contact_id)? else {
        return Ok(CardStored::Unchanged);
    };
    let Some(peer) = &record.peer else {
        return Ok(CardStored::Unchanged);
    };
    if !newer_card(peer, &card) {
        return Ok(CardStored::Unchanged);
    }
    let update = relays.is_some();
    if update && !super::private::is_private(&record) {
        let proven = super::address_proof::proven_in_update(
            keychain,
            network,
            &record,
            &card,
            extras.address_proof.as_ref(),
        )?;
        super::pairing::set_proven(&mut record, proven);
        if let Some(features) = extras.features {
            record.facts.peer_features = features;
        }
        // The latest update speaks for the contact: an update without a claim drops the one
        // stored.
        record.facts.peer_domain = extras.domain.as_ref().map(super::pairing::claim_bytes);
    }
    let Some(mut mailbox) = repos.contact_mailbox(contact_id)? else {
        return Ok(CardStored::Unchanged);
    };
    let peer_mailbox = card.fields().mailbox.as_str().to_owned();
    let moved = peer_mailbox != mailbox.peer_mailbox;
    if !update {
        if moved {
            warn!("card naming another mailbox outside an update ignored");
            return Ok(CardStored::Unchanged);
        }
        record.peer = Some(peer_card(&card));
        repos.put_contact(&record)?;
        return Ok(CardStored::Updated);
    }
    if !within_update_limits(repos, contact_id, now.as_second())? {
        warn!("contact update over the limits dropped");
        return Ok(CardStored::Unchanged);
    }
    EpicboxAddress::parse(&peer_mailbox, relay_network(network))
        .map_err(|_| ContactError::RelayAddress)?;
    record.peer = Some(peer_card(&card));
    repos.put_contact(&record)?;
    // A move to another relay waits for the host: which relays to follow is its choice.
    if let Some(host) = requested_host(&card, &mailbox, network) {
        info!("contact asked to move to another relay");
        return Ok(CardStored::MoveRequested(host));
    }
    if moved {
        repos.redirect_contact_outbox(contact_id, &peer_mailbox)?;
        mailbox.peer_mailbox = peer_mailbox;
        repos.put_contact_mailbox(&mailbox)?;
    }
    Ok(CardStored::Updated)
}

/// Moves the contact's mailbox to the one its stored card names, on the relay `host` the card
/// asked for, in one write: the outbox is redirected, our own card is re-signed for our mailbox
/// there and queued for the contact in a contact update, and the previous home is still
/// drained for [`PREVIOUS_HOME_KEPT`].
fn store_relay_move(
    repos: &mut dyn Repositories,
    rng: &lepic_wallet::SharedRng,
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    contact_id: ContactId,
    host: &str,
    now: Timestamp,
) -> Result<(), ContactError> {
    let mut record = repos
        .contact(contact_id)?
        .ok_or(ContactError::UnknownContact)?;
    let peer = record.peer.as_ref().ok_or(ContactError::UnknownContact)?;
    let mut mailbox = repos
        .contact_mailbox(contact_id)?
        .ok_or(ContactError::UnknownContact)?;
    if super::status::status_of(&record) == super::PairingStatus::Ended {
        return Err(ContactError::Ended);
    }
    let card = ContactCard::decode(&peer.bytes, contact_network(network))
        .map_err(ContactError::StoredData)?;
    if requested_host(&card, &mailbox, network).as_deref() != Some(host) {
        return Err(ContactError::RelayMoveNotRequested);
    }
    let peer_mailbox = card.fields().mailbox.as_str().to_owned();
    let relay = EpicboxAddress::parse(&peer_mailbox, relay_network(network))
        .map_err(|_| ContactError::RelayAddress)?;
    let (own_card, ours, signer) = moved_own_card(keychain, network, &record, &relay)?;
    let envelope = lepic_contact::seal_contact_update(
        &card,
        &own_card,
        &signer,
        &mut super::LockedRng(&mut **rng.lock()),
    )
    .map_err(ContactError::Encode)?;
    record.own_card = own_card.as_bytes().to_vec();
    mailbox.previous = Some(lepic_store::PreviousHome {
        relay: mailbox.home_relay.clone(),
        peer_mailbox: mailbox.peer_mailbox.clone(),
        our_mailbox: mailbox.our_mailbox.clone(),
        until: now.checked_add(PREVIOUS_HOME_KEPT).unwrap_or(now),
    });
    mailbox.home_relay = relay_host(&relay);
    mailbox.our_mailbox = ours.to_string();
    mailbox.peer_mailbox = peer_mailbox.clone();
    repos.redirect_contact_outbox(contact_id, &peer_mailbox)?;
    repos.put_contact(&record)?;
    repos.put_contact_mailbox(&mailbox)?;
    // Our new mailbox reaches the contact at once, in the same write.
    repos.enqueue_contact_outbox(&update_entry(contact_id, &envelope, peer_mailbox, now))?;
    Ok(())
}

/// Whether `card` may replace the contact's `peer` card: the same keys and kind and a higher
/// sequence number. Addresses may change by a card; keys and kind never do (RFC 0002 8.5).
fn newer_card(peer: &lepic_store::PeerCard, card: &ContactCard) -> bool {
    let fields = card.fields();
    super::pairing::same_keys(peer, card)
        && super::pairing::store_kind(fields.kind) == peer.kind
        && fields.seq > peer.seq
}

/// Our card re-signed for a move to the relay of `relay`: our mailbox there and the
/// next sequence number. Returns the card, its mailbox and the key it is signed with.
fn moved_own_card(
    keychain: &lepic_keychain::Keychain,
    network: lepic_primitives::params::Network,
    record: &ContactRecord,
    relay: &EpicboxAddress,
) -> Result<(ContactCard, EpicboxAddress, lepic_contact::SigningKey), ContactError> {
    let net = contact_network(network);
    let keys = contact_keys(
        keychain,
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
    let own = ContactCard::decode(&record.own_card, net).map_err(ContactError::StoredData)?;
    let mut own_fields = own.fields().clone();
    own_fields.mailbox =
        lepic_contact::MailboxAddress::new(&ours.to_string()).map_err(ContactError::Name)?;
    own_fields.seq = own_fields.seq.saturating_add(1);
    let signer = super::keys::signing_key(&keys);
    let own_card = ContactCard::sign(net, own_fields, &signer).map_err(ContactError::Encode)?;
    Ok((own_card, ours, signer))
}

/// The outbox entry that carries a contact update `envelope` to the contact's `destination`.
pub(crate) fn update_entry(
    contact_id: ContactId,
    envelope: &[u8],
    destination: String,
    now: Timestamp,
) -> lepic_store::ContactOutboxEntry {
    lepic_store::ContactOutboxEntry {
        contact_id,
        slate_id: uuid::Uuid::from_bytes(contact_id.0),
        stage: lepic_store::SlateStage::Standard1,
        payload: lepic_contact::armor(envelope),
        destination,
        attempts: 0,
        next_try_at: now,
        state: lepic_store::ContactOutboxState::Queued,
        created_at: now,
        delivered_at: None,
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
    let key = hex::encode(&contact_id.0);
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

/// Whether a message first held at `first` (seconds) and held `holds` times by `now` may no
/// longer be kept for the next cycle under `policy`.
fn hold_expired(first: u64, holds: u32, now: u64, policy: &WalletPolicy) -> bool {
    let patience = policy.contact_hold_patience.as_secs();
    holds > policy.contact_hold_attempts
        || now.saturating_sub(first) >= patience
        // A clock set back since the first hold.
        || first > now.saturating_add(patience)
}

/// Whether the hold count `value` (`first-seen seconds:holds`) may be forgotten at `now`: first
/// held longer ago than `kept`, ahead of a clock set back by more than `patience`, or unreadable.
fn hold_forgotten(value: &str, now: u64, patience: Duration, kept: Duration) -> bool {
    let Some(first) = value
        .split_once(':')
        .and_then(|(first, _)| first.parse::<u64>().ok())
    else {
        return true;
    };
    now.saturating_sub(first) > kept.as_secs() || first > now.saturating_add(patience.as_secs())
}

/// Whether `error` passes by itself: the node, a relay or the store did not answer, or the
/// wallet is locked. A message that fails so is kept for the next cycle without counting a
/// hold, as the payments inbox keeps one; any other failure counts.
pub(crate) fn passes(error: &ContactError) -> bool {
    match error {
        ContactError::Offline | ContactError::EpicboxOff => true,
        ContactError::Wallet(error) => chain_passes(error),
        error => chain_passes(error),
    }
}

/// Whether any error in the chain from `error` passes, as [`passes`] says.
fn chain_passes(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(error) = next {
        let passing = if let Some(error) = error.downcast_ref::<lepic_wallet::WalletError>() {
            matches!(error, lepic_wallet::WalletError::Locked)
        } else if let Some(error) = error.downcast_ref::<StoreError>() {
            matches!(
                error,
                StoreError::Database(_)
                    | StoreError::Io { .. }
                    | StoreError::Randomness(_)
                    | StoreError::Poisoned
            )
        } else if let Some(error) = error.downcast_ref::<lepic_node::NodeError>() {
            error.is_transient()
        } else if let Some(error) = error.downcast_ref::<lepic_epicbox::MailboxError>() {
            matches!(
                error,
                lepic_epicbox::MailboxError::Unreachable(_)
                    | lepic_epicbox::MailboxError::Lost(_)
                    | lepic_epicbox::MailboxError::Unanswered(_)
            )
        } else {
            false
        };
        if passing {
            return true;
        }
        next = error.source();
    }
    false
}

/// Hands each drained message to the engine and acknowledges it once its effect is stored.
struct Collector<'a, N, S: StoreOpener, V> {
    wallet: &'a ContactBook<'a, N, S, V>,
    relays: &'a ContactRelays,
    jobs: Vec<Job>,
    messages: usize,
    paired: usize,
    failed: Vec<FailedPairing>,
    told: &'a mut Told,
}

/// What a cycle told the host and counted: the contacts told about, so each is told once a
/// cycle, and how the message in hand went.
#[derive(Default)]
pub(crate) struct Told {
    /// Reported with [`Event::SealedUnopenable`].
    unopenable: BTreeSet<ContactId>,
    /// Reported with [`Event::ContactPayloadsParked`].
    parked: BTreeSet<ContactId>,
    /// The message in hand opened under the contact's key and is one the contact may send now.
    pub(crate) opened: bool,
    /// Why the message in hand, reported stored, could not be taken.
    pub(crate) dropped: Option<QuarantineReason>,
    quarantined: usize,
    quarantine_dropped: usize,
    pub(crate) buffered: usize,
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
            // Armored text of either marker pair; the envelope's type says what it holds.
            if classify(text.as_bytes()) != Ok(PaymentFile::Armour) {
                debug!("plain payload in a pairing or contact mailbox dropped");
                return Handled::Stored;
            }
            let Ok(envelope) = dearmor(text) else {
                return Handled::Stored;
            };
            match self.take(job, &envelope).await {
                Ok(handled) => handled,
                Err(error) => self.hold_or_settle(job, &envelope, &error).await,
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
    /// Keeps a message whose handling failed for the next cycle. A failure that passes
    /// ([`passes`]) keeps it without counting; any other keeps it until it has been held
    /// [`WalletPolicy::contact_hold_attempts`] times or [`WalletPolicy::contact_hold_patience`]
    /// has passed since it was first held: then it is settled, so the relay keeps nothing
    /// behind it waiting, and a contact's message that opened goes to quarantine when the host
    /// keeps one. An error counting the attempt itself does not stop the message being kept.
    async fn hold_or_settle(&mut self, job: Job, envelope: &[u8], error: &ContactError) -> Handled {
        if passes(error) {
            warn!(error = %ErrorChain(error), "mailbox message kept until the failure passes");
            return Handled::Later;
        }
        let hash = envelope_hash(envelope);
        match self.wallet.count_hold(hash).await {
            Ok(true) => {
                warn!(error = %ErrorChain(error), "mailbox message kept for later");
                Handled::Later
            }
            Ok(false) => {
                if self.told.opened
                    && let Some(result) = self
                        .quarantine(job, envelope, QuarantineReason::HoldBound)
                        .await
                {
                    warn!(error = %ErrorChain(error), "mailbox message settled after being held too long");
                    return match result {
                        Ok(()) => Handled::Stored,
                        Err(error) => {
                            warn!(error = %ErrorChain(&error), "mailbox message not quarantined, kept for later");
                            Handled::Later
                        }
                    };
                }
                warn!(error = %ErrorChain(error), "mailbox message dropped after being held too long");
                if let Err(error) = self.wallet.remember(hash).await {
                    warn!(error = %ErrorChain(&error), "dropped mailbox message not remembered");
                }
                Handled::Stored
            }
            Err(count_error) => {
                warn!(error = %ErrorChain(error), count = %ErrorChain(&count_error), "mailbox message kept for later, holds not counted");
                Handled::Later
            }
        }
    }

    /// Keeps a contact's message in quarantine, with its marks settled as for a stored message.
    /// `None` when there is nothing to do: not a contact's message, or the host keeps none.
    async fn quarantine(
        &mut self,
        job: Job,
        envelope: &[u8],
        reason: QuarantineReason,
    ) -> Option<Result<(), ContactError>> {
        let Job::Contact(contact_id, current) = job else {
            return None;
        };
        let cap = self.wallet.wallet.config().policy.quarantine_max_bytes?;
        let message = Message {
            hash: envelope_hash(envelope),
            envelope,
            contact_id,
            current,
            reason,
        };
        let kept = match self.wallet.quarantine_message(cap, message).await {
            Ok(kept) => kept,
            Err(error) => return Some(Err(error)),
        };
        self.told.quarantine_dropped = self.told.quarantine_dropped.saturating_add(kept.dropped);
        if kept.kept {
            self.told.quarantined = self.told.quarantined.saturating_add(1);
            info!(reason = reason.name(), "contact message quarantined");
        } else {
            warn!(
                reason = reason.name(),
                "contact message too large for the quarantine dropped"
            );
        }
        Some(Ok(()))
    }

    async fn take(&mut self, job: Job, envelope: &[u8]) -> Result<Handled, ContactError> {
        self.told.opened = false;
        self.told.dropped = None;
        let hash = envelope_hash(envelope);
        if self.wallet.seen_before(hash).await? {
            return Ok(Handled::Stored);
        }
        // A payload left for its cap stays without being opened again while the cap holds.
        if let Job::Contact(contact_id, _) = job
            && self.wallet.payload_parked(hash, contact_id).await?
        {
            self.wallet.tell_parked(contact_id, &mut self.told.parked);
            return Ok(Handled::Later);
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
            Job::Contact(contact_id, current) => {
                self.wallet
                    .take_contact_message(self.relays, contact_id, current, envelope, self.told)
                    .await?
            }
        };
        if handled == Handled::Stored {
            let quarantined = match self.told.dropped.take() {
                Some(reason) => self.quarantine(job, envelope, reason).await,
                None => None,
            };
            match quarantined {
                Some(result) => result?,
                None => {
                    self.wallet.remember(hash).await?;
                    self.wallet.clear_hold(hash).await?;
                }
            }
        }
        Ok(handled)
    }

    fn count(&mut self, taken: Result<Taken, ContactError>) -> Result<Handled, ContactError> {
        match &taken {
            Ok(Taken::Paired(_)) => self.paired = self.paired.saturating_add(1),
            Ok(Taken::Failed(Some(failed))) => self.failed.push(*failed),
            _ => {}
        }
        taken.map(|_| Handled::Stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(byte: u8, created_at: Timestamp) -> ContactRecord {
        ContactRecord {
            contact_id: ContactId([byte; 16]),
            account: lepic_store::AccountIndex(0),
            slot: 0,
            box_salt: [0; 16],
            own_card: Vec::new(),
            peer: None,
            alternate: None,
            label: String::new(),
            state: ContactState::Verified,
            sas: None,
            verified_at: None,
            allow_invoices: false,
            seal: SealMode::On,
            last_sealed_in: None,
            app_contact: None,
            imported_from_backup: false,
            created_at,
            updated_at: created_at,
            facts: lepic_store::PairingFacts::default(),
        }
    }

    /// On more than a few relays a foreground tick drops the quiet contacts' mailboxes but
    /// keeps a previous home still drained: a contact that missed our move is quiet by nature.
    #[test]
    fn a_drained_previous_home_is_kept_on_many_relays() {
        let now = Timestamp::from_second(100 * 24 * 60 * 60).unwrap();
        let long_ago = Timestamp::from_second(0).unwrap();
        let relay = |host: &str| {
            RelayEndpoint::new(
                lepic_epicbox::Domain::parse(host).unwrap(),
                Some(80),
                lepic_epicbox::Security::Plain,
            )
        };
        let quiet = record(1, long_ago);
        let fresh = record(2, now);
        let mut boxes: Vec<ContactBox> = vec![
            (
                quiet.clone(),
                relay("a.test"),
                None,
                [0; 16],
                BoxRead::Current,
            ),
            (
                quiet.clone(),
                relay("b.test"),
                None,
                [0; 16],
                BoxRead::PreviousHome,
            ),
            (quiet, relay("c.test"), None, [0; 16], BoxRead::OldSalt),
            (fresh, relay("d.test"), None, [0; 16], BoxRead::Current),
        ];
        let store =
            lepic_store::MemoryStore::new(lepic_store::StoreKeys::from_bytes([1; 32], [1; 32]));
        store
            .read(|repos| keep_active_when_many(repos, &mut boxes, now))
            .unwrap();
        let kept: Vec<_> = boxes
            .iter()
            .map(|(record, _, _, _, read)| (record.contact_id.0[0], *read))
            .collect();
        assert_eq!(
            kept,
            vec![(1, BoxRead::PreviousHome), (2, BoxRead::Current)]
        );
    }

    #[test]
    fn a_message_is_held_for_a_few_tries_and_a_few_minutes() {
        let now = 1_000_000;
        let policy = WalletPolicy::DEFAULT;
        let attempts = policy.contact_hold_attempts;
        assert!(!hold_expired(now, 1, now, &policy));
        assert!(!hold_expired(now, attempts, now + 10, &policy));
        assert!(hold_expired(now, attempts + 1, now, &policy));
        assert!(hold_expired(
            now,
            1,
            now + policy.contact_hold_patience.as_secs(),
            &policy
        ));
    }

    #[test]
    fn a_hold_count_kept_for_a_quarantine_outlives_the_relay() {
        let first = 1_000_000;
        let kept = HELD_KEPT_FOR_QUARANTINE;
        let patience = WalletPolicy::DEFAULT.contact_hold_patience;
        assert!(kept.as_secs() > 7 * 24 * 60 * 60);
        assert!(!hold_forgotten(
            &format!("{first}:1"),
            first + kept.as_secs(),
            patience,
            kept
        ));
        assert!(hold_forgotten(
            &format!("{first}:1"),
            first + kept.as_secs() + 1,
            patience,
            kept
        ));
    }

    #[test]
    fn a_hold_count_is_forgotten_a_day_after_the_first_hold() {
        let first = 1_000_000;
        let forgotten = HELD_FORGOTTEN.as_secs();
        let patience = WalletPolicy::DEFAULT.contact_hold_patience;
        assert!(!hold_forgotten(
            &format!("{first}:1"),
            first + patience.as_secs(),
            patience,
            HELD_FORGOTTEN
        ));
        assert!(!hold_forgotten(
            &format!("{first}:3"),
            first + forgotten,
            patience,
            HELD_FORGOTTEN
        ));
        assert!(hold_forgotten(
            &format!("{first}:3"),
            first + forgotten + 1,
            patience,
            HELD_FORGOTTEN
        ));
        assert!(hold_forgotten(
            &format!("{first}:1"),
            first - patience.as_secs() - 1,
            patience,
            HELD_FORGOTTEN
        ));
        assert!(hold_forgotten("damaged", first, patience, HELD_FORGOTTEN));
    }

    #[test]
    fn a_clock_set_back_since_the_first_hold_ends_it() {
        let first = 1_000_000;
        let policy = WalletPolicy::DEFAULT;
        let patience = policy.contact_hold_patience.as_secs();
        assert!(hold_expired(first, 1, first - patience - 1, &policy));
        assert!(!hold_expired(first, 1, first - 1, &policy));
    }

    #[test]
    fn a_failure_that_passes_by_itself_holds_without_counting() {
        let store = |error| ContactError::Wallet(lepic_wallet::WalletError::Store(error));
        for passing in [
            ContactError::Offline,
            ContactError::EpicboxOff,
            ContactError::Wallet(lepic_wallet::WalletError::Locked),
            store(StoreError::Poisoned),
        ] {
            assert!(passes(&passing), "{passing:?}");
        }
        for counted in [
            ContactError::Ended,
            ContactError::UnknownContact,
            store(StoreError::Corrupt {
                record: lepic_store::Record::Contact,
                field: "card",
            }),
        ] {
            assert!(!passes(&counted), "{counted:?}");
        }
    }
}
