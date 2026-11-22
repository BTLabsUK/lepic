// SPDX-License-Identifier: Apache-2.0
//! Collecting: reading the pairing mailboxes and the contact mailboxes from the contacts' mux/1
//! sessions, and the housekeeping a cycle does around it (RFC 0002 8.2 to 8.5).

use crate::hex;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Duration;

use blake2::Blake2b256;
use blake2::digest::Digest;
use futures_util::future::join_all;
use jiff::Timestamp;
use lepic_contact::{
    ContactCard, MessageType, Opened, PaymentFile, SealedEnvelope, classify, dearmor,
};
use lepic_epicbox::{EpicboxAddress, Handled, MailboxContent, MailboxMessage};
use lepic_node::NodeApi;
use lepic_slate::model::SlateId;
use lepic_store::{
    AccountIndex, ContactId, ContactRecord, ContactState, MailClass, PairingId, PairingRole,
    PendingInvoiceStatus, Repositories, SealMode, StoreError, TxDirection, TxState, WalletStore,
    WatchRow,
};
use lepic_transport::transport::BoxFuture;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use super::epic1::{Payments, Replies};
use super::in_person::Answers;
use super::keys::{box_identity, contact_keys, contact_network, enc_secret};
use super::pairing::{Taken, peer_card};
use super::quarantine::{Message, QuarantineReason};
use super::relay::{check_online, endpoint_for};
use super::{
    ContactError, ContactRelays, LATE_DRAIN_WAIT, PairingFailure, UPDATES_PER_CONTACT_PER_DAY,
    UPDATES_PER_HOUR,
};
use crate::ContactBook;
use crate::delivery::carrier::{Carrier, CarrierError, Part};
use crate::delivery::outbox::{Owed, enqueue};
use crate::delivery::reconcile::{CONTACT_CLASSES, Mailboxes, Reconciled, reconcile};
use crate::delivery::router::{Handler, Hold, Pushed, Router, Stored};
use crate::delivery::transport::{NotAnswered, Reach, Transport, Waiting};
use crate::delivery::watch::{SkipReason, WatchError, WatchReport};
use crate::outbox::{RefusedPost, StuckPayment};
use crate::outbox::{contact_owed, contact_rows, redirect_contact_rows, waiting};
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
    /// The app opened or resumed, or the wallet was unlocked: a session waiting to reconnect
    /// and the whole outbox are tried at once.
    Open,
    /// The foreground tick: the relays are asked what waits; a session's reconnect delay and
    /// outbox retry times are kept.
    Foreground,
    /// The user pulled to refresh, or ran collect in the CLI: as [`CollectTrigger::Open`].
    Pull,
    /// A push wake-up: the mail the sessions queued is read and the relays are asked nothing;
    /// outbox retry times are kept, since pushes can come in bursts.
    Push,
}

/// What one collecting cycle did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectReport {
    /// Mailboxes watched on the contacts' mux/1 sessions.
    pub mailboxes: usize,
    /// Mailboxes the relay still had mail for when the cycle stopped reading; the rest waits
    /// for the next collect.
    pub capped: usize,
    /// Mailboxes a message was kept for later in.
    pub kept: usize,
    /// Mailboxes not read: their relay did not answer, does not offer mux/1 or had no room for
    /// them, their row's relay cannot be reached as written, or their socket does not carry
    /// them.
    pub not_reached: usize,
    /// Mailboxes another socket of the same wallet took over. That socket reads them; this one
    /// attaches them again when its hold-off ends, or at once on the next open.
    pub replaced: usize,
    /// Messages handed out by the relays.
    pub messages: usize,
    /// Pairings that completed.
    pub paired: usize,
    /// Pairings in progress that ended with nothing stored: expired, refused by the inviter,
    /// or changed on the way. Each also raised [`Event::PairingFailed`].
    pub failed: Vec<FailedPairing>,
    /// Outbox entries that reached their relay in this cycle.
    pub delivered: usize,
    /// Outbox posts of this cycle that a mailbox refused; see [`crate::OutboxReport::refused`].
    pub refused: Vec<RefusedPost>,
    /// Payments the outbox holds marked stuck at the end of the cycle, by slate id: no route
    /// took them within [`crate::OUTBOX_STUCK_AFTER`]. The outbox goes on trying them.
    pub stuck: Vec<StuckPayment>,
    /// Relays that did not answer or do not offer mux/1, as `domain:port`.
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
    /// Payments taken at epic1 delivery mailboxes and answers to epic1 payments finalized.
    pub epic1: usize,
}

/// How many times a cycle reads what a socket pushed after asking it what waits. A socket pushes
/// at most 32 messages before they are acknowledged, so a cycle reads about 256 messages a
/// socket; the rest waits for the next cycle. A last question after the last read sends its
/// acknowledgements and gives the counts the cycle concludes on.
const MAX_READ_ROUNDS: usize = 8;

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

pub(crate) fn old_salt_key(contact_id: ContactId) -> String {
    format!("{OLD_SALT_PREFIX}{}", hex::encode(&contact_id.0))
}

/// The box salt of a mailbox moved away from after an in-person pairing. It is read until the
/// contact writes to the new mailbox, which shows it took our new card.
#[derive(Serialize, Deserialize)]
pub(crate) struct OldSalt {
    pub(crate) salt: String,
}
const UPDATES_KEY: &str = "contact.updates";

/// Whose mailbox a message came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Job {
    Reply(PairingId),
    Confirm(PairingId),
    /// A contact's mailbox; `true` for the one our current card names.
    Contact(ContactId, bool),
    /// The delivery mailbox of the epic1 address of an account.
    Address(AccountIndex),
    /// The reply mailbox of an epic1 payment the account sent.
    Payment(SlateId, AccountIndex),
    /// The reply mailbox of an in-person code of the account.
    Code(SlateId, AccountIndex),
    /// The reply mailbox slot the account's shared-slot in-person codes share.
    Slot(AccountIndex),
}

impl Job {
    /// Whether the mailbox is one of the wallet's own epic1 or in-person mailboxes.
    pub(crate) fn is_native(self) -> bool {
        matches!(
            self,
            Self::Address(..) | Self::Payment(..) | Self::Code(..) | Self::Slot(..)
        )
    }
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
    /// Collects the pairing and contact mailboxes once (RFC 0002 8.4). The mailboxes are watched
    /// on the contacts' mux/1 sessions, whose relays push their mail; a cycle reads what the
    /// sessions queued and asks each socket what still waits. Cycles, pairing links entered by
    /// hand and outbox runs take turns, never overlapping. A relay that does not answer or does
    /// not offer mux/1 is not read and raises [`Event::HomeRelayUnreachable`]. Replies to this
    /// wallet's invites pair and raise [`Event::PairingReplied`], confirms raise
    /// [`Event::PairingConfirmed`], contact updates raise [`Event::ContactUpdated`]. Pairings
    /// past their time end with [`Event::PairingFailed`]. Messages are acknowledged only once
    /// their effect is stored.
    ///
    /// Fails with [`ContactError::Offline`] before connecting, with
    /// [`ContactError::NetworkMismatch`], and as the store does. A relay that fails is reported,
    /// not returned as an error.
    #[instrument(skip_all, fields(wallet = %self.wallet.config().name))]
    pub async fn contacts_collect(
        &self,
        relays: &ContactRelays,
        trigger: CollectTrigger,
    ) -> Result<CollectReport, ContactError> {
        self.check_contact_network(relays)?;
        check_online(relays)?;
        let _turn = self.wallet.contact_turn().await;
        let mut report = CollectReport::default();
        // The user's own triggers retry at once what waits: a session waiting to reconnect and
        // outbox entries not yet due (RFC 0002 12.4). The foreground tick and push wake-ups,
        // which can come in bursts, keep the waits.
        let explicit = matches!(trigger, CollectTrigger::Open | CollectTrigger::Pull);
        for failed in self.end_expired_pairings().await? {
            self.wallet.emit(Event::PairingFailed(failed));
            report.failed.push(failed);
        }
        self.tend_key_checks().await?;
        self.prune_outbox().await?;
        self.forget_old_envelopes().await?;
        self.move_in_person_mailboxes(relays).await?;
        self.send_address_cards(relays).await?;
        if let Err(error) = self.tend_in_person().await {
            warn!(error = %ErrorChain(&error), "in-person codes not tended");
        }
        if let Err(error) = self.tend_epic1().await {
            warn!(error = %ErrorChain(&error), "epic1 records not tended");
        }
        let ended_before = self.ended_since(&BTreeSet::new()).await?;
        let ended_before: BTreeSet<ContactId> =
            ended_before.iter().map(|ended| ended.contact_id).collect();
        let mut told = Told::default();
        self.read_mailboxes(relays, trigger, Vec::new(), &mut told, &mut report)
            .await?;
        report.quarantined = told.quarantined;
        report.quarantine_dropped = told.quarantine_dropped;
        report.buffered = told.buffered;
        debug!(count = report.mailboxes, "contact mailboxes collected");
        for ended in self.ended_since(&ended_before).await? {
            if !report.ended.contains(&ended) {
                report.ended.push(ended);
            }
        }
        // Already this run's turn: the outbox runs without taking it again.
        match self.deliver_outbox(relays, explicit).await {
            Ok(outbox) => {
                report.delivered = outbox.delivered;
                report.refused = outbox.refused;
            }
            Err(error) => warn!(error = %ErrorChain(&error), "contact outbox not run"),
        }
        report.stuck = self.stuck_payments().await?;
        Ok(report)
    }

    /// Makes the watch set equal to the records, then has the contacts' sessions carry its rows
    /// and the rows of `extra`, which are not stored, and does what `reach` asks. Returns the
    /// carrier, whose mailbox each row is, and what the watch did. The caller holds the contact
    /// turn.
    pub(crate) async fn watch_mailboxes(
        &self,
        relays: &ContactRelays,
        extra: Vec<(WatchRow, Job)>,
        reach: Reach,
    ) -> Result<(Carrier, Mailboxes, WatchReport), ContactError> {
        let session = self.wallet.session()?;
        let network = self.wallet.config().network;
        let work_session = session.clone();
        let work_relays = relays.clone();
        let (reconciled, now) = self
            .contact_work(move |ports, _| {
                let now = ports.clock.now();
                let reconciled = work_session.store.write(|repos| {
                    reconcile(repos, &work_session.keychain, network, &work_relays, now)
                })?;
                Ok((reconciled, now))
            })
            .await?;
        let Reconciled {
            mut set,
            mut mailboxes,
        } = reconciled;
        let mut places: HashSet<(String, String)> = set
            .iter()
            .map(|row| (row.key_ref.clone(), row.relay.clone()))
            .collect();
        for (row, job) in extra {
            if places.insert((row.key_ref.clone(), row.relay.clone())) {
                mailboxes.add_native(&row, job);
                set.push(row);
            }
        }
        self.resolve_native(relays, &mut mailboxes);
        let carrier = Carrier::new(relays.clone());
        let to_contact = |error| match error {
            CarrierError::Contact(error) => error,
            CarrierError::Store(error) => error.into(),
        };
        let watch = carrier
            .watch(set, &mailboxes, &session.store, now, reach)
            .await
            .map_err(to_contact)?;
        Ok((carrier, mailboxes, watch))
    }

    /// Derives the key of each epic1 and in-person mailbox of `mailboxes` on its relay. One
    /// whose relay cannot be reached as written gets none; the carrier skips its row.
    fn resolve_native(&self, relays: &ContactRelays, mailboxes: &mut Mailboxes) {
        let network = self.wallet.config().network;
        let net = contact_network(network);
        mailboxes.resolve_native(|relay, job| {
            let endpoint = endpoint_for(relay, relays).ok()?;
            let secret = match job {
                Job::Address(account) => self.wallet.epic1_delivery_key(account, net),
                Job::Payment(slate_id, account) | Job::Code(slate_id, account) => self
                    .wallet
                    .reply_mailbox_key(account, net, slate_id.as_bytes()),
                Job::Slot(account) => self.wallet.shared_reply_mailbox_key(account, net),
                Job::Reply(_) | Job::Confirm(_) | Job::Contact(..) => return None,
            };
            let identity = secret
                .map_err(ContactError::from)
                .and_then(|secret| super::in_person::identity(secret, network, &endpoint));
            match identity {
                Ok(identity) => Some(identity),
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "mailbox key not derived");
                    None
                }
            }
        });
    }

    /// Watches the mailboxes of the set and of `extra` and reads them: the mail their sessions
    /// queued, then, but for a push wake-up, what each socket says still waits, round after
    /// round, until nothing does, a round reads nothing, or [`MAX_READ_ROUNDS`] reads are done
    /// and asked about. Contact and pairing mail goes to the [`Collector`], payments to
    /// delivery mailboxes to [`Payments`], answers to the reply mailboxes of payments to
    /// [`Replies`] and answers to in-person codes to [`Answers`]. Adds what came of it to
    /// `report`. A relay that does not answer is reported there, not returned as an error.
    /// Returns what the watch did.
    pub(crate) async fn read_mailboxes(
        &self,
        relays: &ContactRelays,
        trigger: CollectTrigger,
        extra: Vec<(WatchRow, Job)>,
        told: &mut Told,
        report: &mut CollectReport,
    ) -> Result<WatchReport, ContactError> {
        let reach = match trigger {
            CollectTrigger::Open => Reach::TakeBack,
            CollectTrigger::Pull => Reach::Retry,
            CollectTrigger::Foreground | CollectTrigger::Push => Reach::Claim,
        };
        let started = self.wallet.ports().clock.now();
        let (carrier, mailboxes, watch) = self.watch_mailboxes(relays, extra, reach).await?;
        let mut unreachable = count_watch(&watch, report);
        let parts = carrier.parts();
        let mut collector = Collector {
            wallet: self,
            relays,
            mailboxes: &mailboxes,
            paired: 0,
            failed: Vec::new(),
            kept: HashSet::new(),
            told,
        };
        let mut payments = Payments::new(self, relays, &mailboxes);
        let mut replies = Replies::new(self, &mailboxes);
        let mut answers = Answers::new(self);
        let mut reads: Vec<PartRead<'_>> = parts.iter().map(PartRead::new).collect();
        let mut handed;
        {
            let mut router = Router::default();
            let registered = router
                .register_for(&CONTACT_CLASSES, &mut collector)
                .and_then(|()| router.register(MailClass::Address, &mut payments))
                .and_then(|()| router.register(MailClass::Reply, &mut replies))
                .and_then(|()| router.register(MailClass::InPerson, &mut answers));
            if let Err(error) = registered {
                warn!(error = %ErrorChain(&error), "mail handler not registered");
                return Ok(watch);
            }
            handed = router.handle_queued(&carrier).await;
            if trigger != CollectTrigger::Push {
                let more = read_rounds(&mut router, &carrier, &mut reads).await;
                handed = handed.saturating_add(more);
            }
        }
        // The answers are stored before the copies of their payments are cancelled. A pass that
        // returned early above, or a wallet stopped in between, leaves the copies on their
        // relays until they expire.
        self.cancel_copies(&carrier, std::mem::take(&mut replies.cancels))
            .await;
        report.messages = report.messages.saturating_add(handed);
        report.paired = report.paired.saturating_add(collector.paired);
        report.failed.append(&mut collector.failed);
        report.kept = report
            .kept
            .saturating_add(collector.kept.len())
            .saturating_add(payments.kept.len())
            .saturating_add(replies.kept.len())
            .saturating_add(answers.kept.len());
        report.epic1 = report
            .epic1
            .saturating_add(payments.taken)
            .saturating_add(replies.taken);
        report.in_person = report.in_person.saturating_add(answers.taken);
        let replaced = taken_over(&parts);
        report.count_replaced(replaced.len());
        if trigger != CollectTrigger::Push {
            let unsettled = Unsettled {
                kept: &collector.kept,
                replaced: &replaced,
            };
            self.conclude_reads(
                &reads,
                &mailboxes,
                unsettled,
                started,
                &mut unreachable,
                report,
            )
            .await?;
        }
        for relay in unreachable {
            self.wallet
                .emit(Event::HomeRelayUnreachable(UnreachableRelay {
                    relay: relay.clone(),
                }));
            report.unreachable.push(relay);
        }
        Ok(watch)
    }

    /// Ends what a full read of the contact mailboxes settles: the pairings past their deadline
    /// whose mailbox was read to the end, and the wait of contacts that stay unheard. Counts
    /// what was not read to the end, but for the rows another socket reads, concludes nothing
    /// for the rows in `unsettled`, and adds each relay none of whose sockets answered to
    /// `unreachable`.
    async fn conclude_reads(
        &self,
        reads: &[PartRead<'_>],
        mailboxes: &Mailboxes,
        unsettled: Unsettled<'_>,
        started: Timestamp,
        unreachable: &mut Vec<String>,
        report: &mut CollectReport,
    ) -> Result<(), ContactError> {
        let mut pairings: Vec<PairingId> = Vec::new();
        let mut contacts: Vec<ContactId> = Vec::new();
        for read in reads {
            let Some(Ok(waiting)) = &read.last else {
                if read.paced {
                    // Asked too often before a first answer: up, and not read to the end.
                    let paced = read
                        .part
                        .mailboxes
                        .values()
                        .filter(|watched| {
                            !unsettled
                                .replaced
                                .contains(&(watched.row.key_ref.clone(), watched.row.relay.clone()))
                        })
                        .count();
                    report.capped = report.capped.saturating_add(paced);
                } else {
                    report.not_reached =
                        report.not_reached.saturating_add(read.part.mailboxes.len());
                }
                continue;
            };
            for (index, watched) in &read.part.mailboxes {
                let row = &watched.row;
                // Another socket of the wallet reads it.
                if unsettled
                    .replaced
                    .contains(&(row.key_ref.clone(), row.relay.clone()))
                {
                    continue;
                }
                match read_end(waiting, *index) {
                    ReadEnd::Read => {}
                    ReadEnd::Left => {
                        report.capped = report.capped.saturating_add(1);
                        continue;
                    }
                    ReadEnd::NotCarried => {
                        report.not_reached = report.not_reached.saturating_add(1);
                        continue;
                    }
                    ReadEnd::Held => continue,
                }
                if unsettled.kept.contains(&(row.key_ref.clone(), row.class)) {
                    continue;
                }
                // The epic1 and in-person mailboxes conclude nothing from a read.
                match mailboxes.job(&row.key_ref, &row.relay) {
                    // A mailbox is watched on several relays; one read of it counts.
                    Some(Job::Reply(pairing_id) | Job::Confirm(pairing_id)) => {
                        if !pairings.contains(&pairing_id) {
                            pairings.push(pairing_id);
                        }
                    }
                    Some(Job::Contact(contact_id, true)) => {
                        if !contacts.contains(&contact_id) {
                            contacts.push(contact_id);
                        }
                    }
                    Some(
                        Job::Contact(_, false)
                        | Job::Address(..)
                        | Job::Payment(..)
                        | Job::Code(..)
                        | Job::Slot(..),
                    )
                    | None => {}
                }
            }
        }
        let hosts: BTreeSet<&str> = reads.iter().map(|read| read.part.host.as_str()).collect();
        for host in hosts {
            let on_host = || reads.iter().filter(|read| read.part.host == host);
            if on_host().any(|read| read.reached) {
                continue;
            }
            let error = on_host().find_map(|read| match &read.last {
                Some(Err(error)) => Some(error),
                _ => None,
            });
            if let Some(error) = error {
                warn!(peer_relay = %host, error = %ErrorChain(error), "home relay not answering");
            }
            if !unreachable.iter().any(|known| known == host) {
                unreachable.push(host.to_owned());
            }
        }
        // The relay pushed everything that reached it by `started`: what is past its
        // deadline then has had its last chance.
        for failed in self.end_drained_pairings(pairings, started).await? {
            self.wallet.emit(Event::PairingFailed(failed));
            report.failed.push(failed);
        }
        // The wait for an unheard contact counts only after its mailbox was read, so a
        // wallet that cannot read never ends a pairing.
        let mut ended = self.count_heard_wait(contacts, started).await?;
        report.ended.append(&mut ended);
        Ok(())
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
    /// invite's expiry and the clock skew, an answer's wait for its confirm) with no read of
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

    /// Ends the pairings in progress among `pairings` whose deadline had passed when a read that
    /// started at `started` took one of their mailboxes, on any relay that carries it: that
    /// read was their last chance. An inviter whose confirm has not left yet keeps its pairing
    /// until [`LATE_DRAIN_WAIT`] runs out.
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
                        enqueue(
                            repos,
                            &update_owed(record.contact_id, &envelope, &mailbox.peer_mailbox),
                            now,
                        )?;
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
pub(crate) fn has_pending(
    repos: &dyn Repositories,
    contact_id: ContactId,
) -> Result<bool, StoreError> {
    for stored in contact_rows(repos, contact_id)? {
        if waiting(stored.entry.state) {
            return Ok(true);
        }
        for direction in [TxDirection::Outgoing, TxDirection::Incoming] {
            if repos
                .transaction_by_slate(stored.entry.payment_id, direction)?
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

/// Our keys for the contact's mailbox read with `salt`; `None` for a private pairing whose
/// secrets do not open, since nothing is taken through it.
pub(crate) fn box_keys(
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
        redirect_contact_rows(repos, contact_id, &peer_mailbox)?;
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
    redirect_contact_rows(repos, contact_id, &peer_mailbox)?;
    repos.put_contact(&record)?;
    repos.put_contact_mailbox(&mailbox)?;
    // Our new mailbox reaches the contact at once, in the same write.
    enqueue(
        repos,
        &update_owed(contact_id, &envelope, &peer_mailbox),
        now,
    )?;
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

/// The post that carries a contact update `envelope` to the contact's `destination`.
pub(crate) fn update_owed(contact_id: ContactId, envelope: &[u8], destination: &str) -> Owed {
    contact_owed(
        contact_id,
        uuid::Uuid::from_bytes(contact_id.0),
        lepic_store::SlateStage::Standard1,
        destination,
        lepic_contact::armor(envelope),
    )
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
        ContactError::Offline => true,
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

/// Hands each pushed message of a contact class to the engine and has it acknowledged once its
/// effect is stored.
struct Collector<'a, N, S: StoreOpener, V> {
    wallet: &'a ContactBook<'a, N, S, V>,
    relays: &'a ContactRelays,
    mailboxes: &'a Mailboxes,
    paired: usize,
    failed: Vec<FailedPairing>,
    /// The mailboxes, by key reference and class, a message was kept for later in. Only this
    /// cycle's holds: mail an earlier cycle held is not offered while its hold lasts and counts
    /// only in its socket's `held`, which does not say whose it is. So no mailbox of a socket
    /// with mail on hold is concluded ([`ReadEnd::Held`]).
    kept: HashSet<(String, MailClass)>,
    told: &'a mut Told,
}

/// What the last answer of a socket says of one of the mailboxes it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadEnd {
    /// Read to the end: nothing of it waits, nothing is in flight and nothing is on hold.
    Read,
    /// Mail still waits or is in flight on the socket.
    Left,
    /// The answer leaves it out: the socket does not carry it, because the relay refused its
    /// attach or another socket took it over. Nothing of it was read.
    NotCarried,
    /// Mail is on hold on the socket, perhaps this mailbox's.
    Held,
}

/// How far the mailbox of `index` was read, by its socket's last answer. The answer lists every
/// mailbox attached on the socket, with 0 when nothing of it waits.
fn read_end(waiting: &Waiting, index: usize) -> ReadEnd {
    match waiting.waiting.get(&index) {
        None => ReadEnd::NotCarried,
        Some(left) if *left > 0 || waiting.inflight > 0 => ReadEnd::Left,
        Some(_) if waiting.held > 0 => ReadEnd::Held,
        Some(_) => ReadEnd::Read,
    }
}

/// The places, as `(key_ref, relay)`, of the rows whose mailbox another socket of the wallet
/// took over from one of `parts`. Each session attaches them again when its hold-off ends.
fn taken_over(parts: &[Part]) -> BTreeSet<(String, String)> {
    let mut places = BTreeSet::new();
    for part in parts {
        let keys = part.taken_over();
        if keys.is_empty() {
            continue;
        }
        for watched in part.mailboxes.values() {
            if keys.contains(&watched.identity.address().key_text()) {
                places.insert((watched.row.key_ref.clone(), watched.row.relay.clone()));
            }
        }
    }
    places
}

/// Adds the rows `watch` left out and the mailboxes it watched to `report`. Returns the relays
/// whose session could not be had. The carrier logged why each row was not watched.
fn count_watch(watch: &WatchReport, report: &mut CollectReport) -> Vec<String> {
    let mut unreachable = Vec::new();
    for skipped in &watch.skipped {
        match skipped.reason {
            SkipReason::Repeated => {}
            _ => report.not_reached = report.not_reached.saturating_add(1),
        }
    }
    for relay in &watch.relays {
        report.mailboxes = report.mailboxes.saturating_add(relay.watched);
        report.not_reached = report
            .not_reached
            .saturating_add(relay.mailboxes.saturating_sub(relay.watched));
        if matches!(
            relay.error,
            Some(WatchError::NoPush | WatchError::Session(_))
        ) {
            unreachable.push(relay.relay.clone());
        }
    }
    unreachable
}

impl CollectReport {
    /// Counts `marked` rows that this pass watched and another socket of the wallet holds as
    /// replaced only.
    fn count_replaced(&mut self, marked: usize) {
        self.mailboxes = self.mailboxes.saturating_sub(marked);
        self.replaced = self.replaced.saturating_add(marked);
    }
}

/// Whether `watch` claimed every row of `rows` on `host`: none of them was left out, and the
/// relay's session took all its mailboxes. A row left out as a repeat is watched under its key.
pub(crate) fn all_watched(watch: &WatchReport, rows: &[(WatchRow, Job)], host: &str) -> bool {
    let places: HashSet<(&str, &str)> = rows
        .iter()
        .map(|(row, _)| (row.key_ref.as_str(), row.relay.as_str()))
        .collect();
    let skipped = watch.skipped.iter().any(|skipped| {
        !matches!(skipped.reason, SkipReason::Repeated)
            && places.contains(&(skipped.row.key_ref.as_str(), skipped.row.relay.as_str()))
    });
    let relay = watch.relays.iter().find(|relay| relay.relay == host);
    !skipped
        && (rows.is_empty()
            || relay.is_some_and(|relay| relay.error.is_none() && relay.watched == relay.mailboxes))
}

/// The rows a full read leaves as they are: those whose mail a handler kept, as
/// `(key_ref, class)`, and those another socket of the wallet reads, as `(key_ref, relay)`.
struct Unsettled<'a> {
    kept: &'a HashSet<(String, MailClass)>,
    replaced: &'a BTreeSet<(String, String)>,
}

/// Follows every read with a question: it sends the read's acknowledgements and its answer is
/// the count after the read. Hands what came since to `router`, round by round, until no read
/// is open, a round hands nothing, or [`MAX_READ_ROUNDS`] rounds ran. Returns the messages it
/// handed.
async fn read_rounds(
    router: &mut Router<'_>,
    carrier: &Carrier,
    reads: &mut [PartRead<'_>],
) -> usize {
    let mut handed = 0usize;
    let mut rounds = 0usize;
    loop {
        let asking: Vec<&mut PartRead<'_>> = reads.iter_mut().filter(|read| read.open).collect();
        if asking.is_empty() {
            break;
        }
        let answers = join_all(asking.iter().map(|read| carrier.waiting(read.part))).await;
        for (read, answer) in asking.into_iter().zip(answers) {
            read.answered(answer);
        }
        if !reads.iter().any(|read| read.open) || rounds == MAX_READ_ROUNDS {
            break;
        }
        rounds = rounds.saturating_add(1);
        let round = router.handle_queued(carrier).await;
        handed = handed.saturating_add(round);
        if round == 0 {
            break;
        }
    }
    handed
}

/// What a cycle learned of the mailboxes one socket carries.
struct PartRead<'p> {
    part: &'p Part,
    /// The socket answered in this cycle.
    reached: bool,
    /// Its last answer. A paced question leaves the answer before it.
    last: Option<Result<Waiting, NotAnswered>>,
    /// It may still hold mail for the mailboxes.
    open: bool,
    /// The session or the mailbox paced the last question: no more are asked this cycle, and
    /// what was not read to the end counts as capped.
    paced: bool,
}

impl<'p> PartRead<'p> {
    fn new(part: &'p Part) -> Self {
        Self {
            part,
            reached: false,
            last: None,
            open: true,
            paced: false,
        }
    }

    fn answered(&mut self, answer: Result<Waiting, NotAnswered>) {
        if let Err(error) = &answer
            && error.paced()
        {
            debug!(peer_relay = %self.part.host, "mailbox read paced, the rest left to the next cycle");
            self.paced = true;
            self.reached = true;
            self.open = false;
            return;
        }
        self.open = match &answer {
            Ok(waiting) => {
                self.reached = true;
                waiting.inflight > 0
                    || self
                        .part
                        .mailboxes
                        .keys()
                        .any(|index| waiting.waiting.get(index).is_some_and(|left| *left > 0))
            }
            Err(_) => false,
        };
        self.last = Some(answer);
    }
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

impl<N, S, V> Handler for Collector<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    fn handle(&mut self, mail: Pushed) -> BoxFuture<'_, Result<Stored, Hold>> {
        Box::pin(async move {
            let handled = match self.mailboxes.job(&mail.key_ref, &mail.relay) {
                Some(job) => self.handle_message(job, mail.mail).await,
                // Not a row this cycle derived: the relay keeps the mail for a cycle that knows
                // whose mailbox it is.
                None => Handled::Later,
            };
            if handled == Handled::Stored {
                return Ok(Stored);
            }
            self.kept.insert((mail.key_ref, mail.class));
            Err(Hold)
        })
    }
}

impl<N, S, V> Collector<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Takes one message of the mailbox of `job`.
    async fn handle_message(&mut self, job: Job, message: MailboxMessage) -> Handled {
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
    }

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
            // The native classes have handlers of their own; none of their mail comes here.
            Job::Address(..) | Job::Payment(..) | Job::Code(..) | Job::Slot(..) => {
                return Ok(Handled::Stored);
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

    fn answer(waiting: &[(usize, u64)], inflight: u64, held: u64) -> Waiting {
        Waiting {
            waiting: waiting.iter().copied().collect(),
            inflight,
            held,
        }
    }

    #[test]
    fn a_mailbox_is_read_only_when_its_socket_carries_it_with_nothing_left() {
        assert_eq!(read_end(&answer(&[(0, 0), (1, 0)], 0, 0), 1), ReadEnd::Read);
        assert_eq!(read_end(&answer(&[(0, 2), (1, 0)], 0, 0), 0), ReadEnd::Left);
        assert_eq!(read_end(&answer(&[(0, 0)], 1, 0), 0), ReadEnd::Left);
        assert_eq!(read_end(&answer(&[(0, 3)], 0, 1), 0), ReadEnd::Left);
        // Left out of the answer: another socket took it over, or the relay refused it.
        assert_eq!(read_end(&answer(&[(0, 0)], 0, 0), 1), ReadEnd::NotCarried);
        assert_eq!(read_end(&answer(&[], 0, 0), 0), ReadEnd::NotCarried);
        // Mail on hold on the socket may be any of its mailboxes'.
        assert_eq!(read_end(&answer(&[(0, 0), (1, 0)], 0, 1), 1), ReadEnd::Held);
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
