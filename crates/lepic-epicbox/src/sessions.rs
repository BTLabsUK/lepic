//! The mux/1 sessions of one Epicbox transport, shared by the consumers that read the same
//! relay: the contacts collect and the payments listener.
//!
//! A session is named by the relay it talks to and a group the host picks. Two consumers that
//! name the same group on the same relay share its sockets. One socket holds as many mailboxes
//! as the relay allows; a session that needs more opens more sockets on the same relay and
//! group. The extra sockets add capacity, not privacy: the relay sees that they come from one
//! host. Each consumer is an owner: it keeps its own claim on a socket's mailboxes (see
//! [`crate::MuxSession::set_claim`]), and a socket lives until its last owner lets go.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime};

use crate::mux::{HealthNote, HealthNotes};
use crate::{MAX_MAILBOXES_PER_SOCKET, MuxCounters, MuxError, MuxOptions, MuxSession, MuxState};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

/// How long a mailbox that answered the greeting without push is left before it is asked
/// again. Each answer in a row without push doubles it, up to [`NO_PUSH_ASK_AGAIN_MAX`]. A
/// mailbox at its connection limit answers the same way, so it is asked again too.
const NO_PUSH_ASK_AGAIN_FIRST: Duration = Duration::from_secs(60);
const NO_PUSH_ASK_AGAIN_MAX: Duration = Duration::from_secs(3600);

/// How long posts leave a mailbox they could not reach. Each failure in a row doubles it, up
/// to [`POST_RETRY_MAX`], so that one dead mailbox does not add its connect timeout to every
/// post.
const POST_RETRY_FIRST: Duration = Duration::from_secs(30);
const POST_RETRY_MAX: Duration = Duration::from_secs(600);

/// Health events a slow watcher may fall behind by before it misses some.
const HEALTH_EVENTS_KEPT: usize = 64;

/// A consumer that shares the sessions, and the owner of its claim on a socket's mailboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    /// The payments listener.
    Payments,
    /// The contacts collect.
    Contacts,
}

impl Owner {
    /// The owner as [`MuxSession`] claims name it: `payments` or `contacts`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payments => "payments",
            Self::Contacts => "contacts",
        }
    }
}

/// How the contacts collect uses sessions: the group it joins and how the sessions are paced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedConfig {
    /// The group the contacts collect joins; sessions with the same group on the same relay are
    /// shared.
    pub group: String,
    /// How the sessions it starts are paced.
    pub options: MuxOptions,
}

/// A session as the host sees it: its sockets as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The relay as `domain:port`.
    pub relay: String,
    /// The group the session was started for.
    pub group: String,
    /// Where the session is now: `NotOffered` when the relay refused mux/1 and no socket runs,
    /// `Attached` when every running socket is, otherwise the state of the least ready one, and
    /// `Stopped` when none runs.
    pub state: MuxState,
    /// What the session's sockets have done so far, added up.
    pub counters: MuxCounters,
    /// Why a socket of the session was last lost, while it has not attached again; the first
    /// such socket's when several have. The text comes raw from the relay or the transport, cut
    /// to 1024 characters and otherwise as it came, control characters included: a reader
    /// escapes it before showing it.
    pub last_error: Option<String>,
}

/// What the sessions know of one mailbox, as [`PushedSessions::health`] reports it. A record is
/// shown, never used to drop the mailbox: a mailbox that fails stays in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MailboxHealth {
    /// The group of the session that last reported on the mailbox.
    pub group: String,
    /// Whether the mailbox offered push (mux/1) at the last greeting it answered: `false` also
    /// for an error in place of an answer, for a mailbox that never answered, and for one at its
    /// connection limit. `None` before any answer. [`MailboxHealth::no_mux`] reads it.
    pub push: Option<bool>,
    /// When a socket last attached to the mailbox.
    pub last_success: Option<SystemTime>,
    /// Sockets lost since the last success.
    pub failures: u32,
    /// Why the last socket was lost, as [`SessionInfo::last_error`] gives it; cleared by a
    /// success.
    pub last_error: Option<String>,
    /// When a mailbox that answered without push is asked again.
    pub ask_again_at: Option<SystemTime>,
    /// Posts in a row that could not reach the mailbox, as [`PushedSessions::note_post`] counts
    /// them; cleared by a post it answered.
    pub post_failures: u32,
    /// Until when posts leave the mailbox after one could not reach it. `None` once a post
    /// reached it, and before any failed.
    pub post_retry_at: Option<SystemTime>,
}

impl MailboxHealth {
    /// Whether the mailbox is known to lack mux/1: it answered the greeting without it, or in
    /// place of an answer, or not at all while no greeting had ever been answered with it. The
    /// sessions ask it again ([`MailboxHealth::ask_again_at`]), and an answer with mux/1 clears
    /// this. A mailbox that was never reached, or that failed after it offered mux/1, is not
    /// `no_mux`: it is unreachable.
    pub const fn no_mux(&self) -> bool {
        matches!(self.push, Some(false))
    }

    fn new(group: &str) -> Self {
        Self {
            group: group.to_owned(),
            push: None,
            last_success: None,
            failures: 0,
            last_error: None,
            ask_again_at: None,
            post_failures: 0,
            post_retry_at: None,
        }
    }
}

/// A [`MailboxHealth`] and what decides when the mailbox is asked again.
struct Record {
    health: MailboxHealth,
    /// Whether the last outcome was an attach (`true`) or a lost socket or an answer without
    /// push (`false`). `None` before either, and once no socket is left on the relay.
    reachable: Option<bool>,
    /// Answers in a row without push.
    no_push: u32,
    ask_again: Option<Instant>,
}

/// The health of each mailbox, by relay (`domain:port`).
#[derive(Default)]
struct Health {
    records: BTreeMap<String, Record>,
    /// Every recorded mailbox was unreachable at the last note.
    none_reachable: bool,
}

impl Health {
    /// Records `note` from a socket of `relay` and `group`, and returns the events it raises.
    fn note(&mut self, relay: &str, group: &str, note: &HealthNote) -> Vec<SessionEvent> {
        let was_none = self.none_reachable;
        let record = self
            .records
            .entry(relay.to_owned())
            .or_insert_with(|| Record {
                health: MailboxHealth::new(group),
                reachable: None,
                no_push: 0,
                ask_again: None,
            });
        group.clone_into(&mut record.health.group);
        let before = record.reachable;
        match note {
            HealthNote::Greeted(true) => {
                record.health.push = Some(true);
                record.no_push = 0;
                record.ask_again = None;
                record.health.ask_again_at = None;
            }
            HealthNote::Greeted(false) => {
                record.health.push = Some(false);
                record.no_push = record.no_push.saturating_add(1);
                let wait = ask_again_after(record.no_push);
                record.ask_again = Instant::now().checked_add(wait);
                record.health.ask_again_at = SystemTime::now().checked_add(wait);
                record.reachable = Some(false);
            }
            HealthNote::Attached => {
                record.health.last_success = Some(SystemTime::now());
                record.health.failures = 0;
                record.health.last_error = None;
                record.reachable = Some(true);
            }
            HealthNote::Lost(error) => {
                record.health.failures = record.health.failures.saturating_add(1);
                record.health.last_error = Some(error.clone());
                record.reachable = Some(false);
            }
        }
        let mut raised = Vec::new();
        // Back after a loss, or the first to attach after none could be reached: a mailbox that
        // had not answered yet when the others failed ends that state too.
        if record.reachable == Some(true) && (before == Some(false) || was_none) {
            raised.push(SessionEvent::MailboxBack {
                relay: relay.to_owned(),
            });
        }
        let none_reachable = self
            .records
            .values()
            .any(|record| record.reachable.is_some())
            && self
                .records
                .values()
                .all(|record| record.reachable != Some(true));
        if none_reachable && !self.none_reachable {
            raised.push(SessionEvent::NoneReachable);
        }
        self.none_reachable = none_reachable;
        raised
    }

    /// Records a post to `relay`: `None` when the mailbox answered it, taken or refused, else
    /// why it could not be reached. Raises no event: posts do not decide whether a mailbox is
    /// reachable for reading.
    fn note_post(&mut self, relay: &str, failure: Option<&str>, now: SystemTime) {
        let record = self
            .records
            .entry(relay.to_owned())
            .or_insert_with(|| Record {
                health: MailboxHealth::new(""),
                reachable: None,
                no_push: 0,
                ask_again: None,
            });
        let health = &mut record.health;
        match failure {
            None => {
                health.post_failures = 0;
                health.post_retry_at = None;
            }
            Some(error) => {
                health.post_failures = health.post_failures.saturating_add(1);
                health.post_retry_at = now.checked_add(post_retry_after(health.post_failures));
                health.last_error = Some(error.to_owned());
            }
        }
    }

    /// Whether the sockets of `relay` it refused push are to be dropped: its time to be asked
    /// again has come, or a socket of the relay was offered push since, which clears that time.
    /// Without a record nothing was refused.
    fn ask_again_due(&self, relay: &str, now: Instant) -> bool {
        self.records
            .get(relay)
            .is_some_and(|record| record.ask_again.is_none_or(|at| at <= now))
    }
}

/// The wait before a mailbox that answered without push `answers` times in a row is asked
/// again.
fn ask_again_after(answers: u32) -> Duration {
    let factor = 1_u32
        .checked_shl(answers.saturating_sub(1))
        .unwrap_or(u32::MAX);
    NO_PUSH_ASK_AGAIN_FIRST
        .saturating_mul(factor)
        .min(NO_PUSH_ASK_AGAIN_MAX)
}

/// How long posts leave a mailbox after `failures` posts in a row could not reach it.
fn post_retry_after(failures: u32) -> Duration {
    let factor = 1_u32
        .checked_shl(failures.saturating_sub(1))
        .unwrap_or(u32::MAX);
    POST_RETRY_FIRST.saturating_mul(factor).min(POST_RETRY_MAX)
}

/// Where some of an owner's mailboxes go: a socket of the session, and the keys
/// ([`crate::EpicboxAddress::key_text`]) the owner is to claim on it.
#[derive(Debug, Clone)]
pub struct Placement {
    /// The socket.
    pub session: Arc<MuxSession>,
    /// The keys, in the order given to [`PushedSessions::place`].
    pub keys: Vec<String>,
}

/// What a host hears about the sessions of one Epicbox transport through
/// [`PushedSessions::watch`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// The session is in `state`, as [`SessionInfo::state`] puts it. It is the first event of a
    /// session, and a new one follows each change; the last one has ended.
    State {
        /// The relay as `domain:port`.
        relay: String,
        group: String,
        state: MuxState,
    },
    /// The relay pushed mail one of the session's sockets queued. It may be for any owner.
    MailQueued { relay: String, group: String },
    /// No mailbox with a socket can be reached: the last socket of each lost its connection or
    /// was answered without push. Raised once, until a mailbox comes back.
    NoneReachable,
    /// A socket of `relay` attached after the mailbox could not be reached, or after
    /// [`SessionEvent::NoneReachable`].
    MailboxBack { relay: String },
}

/// The sessions of one Epicbox transport, by relay and group, and the contacts collect's
/// config. Clones of the method share one registry.
pub struct PushedSessions {
    registry: Mutex<Registry>,
    /// Counts each time a socket is added or removed.
    changed: watch::Sender<u64>,
    /// The health of each relay a socket reported on; kept past its sockets.
    health: Arc<Mutex<Health>>,
    /// Where [`SessionEvent::NoneReachable`] and [`SessionEvent::MailboxBack`] go.
    health_events: broadcast::Sender<SessionEvent>,
}

impl Default for PushedSessions {
    fn default() -> Self {
        Self {
            registry: Mutex::default(),
            changed: watch::channel(0).0,
            health: Arc::default(),
            health_events: broadcast::channel(HEALTH_EVENTS_KEPT).0,
        }
    }
}

/// A session is named by its relay (`domain:port`) and its group.
type SessionKey = (String, String);

#[derive(Default)]
struct Registry {
    contacts: Option<PushedConfig>,
    /// The sockets of each session, in the order they were started. None is empty.
    entries: BTreeMap<SessionKey, Vec<Shard>>,
}

/// One socket of a session and the owners that keep it alive.
struct Shard {
    session: Arc<MuxSession>,
    owners: BTreeSet<Owner>,
}

impl Shard {
    /// The socket `session`, which tells `notes` how the relay answers.
    fn new(session: MuxSession, owner: Owner, notes: HealthNotes) -> Self {
        session.note_health(notes);
        Self {
            session: Arc::new(session),
            owners: BTreeSet::from([owner]),
        }
    }

    fn state(&self) -> MuxState {
        *self.session.state().borrow()
    }

    /// The socket runs or will run again: it has neither stopped nor been refused push.
    fn is_live(&self) -> bool {
        !self.state().has_ended()
    }

    /// How many mailboxes `owner` may claim here: the socket's room for it, less one for each
    /// other owner that joined and claims nothing yet, so a consumer of one mailbox that joined
    /// still finds its place.
    fn capacity_for(&self, owner: Owner) -> usize {
        let joined = self
            .owners
            .iter()
            .filter(|other| {
                **other != owner && self.session.claimed_keys(other.as_str()).is_empty()
            })
            .count();
        self.session.room_for(owner.as_str()).saturating_sub(joined)
    }
}

/// Forgets the stopped sockets of a session, and with `ask_again` the sockets the relay
/// refused push, so that the next one asks it again. Whether any was forgotten.
fn prune(shards: &mut Vec<Shard>, ask_again: bool) -> bool {
    let before = shards.len();
    shards.retain(|shard| match shard.state() {
        MuxState::Stopped => false,
        MuxState::NotOffered => !ask_again,
        _ => true,
    });
    shards.len() != before
}

impl PushedSessions {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every session with its key and its sockets.
    fn sessions(&self) -> Vec<(SessionKey, Vec<Arc<MuxSession>>)> {
        self.registry()
            .entries
            .iter()
            .map(|(key, shards)| {
                let sockets = shards
                    .iter()
                    .map(|shard| Arc::clone(&shard.session))
                    .collect();
                (key.clone(), sockets)
            })
            .collect()
    }

    fn health_lock(&self) -> MutexGuard<'_, Health> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What a new socket of `relay` and `group` reports its health to.
    fn health_notes(&self, relay: &str, group: &str) -> HealthNotes {
        let health = Arc::clone(&self.health);
        let events = self.health_events.clone();
        let (relay, group) = (relay.to_owned(), group.to_owned());
        Arc::new(move |note| {
            let raised = health
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .note(&relay, &group, &note);
            for event in raised {
                // No watcher is not a problem.
                let _ = events.send(event);
            }
        })
    }

    /// Whether the sockets of `relay` that it refused push are to be dropped, so that the next
    /// one asks it again.
    fn ask_again_due(&self, relay: &str) -> bool {
        self.health_lock().ask_again_due(relay, Instant::now())
    }

    /// The health of each relay (`domain:port`) a socket reported on. A relay keeps its record
    /// after its sockets are released or stopped, for as long as this process runs or until
    /// [`PushedSessions::clear`]: one record per relay the process greeted, so it is bounded by
    /// the relays it was told to use.
    pub fn health(&self) -> BTreeMap<String, MailboxHealth> {
        self.health_lock()
            .records
            .iter()
            .map(|(relay, record)| (relay.clone(), record.health.clone()))
            .collect()
    }

    /// Records a post to `relay` (`domain:port`) made outside the sessions, on a short
    /// connection: `failure` is `None` when the mailbox answered it, taken or refused, and why
    /// it could not be reached otherwise. A failure sets [`MailboxHealth::post_retry_at`],
    /// 30 s after the first and doubling to 10 min, and [`MailboxHealth::last_error`]; an
    /// answer clears the post fields. The record only informs: a mailbox stays in the list.
    pub fn note_post(&self, relay: &str, failure: Option<&str>) {
        self.health_lock()
            .note_post(relay, failure, SystemTime::now());
    }

    fn changed(&self) {
        self.changed
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Sets the config the contacts collect reads pushed mail with (`Some`), or leaves the choice
    /// to the collect (`None`). Does not touch the sessions already running: see
    /// [`PushedSessions::release`].
    pub fn set_contacts(&self, config: Option<PushedConfig>) {
        self.registry().contacts = config;
    }

    /// The config the contacts collect reads pushed mail with, if a host set one.
    pub fn contacts(&self) -> Option<PushedConfig> {
        self.registry().contacts.clone()
    }

    /// The first socket of `relay` and `group` that has not been stopped, if there is one.
    pub fn get(&self, relay: &str, group: &str) -> Option<Arc<MuxSession>> {
        let registry = self.registry();
        let shards = registry
            .entries
            .get(&(relay.to_owned(), group.to_owned()))?;
        shards
            .iter()
            .find(|shard| shard.state() != MuxState::Stopped)
            .map(|shard| Arc::clone(&shard.session))
    }

    /// Every socket on `relay` that has not been stopped, whatever its group.
    pub fn on_relay(&self, relay: &str) -> Vec<Arc<MuxSession>> {
        self.registry()
            .entries
            .iter()
            .filter(|((on, _), _)| on == relay)
            .flat_map(|(_, shards)| shards)
            .filter(|shard| shard.state() != MuxState::Stopped)
            .map(|shard| Arc::clone(&shard.session))
            .collect()
    }

    /// Whether `relay` (`domain:port`) offers mux/1, as a socket last read it in the relay's
    /// answer to the greeting: [`MailboxHealth::push`] of its record, `None` without one. A
    /// relay that answered without it is asked again (see [`MailboxHealth::ask_again_at`]).
    /// Opens no connection.
    pub fn supports_push(&self, relay: &str) -> Option<bool> {
        self.health_lock()
            .records
            .get(relay)
            .and_then(|record| record.health.push)
    }

    /// A socket of `relay` and `group` for an owner of one mailbox, with `owner` added to its
    /// owners: the first one `owner` already uses, else the first with room for one more
    /// mailbox. `start` makes a new socket when none has room, or there is none. A session the
    /// relay does not offer stays in the registry until the relay is to be asked again
    /// ([`MailboxHealth::ask_again_at`]), so a pass does not dial it sooner.
    ///
    /// The room is as of the last claim each socket applied, so two owners that join at once
    /// may both pick the last place; the claim of the second is refused.
    pub fn get_or_start(
        &self,
        relay: &str,
        group: &str,
        owner: Owner,
        start: impl FnOnce() -> Result<MuxSession, MuxError>,
    ) -> Result<Arc<MuxSession>, MuxError> {
        let ask_again = self.ask_again_due(relay);
        let mut registry = self.registry();
        let shards = registry
            .entries
            .entry((relay.to_owned(), group.to_owned()))
            .or_default();
        let mut changed = prune(shards, ask_again);
        // A refused socket is used only when no socket of the session runs: one socket the
        // relay refused does not take the owner off the others.
        let any_live = shards.iter().any(Shard::is_live);
        let found = shards
            .iter()
            .position(|shard| shard.owners.contains(&owner) && (shard.is_live() || !any_live))
            .or_else(|| {
                shards.iter().position(|shard| {
                    shard.is_live()
                        && shard
                            .capacity_for(owner)
                            .saturating_sub(shard.session.claimed_keys(owner.as_str()).len())
                            > 0
                })
            })
            .or_else(|| {
                shards
                    .iter()
                    .position(|shard| shard.state() == MuxState::NotOffered)
            });
        let session = match found.and_then(|at| shards.get_mut(at)) {
            Some(shard) => {
                shard.owners.insert(owner);
                Ok(Arc::clone(&shard.session))
            }
            None => start().map(|session| {
                let shard = Shard::new(session, owner, self.health_notes(relay, group));
                let session = Arc::clone(&shard.session);
                shards.push(shard);
                changed = true;
                session
            }),
        };
        registry.entries.retain(|_, shards| !shards.is_empty());
        drop(registry);
        if changed {
            self.changed();
        }
        session
    }

    /// Spreads the mailboxes `keys` of `owner` ([`crate::EpicboxAddress::key_text`],
    /// each once) over the sockets of `relay` and `group`, and returns each socket that is to
    /// carry some with the keys it is to claim, in socket order. The caller then claims them:
    /// [`MuxSession::set_claim`] on each, or [`MuxSession::add_to_claim`] with `add`.
    ///
    /// A key `owner` already claims on a socket stays there, so no other mailbox moves when one
    /// is added or removed. New keys fill the sockets in order, as far as each has room; `start`
    /// makes a new socket when none has. Without `add`, a socket whose limit dropped below what
    /// `owner` claims there gives up the keys past it to the others, and `owner` leaves the
    /// sockets it no longer needs: a socket nobody else owns is stopped. With `add`, `owner`
    /// keeps what it claims and gains `keys`. With no keys, `owner` keeps or starts one socket,
    /// to claim nothing on.
    ///
    /// When the relay does not offer mux/1 and no socket of the session runs, the one socket it
    /// refused carries every key: the caller sees that it has ended. When other sockets run,
    /// they carry the keys as far as they have room, and no new socket is started; the keys left
    /// over are left out with [`MuxError::NotOffered`]. Once the relay is to be asked again, or
    /// a socket of the relay was offered push since, the refused socket is dropped and the keys
    /// are placed afresh. Keys left over when `start` fails are left out; the
    /// error is returned only when no socket takes any.
    pub fn place(
        &self,
        relay: &str,
        group: &str,
        owner: Owner,
        keys: &[String],
        add: bool,
        mut start: impl FnMut() -> Result<MuxSession, MuxError>,
    ) -> Result<Vec<Placement>, MuxError> {
        let ask_again = self.ask_again_due(relay);
        let mut registry = self.registry();
        let shards = registry
            .entries
            .entry((relay.to_owned(), group.to_owned()))
            .or_default();
        let mut changed = prune(shards, ask_again);
        let any_live = shards.iter().any(Shard::is_live);
        if !any_live
            && let Some(shard) = shards
                .iter_mut()
                .find(|shard| shard.state() == MuxState::NotOffered)
        {
            shard.owners.insert(owner);
            let placed = vec![Placement {
                session: Arc::clone(&shard.session),
                keys: keys.to_vec(),
            }];
            drop(registry);
            if changed {
                self.changed();
            }
            return Ok(placed);
        }
        // The sockets the relay refused while others run are set aside until it is asked
        // again: the running ones carry the keys, and no new socket is dialled meanwhile.
        let (refused, running): (Vec<Shard>, Vec<Shard>) = std::mem::take(shards)
            .into_iter()
            .partition(|shard| shard.state() == MuxState::NotOffered);
        *shards = running;
        let mut layout = Layout::of(shards, owner, add);
        let mut failed = layout.fill(keys, add, || {
            if !refused.is_empty() {
                return Err(MuxError::NotOffered);
            }
            let shard = Shard::new(start()?, owner, self.health_notes(relay, group));
            shards.push(shard);
            changed = true;
            Ok(())
        });
        if keys.is_empty() {
            match shards
                .iter()
                .position(|shard| shard.owners.contains(&owner))
                .or((!shards.is_empty()).then_some(0))
            {
                Some(at) => layout.keep = Some(at),
                None => match start() {
                    Ok(session) => {
                        shards.push(Shard::new(session, owner, self.health_notes(relay, group)));
                        layout.assigned.push(Vec::new());
                        layout.keep = shards.len().checked_sub(1);
                        changed = true;
                    }
                    Err(error) => failed = Some(error),
                },
            }
        }
        let mut placed = Vec::new();
        let mut released = Vec::new();
        let before = std::mem::take(shards);
        for (at, (mut shard, keys)) in before.into_iter().zip(layout.assigned).enumerate() {
            if !keys.is_empty() || layout.keep == Some(at) {
                shard.owners.insert(owner);
                placed.push(Placement {
                    session: Arc::clone(&shard.session),
                    keys,
                });
            } else if !add && shard.owners.remove(&owner) && !shard.owners.is_empty() {
                released.push(Arc::clone(&shard.session));
            }
            if shard.owners.is_empty() {
                changed = true;
                continue;
            }
            shards.push(shard);
        }
        shards.extend(refused);
        registry.entries.retain(|_, shards| !shards.is_empty());
        drop(registry);
        for session in released {
            // An ended socket has nothing to release.
            let _ = session.release_claim(owner.as_str());
        }
        if changed {
            self.changed();
        }
        match failed {
            Some(error) if placed.is_empty() => Err(error),
            _ => Ok(placed),
        }
    }

    /// Lets go of every socket `owner` uses: its claim is emptied, and a socket nobody else
    /// owns is stopped. Does not wait for a socket to apply the claim: one that is still
    /// opening would hold the caller up.
    pub fn release(&self, owner: Owner) {
        self.release_where(owner, |_| true);
        self.changed();
    }

    /// [`PushedSessions::release`] on every relay but those of `kept` (`domain:port`): `owner`
    /// has no mailbox there any more. Tells the watchers only when it let go of something.
    pub fn release_except(&self, owner: Owner, kept: &BTreeSet<String>) {
        if self.release_where(owner, |relay| !kept.contains(relay)) {
            self.changed();
        }
    }

    /// Lets go of the sockets `owner` uses on the relays `on` picks, as
    /// [`PushedSessions::release`] says, and tells whether there was one.
    fn release_where(&self, owner: Owner, on: impl Fn(&str) -> bool) -> bool {
        let mut claimed = Vec::new();
        let mut any = false;
        {
            let mut registry = self.registry();
            for ((relay, _), shards) in &mut registry.entries {
                if !on(relay) {
                    continue;
                }
                shards.retain(|shard| {
                    if !shard.owners.contains(&owner) {
                        return true;
                    }
                    any = true;
                    if shard.owners.len() == 1 {
                        return false;
                    }
                    claimed.push(Arc::clone(&shard.session));
                    true
                });
                for shard in shards.iter_mut() {
                    shard.owners.remove(&owner);
                }
            }
            registry.entries.retain(|_, shards| !shards.is_empty());
            let kept: BTreeSet<&String> = registry.entries.keys().map(|(relay, _)| relay).collect();
            for (relay, record) in &mut self.health_lock().records {
                if !kept.contains(relay) {
                    record.reachable = None;
                }
            }
        }
        for session in claimed {
            // An ended socket has nothing to release.
            let _ = session.release_claim(owner.as_str());
        }
        any
    }

    /// Stops every socket and forgets the contacts config.
    pub fn clear(&self) {
        {
            let mut registry = self.registry();
            registry.contacts = None;
            registry.entries.clear();
            *self.health_lock() = Health::default();
        }
        self.changed();
    }

    /// Every session, by relay and group.
    pub fn infos(&self) -> Vec<SessionInfo> {
        self.registry()
            .entries
            .iter()
            .map(|((relay, group), shards)| SessionInfo {
                relay: relay.clone(),
                group: group.clone(),
                state: state_of_all(shards.iter().map(Shard::state)),
                counters: shards.iter().map(|shard| shard.session.counters()).sum(),
                last_error: shards.iter().find_map(|shard| shard.session.last_error()),
            })
            .collect()
    }

    /// Reports what the sessions do, for as long as the returned future is polled: each session
    /// with its state when it appears and at every change, a note when mail was queued, and
    /// the health events ([`SessionEvent::NoneReachable`], [`SessionEvent::MailboxBack`]). A
    /// session that was removed reports `Stopped` and is not followed any more. Counters are not
    /// part of the events; read them with [`PushedSessions::infos`].
    pub async fn watch(&self, report: impl Fn(SessionEvent) + Send + Sync + 'static) {
        let report = Arc::new(report);
        let mut changes = self.changed.subscribe();
        let mut health = self.health_events.subscribe();
        let mut tasks = JoinSet::new();
        let mut watched = Watched::new();
        loop {
            changes.borrow_and_update();
            follow(&mut watched, &mut tasks, self.sessions(), &report);
            // The tasks that ended are not awaited; a finished task of a replaced socket set is
            // dropped when the join set is.
            while tasks.try_join_next().is_some() {}
            loop {
                tokio::select! {
                    changed = changes.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        break;
                    }
                    event = health.recv() => match event {
                        Ok(event) => report(event),
                        // A watcher that fell behind reads the records with `health`.
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => return,
                    },
                }
            }
        }
    }
}

/// The keys a [`PushedSessions::place`] call gives each socket.
struct Layout {
    /// The keys for each socket, by its position.
    assigned: Vec<Vec<String>>,
    /// How many more keys each socket takes.
    free: Vec<usize>,
    /// The keys the owner claims on each socket now.
    claimed: Vec<BTreeSet<String>>,
    /// A socket that carries no key but is kept for the owner.
    keep: Option<usize>,
    /// The cap a new socket is expected to have: the lowest a relay named on this session.
    cap: usize,
}

impl Layout {
    fn of(shards: &[Shard], owner: Owner, add: bool) -> Self {
        let claimed: Vec<BTreeSet<String>> = shards
            .iter()
            .map(|shard| shard.session.claimed_keys(owner.as_str()))
            .collect();
        let free = shards
            .iter()
            .zip(&claimed)
            .map(|(shard, claimed)| {
                let capacity = shard.capacity_for(owner);
                if add {
                    capacity.saturating_sub(claimed.len())
                } else {
                    capacity
                }
            })
            .collect();
        let cap = shards
            .iter()
            .map(|shard| shard.session.mailbox_cap())
            .min()
            .unwrap_or(MAX_MAILBOXES_PER_SOCKET)
            .max(1);
        Self {
            assigned: vec![Vec::new(); shards.len()],
            free,
            claimed,
            keep: None,
            cap,
        }
    }

    /// Gives each key a socket: the one that claims it, if it still has room for it (with
    /// `add`, it always does), else the first with room, else a new one from `start`. Returns
    /// the error of a `start` that failed; the keys left then are not given any.
    fn fill(
        &mut self,
        keys: &[String],
        add: bool,
        mut start: impl FnMut() -> Result<(), MuxError>,
    ) -> Option<MuxError> {
        let mut left = Vec::new();
        for key in keys {
            let home = self
                .claimed
                .iter()
                .position(|claimed| claimed.contains(key));
            match home {
                Some(at) if add => self.give(at, key, false),
                Some(at) if self.free.get(at).is_some_and(|free| *free > 0) => {
                    self.give(at, key, true);
                }
                _ => left.push(key),
            }
        }
        for key in left {
            let at = match self.free.iter().position(|free| *free > 0) {
                Some(at) => at,
                None => {
                    if let Err(error) = start() {
                        return Some(error);
                    }
                    self.assigned.push(Vec::new());
                    self.free.push(self.cap);
                    self.claimed.push(BTreeSet::new());
                    self.free.len().saturating_sub(1)
                }
            };
            self.give(at, key, true);
        }
        None
    }

    fn give(&mut self, at: usize, key: &str, uses_room: bool) {
        if let Some(keys) = self.assigned.get_mut(at) {
            keys.push(key.to_owned());
        }
        if uses_room && let Some(free) = self.free.get_mut(at) {
            *free = free.saturating_sub(1);
        }
    }
}

/// The state of a session from the states of its sockets: `NotOffered` when the relay refused
/// mux/1 to a socket and none runs, `Attached` when every running socket is, otherwise the state
/// of the least ready one (waiting to reconnect, then connecting), and `Stopped` when every socket
/// is.
fn state_of_all(states: impl IntoIterator<Item = MuxState>) -> MuxState {
    let mut least: Option<MuxState> = None;
    let mut refused = false;
    for state in states {
        match state {
            MuxState::Stopped => {}
            MuxState::NotOffered => refused = true,
            _ => {
                if least.is_none_or(|known| readiness(state) < readiness(known)) {
                    least = Some(state);
                }
            }
        }
    }
    match least {
        Some(state) => state,
        None if refused => MuxState::NotOffered,
        None => MuxState::Stopped,
    }
}

/// How close a running socket is to reading mail.
fn readiness(state: MuxState) -> u8 {
    match state {
        MuxState::Attached => 2,
        MuxState::Connecting { .. } => 1,
        // Waiting, and any state a later version adds.
        _ => 0,
    }
}

/// The sessions being followed, by key.
type Watched = BTreeMap<SessionKey, Followed>;

/// A session being followed: its sockets, the task that follows them, and what was said.
struct Followed {
    /// Tells this set of sockets apart from a later one under the same key.
    sockets: Vec<Weak<MuxSession>>,
    task: AbortHandle,
    said: Arc<Mutex<Said>>,
}

/// What was last reported for a session, shared by the tasks that follow it in turn.
#[derive(Default)]
struct Said {
    /// The state last reported, if any was.
    state: Option<MuxState>,
    /// The turn of the task that may report; a task that was replaced says nothing more.
    turn: u64,
}

fn same_sockets(followed: &[Weak<MuxSession>], now: &[Arc<MuxSession>]) -> bool {
    followed.len() == now.len()
        && followed
            .iter()
            .zip(now)
            .all(|(old, new)| Weak::ptr_eq(old, &Arc::downgrade(new)))
}

/// Follows `current`: a session whose sockets changed gets a new task, which carries on from
/// what the old one said; a session that was removed is reported stopped, unless it had
/// ended already.
fn follow(
    watched: &mut Watched,
    tasks: &mut JoinSet<()>,
    current: Vec<(SessionKey, Vec<Arc<MuxSession>>)>,
    report: &Arc<impl Fn(SessionEvent) + Send + Sync + 'static>,
) {
    let mut next = Watched::new();
    for (key, sockets) in current {
        let said = match watched.remove(&key) {
            Some(followed) if same_sockets(&followed.sockets, &sockets) => {
                next.insert(key, followed);
                continue;
            }
            Some(followed) => {
                followed.task.abort();
                followed.said
            }
            None => Arc::default(),
        };
        let turn = {
            let mut said = lock(&said);
            said.turn = said.turn.wrapping_add(1);
            said.turn
        };
        // Subscribed before the task reads the states, so no change in between is missed.
        let receivers = sockets
            .iter()
            .map(|socket| (socket.state(), socket.queued()))
            .collect();
        let weak: Vec<Weak<MuxSession>> = sockets.iter().map(Arc::downgrade).collect();
        let task = tasks.spawn(watch_one(
            key.clone(),
            weak.clone(),
            receivers,
            Arc::clone(&said),
            turn,
            Arc::clone(report),
        ));
        next.insert(
            key,
            Followed {
                sockets: weak,
                task,
                said,
            },
        );
    }
    for ((relay, group), followed) in std::mem::replace(watched, next) {
        followed.task.abort();
        let mut said = lock(&followed.said);
        said.turn = said.turn.wrapping_add(1);
        // One that already ended said so itself.
        if !said.state.is_some_and(|state| state.has_ended()) {
            said.state = Some(MuxState::Stopped);
            report(SessionEvent::State {
                relay,
                group,
                state: MuxState::Stopped,
            });
        }
    }
}

fn lock(said: &Mutex<Said>) -> MutexGuard<'_, Said> {
    said.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Something changed on one socket.
enum Stir {
    State,
    Queued,
}

/// Reports the state changes and queued mail of one session's sockets until the session ends or
/// the task is replaced. Each report is made under the lock of `said`, so a task that was
/// replaced, and is still running until its abort lands, cannot report out of turn.
async fn watch_one(
    (relay, group): SessionKey,
    sockets: Vec<Weak<MuxSession>>,
    receivers: Vec<(watch::Receiver<MuxState>, watch::Receiver<u64>)>,
    said: Arc<Mutex<Said>>,
    turn: u64,
    report: Arc<impl Fn(SessionEvent) + Send + Sync + 'static>,
) {
    let (stirs, mut stirred) = mpsc::unbounded_channel();
    let mut followers = JoinSet::new();
    for (state, queued) in receivers {
        followers.spawn(follow_socket(state, queued, stirs.clone()));
    }
    drop(stirs);
    let mut gone = false;
    loop {
        let now = state_of_all(sockets.iter().map(|socket| {
            socket
                .upgrade()
                .map_or(MuxState::Stopped, |socket| *socket.state().borrow())
        }));
        {
            let mut said = lock(&said);
            if said.turn != turn {
                return;
            }
            if said.state != Some(now) {
                said.state = Some(now);
                report(SessionEvent::State {
                    relay: relay.clone(),
                    group: group.clone(),
                    state: now,
                });
            }
        }
        if now.has_ended() || gone {
            return;
        }
        match stirred.recv().await {
            Some(Stir::State) => {}
            Some(Stir::Queued) => {
                let said = lock(&said);
                if said.turn != turn {
                    return;
                }
                report(SessionEvent::MailQueued {
                    relay: relay.clone(),
                    group: group.clone(),
                });
            }
            // Every socket is gone: one more look reports them stopped.
            None => gone = true,
        }
    }
}

/// Tells `stirs` of each change of one socket's state and queue, until the socket is gone or
/// nobody listens.
async fn follow_socket(
    mut state: watch::Receiver<MuxState>,
    mut queued: watch::Receiver<u64>,
    stirs: mpsc::UnboundedSender<Stir>,
) {
    loop {
        let stir = tokio::select! {
            changed = state.changed() => {
                if changed.is_err() {
                    let _ = stirs.send(Stir::State);
                    return;
                }
                state.borrow_and_update();
                Stir::State
            }
            changed = queued.changed() => {
                if changed.is_err() {
                    let _ = stirs.send(Stir::State);
                    return;
                }
                queued.borrow_and_update();
                Stir::Queued
            }
        };
        if stirs.send(stir).is_err() {
            return;
        }
    }
}

impl std::fmt::Debug for PushedSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registry = self.registry();
        f.debug_struct("PushedSessions")
            .field("sessions", &registry.entries.len())
            .field(
                "sockets",
                &registry.entries.values().map(Vec::len).sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use std::time::Duration;

    use lepic_crypto::{PublicKey, SecretKey};

    use crate::mock_mux::MuxMockRelay;
    use crate::testing::client_settings;
    use crate::{
        Domain, EpicboxAddress, Identity, Network, Nonce, RelayEndpoint, Salt, Security,
        SignedMessage,
    };

    use super::*;

    const RELAY: &str = "relay.test:80";
    const GROUP: &str = "wallet";

    fn secret(byte: u8) -> SecretKey {
        SecretKey::from_array([byte; 32]).unwrap()
    }

    fn address(byte: u8) -> EpicboxAddress {
        EpicboxAddress::new(
            PublicKey::from_secret_key(&secret(byte)).unwrap(),
            Network::Mainnet,
            Domain::parse("relay.test").unwrap(),
            None,
        )
    }

    fn identity(byte: u8) -> Identity {
        Identity::new(secret(byte), address(byte)).unwrap()
    }

    fn key(byte: u8) -> String {
        address(byte).key_text()
    }

    fn keys(bytes: &[u8]) -> Vec<String> {
        bytes.iter().map(|byte| key(*byte)).collect()
    }

    fn starter(relay: &MuxMockRelay) -> impl FnMut() -> Result<MuxSession, MuxError> + '_ {
        move || {
            let endpoint =
                RelayEndpoint::new(Domain::parse("relay.test").unwrap(), None, Security::Plain);
            MuxSession::start_queued(
                client_settings(endpoint),
                relay.connector(),
                Vec::new(),
                MuxOptions {
                    waiting_every: None,
                    ..MuxOptions::default()
                },
            )
        }
    }

    /// Places `bytes` for `owner` and claims each socket's share, as the contacts collect does.
    async fn claim(
        sessions: &PushedSessions,
        relay: &MuxMockRelay,
        owner: Owner,
        bytes: &[u8],
        add: bool,
    ) -> Vec<Vec<String>> {
        let placed = sessions
            .place(RELAY, GROUP, owner, &keys(bytes), add, starter(relay))
            .unwrap();
        let mut shares = Vec::new();
        for placement in placed {
            let share: Vec<Identity> = bytes
                .iter()
                .filter(|byte| placement.keys.contains(&key(**byte)))
                .map(|byte| identity(*byte))
                .collect();
            if add {
                placement
                    .session
                    .add_to_claim(owner.as_str(), share)
                    .await
                    .unwrap();
            } else {
                placement
                    .session
                    .set_claim(owner.as_str(), share)
                    .await
                    .unwrap();
            }
            shares.push(placement.keys);
        }
        shares
    }

    async fn until(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("timed out");
    }

    fn info(sessions: &PushedSessions) -> SessionInfo {
        let mut infos = sessions.infos();
        assert_eq!(infos.len(), 1);
        infos.remove(0)
    }

    /// A session of `bytes` for the contacts on a relay that holds `limit` mailboxes a socket,
    /// started with no claim first so the limit is known, as a collect pass finds it.
    async fn spread(limit: usize, bytes: &[u8]) -> (PushedSessions, MuxMockRelay) {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.set_mailboxes_per_socket(limit);
        let sessions = PushedSessions::default();
        claim(&sessions, &relay, Owner::Contacts, &[], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        claim(&sessions, &relay, Owner::Contacts, bytes, false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        (sessions, relay)
    }

    /// Mailboxes named in the `Attach` and `Detach` frames the relay received.
    fn moves(relay: &MuxMockRelay) -> (usize, usize) {
        let named = |name: &str| {
            relay
                .frames(name)
                .iter()
                .map(|frame| frame["mailboxes"].as_array().map_or(0, Vec::len))
                .sum()
        };
        (named("Attach"), named("Detach"))
    }

    #[tokio::test]
    async fn a_relay_that_offered_mux_supports_push() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let sessions = PushedSessions::default();
        claim(&sessions, &relay, Owner::Contacts, &[1], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        assert_eq!(sessions.supports_push(RELAY), Some(true));
        assert_eq!(sessions.supports_push("other.test:80"), None);
    }

    #[tokio::test]
    async fn a_relay_that_answered_without_mux_does_not_support_push() {
        // An answer without mux/1, then an error in place of an answer.
        for error in [false, true] {
            let relay = MuxMockRelay::new(Network::Mainnet);
            if error {
                relay.answer_greeting_with_error(true);
            } else {
                relay.offer_mux(false);
            }
            let sessions = PushedSessions::default();
            sessions
                .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
                .unwrap();
            until(|| info(&sessions).state == MuxState::NotOffered).await;
            assert_eq!(sessions.supports_push(RELAY), Some(false));
        }
    }

    #[tokio::test]
    async fn a_relay_keeps_its_answer_after_the_refused_session_is_released() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.offer_mux(false);
        let sessions = PushedSessions::default();
        assert!(sessions.health().is_empty());
        sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        until(|| sessions.supports_push(RELAY).is_some()).await;
        // Released before anything watched the sessions: nothing else saw the answer.
        sessions.release(Owner::Payments);
        assert!(sessions.infos().is_empty());
        assert_eq!(sessions.supports_push(RELAY), Some(false));
        let health = sessions.health();
        let record = health.get(RELAY).unwrap();
        assert_eq!(record.push, Some(false), "{record:?}");
        assert_eq!(record.group, GROUP);
        assert!(record.ask_again_at.is_some());

        // A later attach on the same relay overwrites the answer.
        relay.offer_mux(true);
        sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        until(|| info(&sessions).state == MuxState::Attached).await;
        let health = sessions.health();
        assert_eq!(health.len(), 1);
        let record = health.get(RELAY).unwrap();
        assert_eq!(record.push, Some(true));
        assert_eq!(record.ask_again_at, None);
        assert!(record.last_success.is_some());
    }

    #[tokio::test]
    async fn one_socket_refused_push_leaves_the_running_sockets_their_mailboxes() {
        // One socket attached, then the relay refuses push to a second one, as a mailbox at its
        // connection limit does.
        let (sessions, relay) = spread(2, &[1, 2]).await;
        let first = sessions.get(RELAY, GROUP).unwrap();
        relay.offer_mux(false);
        let placed = sessions
            .place(
                RELAY,
                GROUP,
                Owner::Contacts,
                &keys(&[1, 2, 3, 4]),
                false,
                starter(&relay),
            )
            .unwrap();
        assert_eq!(placed.len(), 2);
        let second = Arc::clone(&placed[1].session);
        until(|| *second.state().borrow() == MuxState::NotOffered).await;
        relay.offer_mux(true);
        assert_eq!(sessions.supports_push(RELAY), Some(false));
        assert!(sessions.health()[RELAY].ask_again_at.is_some());
        // The session still reads on the socket that runs.
        assert_eq!(info(&sessions).state, MuxState::Attached);
        let made = relay.sockets_made();

        // Before the relay is asked again: the running socket keeps its mailboxes, the rest
        // wait, and nothing dials the relay.
        let placed = sessions
            .place(
                RELAY,
                GROUP,
                Owner::Contacts,
                &keys(&[1, 2, 3, 4]),
                false,
                starter(&relay),
            )
            .unwrap();
        assert_eq!(placed.len(), 1);
        assert!(Arc::ptr_eq(&placed[0].session, &first));
        assert_eq!(placed[0].keys, keys(&[1, 2]));
        assert_eq!(relay.sockets_made(), made);

        // The running socket greets the relay again and is offered push: the refused socket is
        // dropped, and the next placement asks the relay again for the rest.
        relay.drop_sockets();
        until(|| sessions.supports_push(RELAY) == Some(true)).await;
        assert_eq!(sessions.health()[RELAY].ask_again_at, None);
        claim(&sessions, &relay, Owner::Contacts, &[1, 2, 3, 4], false).await;
        until(|| (1..=4).all(|byte| relay.attached().contains(&key(byte)))).await;
        assert!(
            sessions
                .on_relay(RELAY)
                .iter()
                .all(|session| !session.state().borrow().has_ended())
        );
    }

    #[tokio::test]
    async fn a_mailbox_that_answered_without_push_is_asked_again_and_used_once_it_offers_it() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.offer_mux(false);
        let sessions = PushedSessions::default();
        sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        until(|| info(&sessions).state == MuxState::NotOffered).await;

        // Before its time the refused socket is kept, and nothing dials the mailbox again.
        sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        let placed = sessions
            .place(
                RELAY,
                GROUP,
                Owner::Contacts,
                &keys(&[1]),
                false,
                starter(&relay),
            )
            .unwrap();
        assert_eq!(placed.len(), 1);
        assert_eq!(*placed[0].session.state().borrow(), MuxState::NotOffered);
        assert_eq!(relay.sockets_made(), 1);
        assert_eq!(info(&sessions).state, MuxState::NotOffered);

        relay.offer_mux(true);
        sessions
            .health_lock()
            .records
            .get_mut(RELAY)
            .unwrap()
            .ask_again = Some(Instant::now());
        claim(&sessions, &relay, Owner::Contacts, &[1], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        assert_eq!(relay.sockets_made(), 2);
        until(|| relay.attached().contains(&key(1))).await;
        assert_eq!(sessions.supports_push(RELAY), Some(true));
        assert_eq!(sessions.health().get(RELAY).unwrap().ask_again_at, None);
    }

    #[test]
    fn the_wait_before_asking_again_doubles_up_to_an_hour() {
        let waits: Vec<u64> = [1, 2, 3, 6, 7, 40, u32::MAX]
            .into_iter()
            .map(|answers| ask_again_after(answers).as_secs())
            .collect();
        assert_eq!(waits, [60, 120, 240, 1920, 3600, 3600, 3600]);
    }

    #[test]
    fn none_reachable_is_raised_once_and_a_mailbox_coming_back_is_reported() {
        let mut health = Health::default();
        let lost = |text: &str| HealthNote::Lost(text.to_owned());
        assert!(
            health
                .note("a:443", GROUP, &HealthNote::Attached)
                .is_empty()
        );
        assert!(
            health
                .note("b:443", GROUP, &HealthNote::Attached)
                .is_empty()
        );
        assert!(health.note("a:443", GROUP, &lost("reset")).is_empty());
        assert_eq!(
            health.note("b:443", GROUP, &lost("closed")),
            [SessionEvent::NoneReachable]
        );
        // Still none, said once.
        assert!(health.note("b:443", GROUP, &lost("closed")).is_empty());
        assert!(
            health
                .note("a:443", GROUP, &HealthNote::Greeted(false))
                .is_empty()
        );

        let record = &health.records["b:443"].health;
        assert_eq!(record.failures, 2);
        assert_eq!(record.last_error.as_deref(), Some("closed"));
        assert!(record.last_success.is_some());

        assert!(
            health
                .note("b:443", GROUP, &HealthNote::Greeted(true))
                .is_empty()
        );
        assert_eq!(
            health.note("b:443", GROUP, &HealthNote::Attached),
            [SessionEvent::MailboxBack {
                relay: "b:443".to_owned()
            }]
        );
        let record = &health.records["b:443"].health;
        assert_eq!((record.failures, record.last_error.as_deref()), (0, None));
        // One is back: losing the other one raises nothing.
        assert!(health.note("a:443", GROUP, &lost("reset")).is_empty());
        assert_eq!(
            health.note("b:443", GROUP, &lost("closed")),
            [SessionEvent::NoneReachable]
        );
    }

    #[test]
    fn a_mailbox_first_attaching_after_none_reachable_is_reported_back() {
        let mut health = Health::default();
        // The first mailbox fails before the second has answered.
        assert_eq!(
            health.note("a:443", GROUP, &HealthNote::Lost("reset".to_owned())),
            [SessionEvent::NoneReachable]
        );
        assert_eq!(
            health.note("b:443", GROUP, &HealthNote::Attached),
            [SessionEvent::MailboxBack {
                relay: "b:443".to_owned()
            }]
        );
        assert!(!health.none_reachable);
    }

    #[tokio::test]
    async fn the_watch_reports_a_mailbox_lost_and_back() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let sessions = Arc::new(PushedSessions::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let watching = tokio::spawn({
            let sessions = Arc::clone(&sessions);
            let events = Arc::clone(&events);
            async move {
                sessions
                    .watch(move |event| events.lock().unwrap().push(event))
                    .await;
            }
        });
        let said = |wanted: &SessionEvent| events.lock().unwrap().contains(wanted);
        claim(&sessions, &relay, Owner::Contacts, &[1], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;

        relay.drop_sockets();
        until(|| said(&SessionEvent::NoneReachable)).await;
        let back = SessionEvent::MailboxBack {
            relay: RELAY.to_owned(),
        };
        until(|| said(&back)).await;
        let record = sessions.health().remove(RELAY).unwrap();
        assert_eq!(record.failures, 0);
        assert!(record.last_success.is_some());
        watching.abort();
    }

    #[tokio::test]
    async fn a_session_keeps_why_it_lost_its_socket_until_it_attaches_again() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        let sessions = PushedSessions::default();
        sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        until(|| info(&sessions).state == MuxState::Attached).await;
        assert_eq!(info(&sessions).last_error, None);

        relay.rate_limit_attaches(1, 0);
        claim(&sessions, &relay, Owner::Payments, &[1], true).await;
        until(|| info(&sessions).last_error.is_some()).await;
        let text = info(&sessions).last_error.unwrap();
        assert!(text.contains("rate limited"), "{text}");

        until(|| info(&sessions).state == MuxState::Attached).await;
        assert_eq!(info(&sessions).last_error, None);
    }

    #[tokio::test]
    async fn a_relay_whose_greeting_was_not_answered_is_not_known() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.ignore_greeting(true);
        let sessions = PushedSessions::default();
        assert_eq!(sessions.supports_push(RELAY), None);
        sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        until(|| relay.received("ClientDetails") >= 1).await;
        assert_eq!(sessions.supports_push(RELAY), None);
    }

    #[tokio::test]
    async fn a_relay_that_never_answers_the_greeting_does_not_support_push() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.ignore_greeting(true);
        let sessions = PushedSessions::default();
        sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, || {
                let endpoint =
                    RelayEndpoint::new(Domain::parse("relay.test").unwrap(), None, Security::Plain);
                let mut quick = client_settings(endpoint);
                quick.response_timeout = Duration::from_millis(100);
                quick.backoff = crate::Backoff {
                    initial: Duration::from_millis(20),
                    max: Duration::from_millis(100),
                };
                MuxSession::start_queued(
                    quick,
                    relay.connector(),
                    Vec::new(),
                    MuxOptions::default(),
                )
            })
            .unwrap();
        until(|| info(&sessions).state == MuxState::NotOffered).await;
        assert_eq!(relay.received("ClientDetails"), 3);
        assert_eq!(sessions.supports_push(RELAY), Some(false));
    }

    #[tokio::test]
    async fn a_claim_past_the_relay_limit_opens_another_socket() {
        let (sessions, relay) = spread(2, &[1, 2, 3]).await;
        assert_eq!(relay.sockets_made(), 2);
        assert_eq!(
            relay.attached(),
            keys(&[1, 2, 3])
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
        );
        let info = info(&sessions);
        assert_eq!(info.counters.sockets_opened, 2);
        assert_eq!(sessions.on_relay(RELAY).len(), 2);
    }

    #[tokio::test]
    async fn adding_or_removing_a_mailbox_moves_no_other() {
        let (sessions, relay) = spread(2, &[1, 2, 3]).await;
        let before = moves(&relay);
        let shares = claim(&sessions, &relay, Owner::Contacts, &[1, 3, 4], false).await;
        assert_eq!(shares, vec![keys(&[1, 4]), keys(&[3])]);
        relay
            .wait_until(|relay| relay.attached().contains(&key(4)))
            .await;
        assert_eq!(moves(&relay), (before.0 + 1, before.1 + 1));
        assert!(!relay.attached().contains(&key(2)));

        // Added without the others: it takes the free place, and nothing is detached.
        let shares = claim(&sessions, &relay, Owner::Contacts, &[5], true).await;
        assert_eq!(shares, vec![keys(&[5])]);
        relay
            .wait_until(|relay| relay.attached().contains(&key(5)))
            .await;
        assert_eq!(moves(&relay), (before.0 + 2, before.1 + 1));
        assert_eq!(relay.sockets_made(), 2);
    }

    #[tokio::test]
    async fn a_socket_no_longer_needed_is_stopped() {
        let (sessions, relay) = spread(2, &[1, 2, 3]).await;
        let shares = claim(&sessions, &relay, Owner::Contacts, &[1], false).await;
        assert_eq!(shares, vec![keys(&[1])]);
        relay.wait_until(|relay| relay.sockets_open() == 1).await;
        assert_eq!(sessions.on_relay(RELAY).len(), 1);
    }

    #[tokio::test]
    async fn a_lower_limit_moves_only_the_mailboxes_past_it() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.set_mailboxes_per_socket(3);
        let sessions = PushedSessions::default();
        claim(&sessions, &relay, Owner::Contacts, &[], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        claim(&sessions, &relay, Owner::Contacts, &[1, 2, 3], false).await;
        relay.set_mailboxes_per_socket(2);
        relay.restart();
        let first = sessions.get(RELAY, GROUP).unwrap();
        until(|| first.mailbox_cap() == 2).await;
        let shares = claim(&sessions, &relay, Owner::Contacts, &[1, 2, 3], false).await;
        assert_eq!(shares, vec![keys(&[1, 2]), keys(&[3])]);
    }

    #[tokio::test]
    async fn the_payments_mailbox_finds_room_when_the_contacts_filled_a_socket() {
        let (sessions, relay) = spread(2, &[1, 2]).await;
        let payments = sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        payments
            .set_claim(Owner::Payments.as_str(), vec![identity(9)])
            .await
            .unwrap();
        assert_eq!(relay.sockets_made(), 2);
        relay
            .wait_until(|relay| relay.attached().contains(&key(9)))
            .await;
        // The contacts use the place left beside it.
        let shares = claim(&sessions, &relay, Owner::Contacts, &[1, 2, 3], false).await;
        assert_eq!(shares, vec![keys(&[1, 2]), keys(&[3])]);
        assert_eq!(relay.sockets_made(), 2);
    }

    #[tokio::test]
    async fn the_contacts_leave_a_place_for_a_payments_owner_that_joined() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.set_mailboxes_per_socket(2);
        let sessions = PushedSessions::default();
        claim(&sessions, &relay, Owner::Contacts, &[], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        let payments = sessions
            .get_or_start(RELAY, GROUP, Owner::Payments, starter(&relay))
            .unwrap();
        let shares = claim(&sessions, &relay, Owner::Contacts, &[1, 2], false).await;
        assert_eq!(shares, vec![keys(&[1]), keys(&[2])]);
        payments
            .set_claim(Owner::Payments.as_str(), vec![identity(9)])
            .await
            .unwrap();
        relay.wait_until(|relay| relay.attached().len() == 3).await;
    }

    #[tokio::test]
    async fn release_and_clear_stop_every_socket() {
        let (sessions, relay) = spread(2, &[1, 2, 3]).await;
        sessions.release(Owner::Contacts);
        assert!(sessions.infos().is_empty());
        relay.wait_until(|relay| relay.sockets_open() == 0).await;

        claim(&sessions, &relay, Owner::Contacts, &[], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        claim(&sessions, &relay, Owner::Contacts, &[1, 2, 3], false).await;
        relay.wait_until(|relay| relay.sockets_open() == 2).await;
        sessions.clear();
        assert!(sessions.infos().is_empty());
        relay.wait_until(|relay| relay.sockets_open() == 0).await;
    }

    #[tokio::test]
    async fn release_except_keeps_the_relays_kept_and_stops_the_rest() {
        let (sessions, relay) = spread(2, &[1, 2, 3]).await;
        sessions.release_except(Owner::Contacts, &BTreeSet::from([RELAY.to_owned()]));
        assert_eq!(sessions.infos().len(), 1);
        assert_eq!(relay.sockets_open(), 2);
        sessions.release_except(Owner::Contacts, &BTreeSet::new());
        assert!(sessions.infos().is_empty());
        relay.wait_until(|relay| relay.sockets_open() == 0).await;
    }

    #[test]
    fn a_session_is_as_ready_as_its_least_ready_socket() {
        let connecting = MuxState::Connecting { attempt: 1 };
        let waiting = MuxState::Waiting {
            attempt: 1,
            delay: Duration::from_secs(1),
        };
        assert_eq!(state_of_all([]), MuxState::Stopped);
        assert_eq!(
            state_of_all([MuxState::Attached, MuxState::Attached]),
            MuxState::Attached
        );
        assert_eq!(state_of_all([MuxState::Attached, connecting]), connecting);
        assert_eq!(
            state_of_all([connecting, waiting, MuxState::Attached]),
            waiting
        );
        assert_eq!(
            state_of_all([MuxState::Stopped, MuxState::Attached]),
            MuxState::Attached
        );
        // One socket refused while another runs: the session still reads.
        assert_eq!(
            state_of_all([MuxState::Attached, MuxState::NotOffered]),
            MuxState::Attached
        );
        assert_eq!(
            state_of_all([MuxState::NotOffered, MuxState::Stopped]),
            MuxState::NotOffered
        );
    }

    #[tokio::test]
    async fn the_watch_reports_a_session_once_for_all_its_sockets() {
        let relay = MuxMockRelay::new(Network::Mainnet);
        relay.set_mailboxes_per_socket(2);
        let sessions = Arc::new(PushedSessions::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let watching = tokio::spawn({
            let sessions = Arc::clone(&sessions);
            let events = Arc::clone(&events);
            async move {
                sessions
                    .watch(move |event| events.lock().unwrap().push(event))
                    .await;
            }
        });
        let said = |wanted: &SessionEvent| events.lock().unwrap().contains(wanted);
        let state = |state: MuxState| SessionEvent::State {
            relay: RELAY.to_owned(),
            group: GROUP.to_owned(),
            state,
        };
        claim(&sessions, &relay, Owner::Contacts, &[], false).await;
        until(|| said(&state(MuxState::Attached))).await;
        claim(&sessions, &relay, Owner::Contacts, &[1, 2, 3], false).await;
        until(|| info(&sessions).state == MuxState::Attached).await;
        until(|| events.lock().unwrap().last() == Some(&state(MuxState::Attached))).await;

        // Mail for the second socket is heard from the session.
        let sealed = SignedMessage::seal(
            "hello",
            &address(3),
            &secret(1),
            Salt::from([4; 8]),
            Nonce::from([5; 12]),
        )
        .unwrap();
        relay.store(&address(1), &address(3), &sealed);
        let queued = SessionEvent::MailQueued {
            relay: RELAY.to_owned(),
            group: GROUP.to_owned(),
        };
        until(|| said(&queued)).await;
        assert_eq!(info(&sessions).counters.mails, 1);

        sessions.clear();
        until(|| said(&state(MuxState::Stopped))).await;
        let events = events.lock().unwrap().clone();
        assert!(events.iter().all(|event| match event {
            SessionEvent::State { relay, group, .. }
            | SessionEvent::MailQueued { relay, group } => relay == RELAY && group == GROUP,
            SessionEvent::NoneReachable | SessionEvent::MailboxBack { .. } => false,
        }));
        let stopped = events
            .iter()
            .filter(|event| **event == state(MuxState::Stopped))
            .count();
        assert_eq!(stopped, 1);
        // No two reports in a row say the same state.
        let states: Vec<&SessionEvent> = events
            .iter()
            .filter(|event| matches!(event, SessionEvent::State { .. }))
            .collect();
        assert!(states.windows(2).all(|pair| pair[0] != pair[1]));
        watching.abort();
    }

    #[test]
    fn a_post_that_did_not_reach_a_mailbox_holds_posts_back_until_one_does() {
        let mut health = Health::default();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        health.note_post(RELAY, Some("connect failed"), start);
        let record = &health.records[RELAY].health;
        assert_eq!(record.post_failures, 1);
        assert_eq!(record.post_retry_at, Some(start + POST_RETRY_FIRST));
        assert_eq!(record.last_error.as_deref(), Some("connect failed"));
        for _ in 0..10 {
            health.note_post(RELAY, Some("connect failed"), start);
        }
        let record = &health.records[RELAY].health;
        assert_eq!(record.post_failures, 11);
        assert_eq!(record.post_retry_at, Some(start + POST_RETRY_MAX));
        // A post the mailbox answered clears the hold; the record stays, and so does the list.
        health.note_post(RELAY, None, start);
        let record = &health.records[RELAY].health;
        assert_eq!((record.post_failures, record.post_retry_at), (0, None));
        assert_eq!(post_retry_after(2), POST_RETRY_FIRST * 2);
        assert!(!health.none_reachable, "posts raise no reachability");
    }
}
