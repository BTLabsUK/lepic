//! The mux/1 sessions of one [`super::Epicbox`], shared by the consumers that read the same
//! relay: the contacts collect and the payments listener.
//!
//! A session is named by the relay it talks to and a group the host picks. Two consumers that
//! name the same group on the same relay get the same socket. Each consumer is an owner: it
//! keeps its own claim on the session's mailboxes (see [`lepic_epicbox::MuxSession::set_claim`]),
//! and a session lives until its last owner lets go.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use lepic_epicbox::{MuxCounters, MuxError, MuxOptions, MuxSession, MuxState};
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinSet};

/// The claim owner of the contacts collect.
pub const CONTACTS_OWNER: &str = "contacts";
/// The claim owner of the payments listener.
pub const PAYMENTS_OWNER: &str = "payments";

/// How the contacts collect uses sessions: the group it joins and how the sessions are paced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedConfig {
    /// The group the contacts collect joins; sessions with the same group on the same relay are
    /// shared.
    pub group: String,
    /// How the sessions it starts are paced.
    pub options: MuxOptions,
}

/// A session as the host sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The relay as `domain:port`.
    pub relay: String,
    /// The group the session was started for.
    pub group: String,
    /// Where the session is now.
    pub state: MuxState,
    /// What the session has done so far.
    pub counters: MuxCounters,
}

/// What a host hears about the sessions of one [`super::Epicbox`] through
/// [`PushedSessions::watch`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// The session is in `state`. It is the first event of a session, and a new one follows each
    /// change; the last one has ended.
    State {
        /// The relay as `domain:port`.
        relay: String,
        group: String,
        state: MuxState,
    },
    /// The relay pushed mail the session queued. It may be for any owner of the session.
    MailQueued { relay: String, group: String },
}

/// The sessions of one [`super::Epicbox`], by relay and group, and the contacts collect's
/// config. Clones of the method share one registry.
pub struct PushedSessions {
    registry: Mutex<Registry>,
    /// Counts each time a session is added or removed.
    changed: watch::Sender<u64>,
}

impl Default for PushedSessions {
    fn default() -> Self {
        Self {
            registry: Mutex::default(),
            changed: watch::channel(0).0,
        }
    }
}

/// A session is named by its relay (`domain:port`) and its group.
type SessionKey = (String, String);

#[derive(Default)]
struct Registry {
    contacts: Option<PushedConfig>,
    entries: BTreeMap<SessionKey, Entry>,
}

/// A running session and the owners that keep it alive.
struct Entry {
    session: Arc<MuxSession>,
    owners: BTreeSet<String>,
}

impl PushedSessions {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every session with its key.
    fn sessions(&self) -> Vec<(SessionKey, Arc<MuxSession>)> {
        self.registry()
            .entries
            .iter()
            .map(|(key, entry)| (key.clone(), Arc::clone(&entry.session)))
            .collect()
    }

    fn changed(&self) {
        self.changed
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Makes the contacts collect read pushed mail (`Some`) or go back to sockets (`None`). Does
    /// not touch the sessions already running: see [`PushedSessions::release`].
    pub fn set_contacts(&self, config: Option<PushedConfig>) {
        self.registry().contacts = config;
    }

    /// The config the contacts collect reads pushed mail with, if it does.
    pub fn contacts(&self) -> Option<PushedConfig> {
        self.registry().contacts.clone()
    }

    /// The session of `relay` and `group`, if there is one that has not been stopped.
    pub fn get(&self, relay: &str, group: &str) -> Option<Arc<MuxSession>> {
        let registry = self.registry();
        let entry = registry
            .entries
            .get(&(relay.to_owned(), group.to_owned()))?;
        (*entry.session.state().borrow() != MuxState::Stopped).then(|| Arc::clone(&entry.session))
    }

    /// The session of `relay` and `group` with `owner` added to its owners. `start` makes it when
    /// there is none, or the one there was has been stopped. A session the relay does not offer
    /// stays in the registry, so a pass does not dial the relay again; it is forgotten when its
    /// owners release it.
    pub fn get_or_start(
        &self,
        relay: &str,
        group: &str,
        owner: &str,
        start: impl FnOnce() -> Result<MuxSession, MuxError>,
    ) -> Result<Arc<MuxSession>, MuxError> {
        let mut registry = self.registry();
        let key = (relay.to_owned(), group.to_owned());
        if let Some(entry) = registry.entries.get_mut(&key)
            && *entry.session.state().borrow() != MuxState::Stopped
        {
            entry.owners.insert(owner.to_owned());
            return Ok(Arc::clone(&entry.session));
        }
        let session = Arc::new(start()?);
        registry.entries.insert(
            key,
            Entry {
                session: Arc::clone(&session),
                owners: BTreeSet::from([owner.to_owned()]),
            },
        );
        drop(registry);
        self.changed();
        Ok(session)
    }

    /// Lets go of every session `owner` uses: its claim is emptied, and a session nobody else
    /// owns is stopped. Does not wait for a session to apply the claim: one that is still
    /// opening its socket would hold the caller up.
    pub fn release(&self, owner: &str) {
        let mut claimed = Vec::new();
        {
            let mut registry = self.registry();
            registry.entries.retain(|_, entry| {
                if !entry.owners.remove(owner) {
                    return true;
                }
                if entry.owners.is_empty() {
                    return false;
                }
                claimed.push(Arc::clone(&entry.session));
                true
            });
        }
        self.changed();
        for session in claimed {
            // An ended session has nothing to release.
            let _ = session.release_claim(owner);
        }
    }

    /// Stops every session and forgets the contacts config.
    pub fn clear(&self) {
        {
            let mut registry = self.registry();
            registry.contacts = None;
            registry.entries.clear();
        }
        self.changed();
    }

    /// Every session, by relay and group.
    pub fn infos(&self) -> Vec<SessionInfo> {
        self.registry()
            .entries
            .iter()
            .map(|((relay, group), entry)| SessionInfo {
                relay: relay.clone(),
                group: group.clone(),
                state: *entry.session.state().borrow(),
                counters: entry.session.counters(),
            })
            .collect()
    }

    /// Reports what the sessions do, for as long as the returned future is polled: each session
    /// with its state when it appears and at every change, and a note when mail was queued. A
    /// session that was removed reports `Stopped` and is not followed any more. Counters are not
    /// part of the events; read them with [`PushedSessions::infos`].
    pub async fn watch(&self, report: impl Fn(SessionEvent) + Send + Sync + 'static) {
        let report = Arc::new(report);
        let mut changes = self.changed.subscribe();
        let mut tasks = JoinSet::new();
        let mut watched = Watched::new();
        loop {
            changes.borrow_and_update();
            let current = self.sessions();
            stop_watching_removed(&mut watched, &current, &*report);
            watch_new(&mut watched, &mut tasks, current, &report);
            // The tasks that ended are not awaited; a finished task of a replaced session is
            // dropped when the join set is.
            while tasks.try_join_next().is_some() {}
            if changes.changed().await.is_err() {
                return;
            }
        }
    }
}

/// The sessions being followed, with the task that follows each. The weak handle tells a
/// session apart from a later one started under the same key.
type Watched = BTreeMap<SessionKey, (Weak<MuxSession>, AbortHandle)>;

/// Aborts the task of each watched session that is no longer in `current` (removed, or replaced
/// by another under the same key), and reports it as stopped unless it ended on its own.
fn stop_watching_removed(
    watched: &mut Watched,
    current: &[(SessionKey, Arc<MuxSession>)],
    report: &impl Fn(SessionEvent),
) {
    watched.retain(|key, (session, handle)| {
        let kept = current
            .iter()
            .any(|(known, now)| known == key && Weak::ptr_eq(session, &Arc::downgrade(now)));
        if !kept {
            // One that already ended said so itself.
            if !handle.is_finished() {
                report(SessionEvent::State {
                    relay: key.0.clone(),
                    group: key.1.clone(),
                    state: MuxState::Stopped,
                });
            }
            handle.abort();
        }
        kept
    });
}

/// Starts a task for each session of `current` that is not watched yet.
fn watch_new(
    watched: &mut Watched,
    tasks: &mut JoinSet<()>,
    current: Vec<(SessionKey, Arc<MuxSession>)>,
    report: &Arc<impl Fn(SessionEvent) + Send + Sync + 'static>,
) {
    for (key, session) in current {
        if watched.contains_key(&key) {
            continue;
        }
        let (relay, group) = key.clone();
        let handle = tasks.spawn(watch_one(
            relay,
            group,
            session.state(),
            session.queued(),
            Arc::clone(report),
        ));
        watched.insert(key, (Arc::downgrade(&session), handle));
    }
}

/// Reports the state changes and queued mail of one session until it ends.
async fn watch_one(
    relay: String,
    group: String,
    mut state: watch::Receiver<MuxState>,
    mut queued: watch::Receiver<u64>,
    report: Arc<impl Fn(SessionEvent) + Send + Sync + 'static>,
) {
    let say = |state| {
        report(SessionEvent::State {
            relay: relay.clone(),
            group: group.clone(),
            state,
        });
    };
    say(*state.borrow_and_update());
    queued.borrow_and_update();
    loop {
        tokio::select! {
            changed = state.changed() => {
                if changed.is_err() {
                    say(MuxState::Stopped);
                    return;
                }
                let now = *state.borrow_and_update();
                say(now);
                if now.has_ended() {
                    return;
                }
            }
            changed = queued.changed() => {
                if changed.is_err() {
                    say(MuxState::Stopped);
                    return;
                }
                queued.borrow_and_update();
                report(SessionEvent::MailQueued {
                    relay: relay.clone(),
                    group: group.clone(),
                });
            }
        }
    }
}

impl std::fmt::Debug for PushedSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedSessions")
            .field("sessions", &self.registry().entries.len())
            .finish_non_exhaustive()
    }
}
