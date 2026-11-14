//! The mux/1 sessions of one [`super::Epicbox`], shared by the consumers that read the same
//! relay: the contacts collect and the payments listener.
//!
//! A session is named by the relay it talks to and a group the host picks. Two consumers that
//! name the same group on the same relay get the same socket. Each consumer is an owner: it
//! keeps its own claim on the session's mailboxes (see [`lepic_epicbox::MuxSession::set_claim`]),
//! and a session lives until its last owner lets go.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lepic_epicbox::{MuxCounters, MuxError, MuxOptions, MuxSession, MuxState};

/// The claim owner of the contacts collect.
pub const CONTACTS_OWNER: &str = "contacts";
/// The claim owner of the payments listener.
pub const PAYMENTS_OWNER: &str = "payments";

/// How the contacts collect uses sessions: the group it joins and how the sessions are paced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedConfig {
    pub group: String,
    pub options: MuxOptions,
}

/// A session as the host sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The relay as `domain:port`.
    pub relay: String,
    pub group: String,
    pub state: MuxState,
    pub counters: MuxCounters,
}

#[derive(Default)]
pub struct PushedSessions {
    registry: Mutex<Registry>,
}

#[derive(Default)]
struct Registry {
    contacts: Option<PushedConfig>,
    entries: BTreeMap<(String, String), Entry>,
}

struct Entry {
    session: Arc<MuxSession>,
    owners: BTreeSet<String>,
}

impl PushedSessions {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes the contacts collect read pushed mail (`Some`) or go back to sockets (`None`). Does
    /// not touch the sessions already running: see [`PushedSessions::release`].
    pub fn set_contacts(&self, config: Option<PushedConfig>) {
        self.registry().contacts = config;
    }

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
        Ok(session)
    }

    /// Lets go of every session `owner` uses: its claim is emptied, and a session nobody else
    /// owns is stopped.
    pub async fn release(&self, owner: &str) {
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
        for session in claimed {
            // An ended session has nothing to release.
            let _ = session.set_claim(owner, Vec::new()).await;
        }
    }

    /// Stops every session and forgets the contacts config.
    pub fn clear(&self) {
        let mut registry = self.registry();
        registry.contacts = None;
        registry.entries.clear();
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
}

impl std::fmt::Debug for PushedSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushedSessions")
            .field("sessions", &self.registry().entries.len())
            .finish_non_exhaustive()
    }
}
