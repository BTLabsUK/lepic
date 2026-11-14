// SPDX-License-Identifier: Apache-2.0
//! Push sessions (mux/1) as the host sees them: the listener's choice to read through one, the
//! contacts collect's setting and the view of the sessions.

use std::time::Duration;

use lepic_epicbox::{MuxOptions, MuxState};
use lepic_methods::epicbox::{CONTACTS_OWNER, PushedConfig, SessionEvent};

use super::{Mutex, Session, invalid};
use crate::api::error::WalletError;
use crate::api::types::{
    EpicboxSessionEvent, EpicboxSessionEventKind, EpicboxSessionState, EpicboxSessionView,
    ListenVia,
};

/// The longest group name taken from the app.
const MAX_GROUP: usize = 64;
/// The longest interval of the waiting check, in seconds: a day.
const MAX_WAITING_EVERY_S: u32 = 86_400;

/// What the app chose for push sessions that the session keeps.
pub(crate) struct Choices {
    /// How the listener reads the relay, when the app chose a push session.
    pub(crate) listen_via: Mutex<Option<Via>>,
    /// Counts each relay switch, so a watch of the sessions moves to the new relay.
    pub(crate) epoch: tokio::sync::watch::Sender<u64>,
}

impl Default for Choices {
    fn default() -> Self {
        Self {
            listen_via: Mutex::default(),
            epoch: tokio::sync::watch::channel(0).0,
        }
    }
}

/// A checked [`ListenVia`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Via {
    pub(crate) group: String,
    pub(crate) options: MuxOptions,
}

impl Via {
    pub(crate) fn new(via: ListenVia) -> Result<Self, WalletError> {
        if via.group.is_empty()
            || via.group.len() > MAX_GROUP
            || via.group.chars().any(char::is_control)
        {
            return Err(invalid("the session group must be 1 to 64 characters"));
        }
        if via
            .waiting_every_s
            .is_some_and(|seconds| seconds == 0 || seconds > MAX_WAITING_EVERY_S)
        {
            return Err(invalid("waiting_every_s must be between 1 and 86400"));
        }
        Ok(Self {
            group: via.group,
            options: MuxOptions {
                waiting_every: via
                    .waiting_every_s
                    .map(|seconds| Duration::from_secs(u64::from(seconds))),
                ..MuxOptions::default()
            },
        })
    }
}

fn state(state: MuxState) -> EpicboxSessionState {
    match state {
        MuxState::Connecting { .. } => EpicboxSessionState::Connecting,
        MuxState::Attached => EpicboxSessionState::Attached,
        MuxState::NotOffered => EpicboxSessionState::NotOffered,
        MuxState::Stopped => EpicboxSessionState::Stopped,
        // Waiting, and any state added later: a session that is not attached and retries.
        _ => EpicboxSessionState::Reconnecting,
    }
}

fn event(event: SessionEvent) -> Option<EpicboxSessionEvent> {
    match event {
        SessionEvent::State {
            relay,
            group,
            state: now,
        } => Some(EpicboxSessionEvent {
            kind: EpicboxSessionEventKind::State,
            relay,
            group,
            state: Some(state(now)),
        }),
        SessionEvent::MailQueued { relay, group } => Some(EpicboxSessionEvent {
            kind: EpicboxSessionEventKind::MailQueued,
            relay,
            group,
            state: None,
        }),
        _ => None,
    }
}

impl Session {
    pub(crate) fn contacts_push_start(&self, via: ListenVia) -> Result<(), WalletError> {
        let via = Via::new(via)?;
        self.epicbox()?.pushed().set_contacts(Some(PushedConfig {
            group: via.group,
            options: via.options,
        }));
        Ok(())
    }

    pub(crate) async fn contacts_push_stop(&self) -> Result<(), WalletError> {
        let epicbox = self.epicbox()?;
        epicbox.pushed().set_contacts(None);
        epicbox.pushed().release(CONTACTS_OWNER);
        Ok(())
    }

    /// The sessions of the relay in use; none when the wallet has no relay.
    pub(crate) fn epicbox_sessions(&self) -> Vec<EpicboxSessionView> {
        let Ok(epicbox) = self.epicbox() else {
            return Vec::new();
        };
        epicbox
            .pushed()
            .infos()
            .into_iter()
            .map(|info| EpicboxSessionView {
                relay: info.relay,
                group: info.group,
                state: state(info.state),
                sockets_opened: info.counters.sockets_opened,
                attaches: info.counters.attaches,
                resumes: info.counters.resumes,
                mails: info.counters.mails,
                duplicates: info.counters.duplicates,
                stall_reconnects: info.counters.stall_reconnects,
            })
            .collect()
    }

    /// Reports the sessions of the relay in use and follows a relay switch.
    pub(crate) async fn watch_epicbox_sessions(
        &self,
        report: impl Fn(EpicboxSessionEvent) + Clone + Send + Sync + 'static,
    ) -> Result<(), WalletError> {
        let mut switched = self.pushed.epoch.subscribe();
        loop {
            let epicbox = self.epicbox()?;
            switched.borrow_and_update();
            let report = report.clone();
            tokio::select! {
                () = epicbox.pushed().watch(move |found| {
                    if let Some(found) = event(found) {
                        report(found);
                    }
                }) => return Ok(()),
                changed = switched.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}
