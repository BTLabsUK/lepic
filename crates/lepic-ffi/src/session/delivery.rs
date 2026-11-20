// SPDX-License-Identifier: Apache-2.0
//! The delivery loop: the contacts' delivery layer run in the background as `lepic serve` runs
//! it, from [`Session::set_delivery`] until the wallet locks or the session drops. Each tick is
//! one collecting cycle: it claims the contact mailboxes on push sessions, handles the mail they
//! queued, ends what expired and posts the outbox rows that are due. A session that pushes mail
//! or attaches again starts a tick, so mail is read as it arrives.

use std::sync::{Arc, Weak};
use std::time::Duration;

use lepic_epicbox::sessions::{Owner, PushedConfig, SessionEvent};
use lepic_epicbox::{MuxOptions, MuxState};
use lepic_methods::epicbox::Epicbox;
use lepic_wallet::boost::Poller;
use lepic_wallet_contacts::{CollectReport, CollectTrigger, WalletContacts as _};
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tracing::instrument::WithSubscriber as _;
use tracing::warn;

use super::{Mutex, Session, lock};
use crate::api::error::WalletError;
use crate::api::types::ContactRelayMode;

/// The least time between the end of one tick and a tick a push starts. Pushes come in bursts,
/// and a payment's mail on a shared session wakes the contacts too, so pushes may not run the
/// tick back to back. Short, since a pairing takes several round trips that each wait for one.
const PUSH_FLOOR: Duration = Duration::from_secs(1);

/// The session group of the contact mailboxes while tor runs, and the core's group while the
/// loop has set none.
#[cfg(feature = "tor")]
const CONTACTS_GROUP: &str = "contacts";

/// The session group of the contact mailboxes without tor and without a listener reading
/// through a session: their sockets come from the wallet's address either way.
const SHARED_GROUP: &str = "main";

/// The loop's state in a session.
#[derive(Default)]
pub(crate) struct DeliveryLoop {
    /// The task of the running loop. Taken before `mode` where both are held.
    task: Mutex<Option<AbortHandle>>,
    /// The mode the app set; `None` until it sets one, and again after a lock.
    mode: Mutex<Option<ContactRelayMode>>,
    /// Held for a tick, so two never run at once.
    tick: tokio::sync::Mutex<()>,
    /// The group the loop's contacts sessions use, which the watch of the sessions follows.
    group: Arc<Mutex<String>>,
}

impl DeliveryLoop {
    /// Ends the loop and forgets the mode.
    pub(super) fn stop(&self) {
        if let Some(task) = lock(&self.task).take() {
            task.abort();
        }
        lock(&self.mode).take();
    }
}

impl Session {
    /// Sets the relay mode of the delivery loop: `Online` starts the loop or keeps it running,
    /// `Offline` ends it and lets go of the contacts' push sessions. Fails with `Locked` after a
    /// lock and with `Unsupported` for `Online` when no relay is configured.
    pub(crate) fn set_delivery(
        self: &Arc<Self>,
        mode: ContactRelayMode,
    ) -> Result<(), WalletError> {
        // Held across the check, so a lock that comes after it finds the task in its slot.
        let mut task = lock(&self.delivery.task);
        self.ensure_unlocked()?;
        if mode == ContactRelayMode::Online {
            self.epicbox()?;
        }
        *lock(&self.delivery.mode) = Some(mode);
        if mode == ContactRelayMode::Online {
            if task.as_ref().is_none_or(AbortHandle::is_finished) {
                *task = Some(self.spawn_delivery());
            }
        } else {
            // The task lets go of the sessions again when its future drops, after a claim of
            // the poll under way.
            if let Some(task) = task.take() {
                task.abort();
            }
            self.release_contacts();
        }
        Ok(())
    }

    /// Ends the delivery loop, forgets its mode and lets go of the contacts' push sessions.
    pub(super) fn stop_delivery(&self) {
        self.delivery.stop();
        self.release_contacts();
    }

    /// The task of the running loop, for a test to see it end.
    #[cfg(test)]
    pub(crate) fn delivery_task(&self) -> Option<AbortHandle> {
        lock(&self.delivery.task).clone()
    }

    /// Lets go of the contacts' push sessions and forgets their config.
    fn release_contacts(&self) {
        if let Some(slot) = &self.epicbox {
            let epicbox = slot.current();
            epicbox.pushed().set_contacts(None);
            epicbox.pushed().release(Owner::Contacts);
        }
    }

    fn spawn_delivery(self: &Arc<Self>) -> AbortHandle {
        let boundary = &self.runtime().boundary;
        boundary
            .handle
            .spawn(run(Arc::downgrade(self)).with_subscriber(boundary.dispatch.clone()))
            .abort_handle()
    }

    /// One tick of the delivery layer in the mode the app set, `Online` when it set none, after
    /// any tick under way. `Online` first points the contacts sessions at their group. Fails
    /// with `ContactsOffline` before connecting, as the mode says, and with
    /// `Unsupported` when no relay is configured.
    pub(crate) async fn delivery_tick(
        &self,
        trigger: CollectTrigger,
    ) -> Result<CollectReport, WalletError> {
        let _tick = self.delivery.tick.lock().await;
        let mode = lock(&self.delivery.mode).unwrap_or(ContactRelayMode::Online);
        let relays = self.contact_relays(mode)?;
        if mode == ContactRelayMode::Online {
            self.point_contacts_sessions(&self.epicbox()?);
        }
        Ok(self
            .engine
            .contact_book()
            .contacts_collect(&relays, trigger)
            .await?)
    }

    /// The loop's tick: runs one tick, after any server switch. Tells whether it completed a
    /// pairing; a failure is logged.
    async fn loop_tick(&self, trigger: CollectTrigger) -> bool {
        let _servers = self.servers.read().await;
        match self.delivery_tick(trigger).await {
            Ok(report) => report.paired > 0,
            Err(error) => {
                warn!(
                    error = %lepic_telemetry::ErrorChain(&error),
                    "delivery tick failed"
                );
                false
            }
        }
    }

    /// Sets the contacts sessions' config to the one [`Self::contacts_config`] gives, letting go
    /// of the sessions of another config.
    fn point_contacts_sessions(&self, epicbox: &Epicbox) {
        let config = self.contacts_config();
        let pushed = epicbox.pushed();
        if pushed.contacts().as_ref() != Some(&config) {
            pushed.release(Owner::Contacts);
            pushed.set_contacts(Some(config.clone()));
        }
        *lock(&self.delivery.group) = config.group;
    }

    /// The contacts sessions' config: their own group while tor runs; without tor, the group
    /// of the listener when it reads through a session, else the shared group.
    fn contacts_config(&self) -> PushedConfig {
        #[cfg(feature = "tor")]
        if self.tor_running() {
            return PushedConfig {
                group: CONTACTS_GROUP.to_owned(),
                options: MuxOptions::default(),
            };
        }
        // Read before `listen_via`, in the order a listener claim takes them.
        let listening = self.listener_running();
        let via = if listening {
            lock(&self.pushed.listen_via).clone()
        } else {
            None
        };
        via.map_or_else(
            || PushedConfig {
                group: SHARED_GROUP.to_owned(),
                options: MuxOptions::default(),
            },
            |via| PushedConfig {
                group: via.group,
                options: via.options,
            },
        )
    }

    /// When the next tick runs: `base`, or less while a boost of the relays lasts, after `last`.
    fn tick_after(&self, last: Instant, base: Duration) -> Instant {
        last.checked_add(self.boosts().interval(Poller::Relays, base))
            .unwrap_or(last)
    }
}

/// When a tick a push asks for may run: now, or [`PUSH_FLOOR`] after the last one ended.
fn push_due(collected: Instant) -> Instant {
    let floor = collected.checked_add(PUSH_FLOOR).unwrap_or(collected);
    floor.max(Instant::now())
}

/// Runs the loop until the session is gone or the task is aborted. The first tick runs at once
/// with `Open`, the others with `Foreground` at the tuned interval. A push runs a tick with
/// `Push` [`PUSH_FLOOR`] after the last one ended, and so do a tick that completed a pairing,
/// which claims the new contact's mailboxes, and a relay switch, which moves the watch of the
/// sessions to the new relay and claims the mailboxes there. Holds the session only for a tick.
/// When the future drops and the app wants no loop, it lets go of the contacts' push sessions.
async fn run(session: Weak<Session>) {
    let _release = ReleaseOnDrop(Weak::clone(&session));
    let Some((mut switched, mut boosted, base, group)) = session.upgrade().map(|session| {
        (
            session.pushed.epoch.subscribe(),
            session.boosts().changed(),
            session.tuning.collect_every(),
            Arc::clone(&session.delivery.group),
        )
    }) else {
        return;
    };
    let wake = Arc::new(Notify::new());
    let mut collected = Instant::now();
    let mut next = collected;
    let mut trigger = CollectTrigger::Open;
    loop {
        let Some(epicbox) = session.upgrade().and_then(|session| session.epicbox().ok()) else {
            return;
        };
        switched.borrow_and_update();
        let follow = follow_pushes(epicbox, Arc::clone(&group), Arc::clone(&wake));
        tokio::pin!(follow);
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(next) => {
                    let Some(held) = session.upgrade() else {
                        return;
                    };
                    let paired = held.loop_tick(trigger).await;
                    trigger = CollectTrigger::Foreground;
                    collected = Instant::now();
                    next = held.tick_after(collected, base);
                    if paired {
                        // A pairing that completed has mailboxes the sessions do not hold yet:
                        // the next tick claims them.
                        trigger = CollectTrigger::Push;
                        next = next.min(push_due(collected));
                    }
                }
                () = wake.notified() => {
                    // The first tick, still to come, reads everything anyway.
                    if trigger != CollectTrigger::Open {
                        trigger = CollectTrigger::Push;
                    }
                    next = next.min(push_due(collected));
                }
                Ok(()) = boosted.changed() => {
                    let Some(held) = session.upgrade() else {
                        return;
                    };
                    next = next.min(held.tick_after(collected, base));
                }
                changed = switched.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    // The sessions on the new relay hold no mailbox yet: the next tick claims
                    // them.
                    if trigger != CollectTrigger::Open {
                        trigger = CollectTrigger::Push;
                    }
                    next = next.min(push_due(collected));
                    break;
                }
                () = &mut follow => {}
            }
        }
    }
}

/// Lets go of the contacts' push sessions when the loop's future drops, unless the app set
/// `Online` again. An aborted task drops its future only after the poll under way returns, so
/// this runs after any claim that poll made.
struct ReleaseOnDrop(Weak<Session>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        let Some(session) = self.0.upgrade() else {
            return;
        };
        let wanted = *lock(&session.delivery.mode) == Some(ContactRelayMode::Online);
        if !wanted {
            session.release_contacts();
        }
    }
}

/// Wakes `wake` each time a contacts session of the group in `group` attaches, at start and
/// after each reconnect, and each time its relay pushes mail. The tick that follows reads the
/// mail, and after a reconnect it catches up on what came while the socket was down. Never
/// ends.
async fn follow_pushes(epicbox: Epicbox, group: Arc<Mutex<String>>, wake: Arc<Notify>) {
    epicbox
        .pushed()
        .watch(move |event| match event {
            SessionEvent::MailQueued { group: of, .. }
            | SessionEvent::State {
                group: of,
                state: MuxState::Attached,
                ..
            } if *lock(&group) == of => wake.notify_one(),
            _ => {}
        })
        .await;
    // The watch ends only with the relay's sessions, which `epicbox` holds.
    std::future::pending::<()>().await;
}
