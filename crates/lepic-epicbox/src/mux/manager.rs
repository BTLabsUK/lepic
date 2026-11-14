// SPDX-License-Identifier: Apache-2.0
//! The task that owns the socket: it reconnects, resumes or attaches, and serves the socket
//! until it is lost or the session is stopped.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep_until, timeout};
use tracing::{debug, info, warn};

use crate::client::{Awaiting, CancelToken, ClientError, ClientSettings, Identity};
use crate::frame::{RelayMessageId, signed};
use crate::mailbox::Handled;
use crate::mux_frame::{
    AttachEntry, MAX_ATTACH_PER_FRAME, MAX_MAILBOXES_PER_SOCKET, MuxClientFrame, ResumeToken,
};
use crate::session::{Connection, Connector, deadline_after};

use super::claims::Entry;
use super::counters::bump;
use super::link::{Link, Lost, PendingKind, StoredIds, sleep_until_opt, tick_opt};
use super::negotiate::Refusal;
use super::{Command, Delivery, End, MuxEvent, MuxOptions, MuxState, Shared};

/// Greetings left unanswered, one after another, before a relay that never offered mux/1 is taken
/// as not offering it.
const MAX_GREETING_TIMEOUTS: u32 = 3;

/// How long leaving a socket may take.
const LEAVE_GRACE: Duration = Duration::from_millis(500);

enum Wake {
    Cancel,
    Command(Option<Command>),
    Text(Result<String, ClientError>),
    AckDue,
    Expired,
    Ping,
    Probe,
    Route,
}

pub(super) struct Manager {
    pub(super) settings: ClientSettings,
    pub(super) connector: Arc<dyn Connector>,
    pub(super) options: MuxOptions,
    /// An inline handler is in a `Mutex` only so that `&Manager` is `Send`: it is not `Sync`, and
    /// is always reached through `&mut`.
    pub(super) delivery: Delivery,
    /// The session's mailboxes by index. Indexes are never reused.
    pub(super) entries: BTreeMap<usize, Entry>,
    pub(super) keys: HashMap<String, usize>,
    /// What each owner wants attached. The session's mailboxes are the union of the claims.
    pub(super) claims: BTreeMap<String, Vec<Identity>>,
    /// Keys of mailboxes another socket took over. They stay in the session, so that indexes do
    /// not move, but are never attached from here (see [`MuxEvent::Replaced`]).
    pub(super) replaced: HashSet<String>,
    /// How many mailboxes the session may hold: the smaller of the relay's limit and
    /// [`MAX_MAILBOXES_PER_SOCKET`], as far as the relay has said.
    pub(super) mailbox_cap: usize,
    /// A relay has offered mux/1 to this session at least once.
    pub(super) offered: bool,
    /// Greetings in a row that got no answer.
    pub(super) greeting_timeouts: u32,
    pub(super) next_index: usize,
    /// The token of the last `Attached`. In memory only.
    pub(super) token: Option<ResumeToken>,
    pub(super) stored: StoredIds,
    pub(super) commands: mpsc::UnboundedReceiver<Command>,
    pub(super) cancel: CancelToken,
    pub(super) shared: Arc<Shared>,
}

impl Manager {
    fn set_state(&self, state: MuxState) {
        self.shared.state.send_replace(state);
    }

    pub(super) fn emit(&self, event: MuxEvent) {
        // No receiver is not a problem.
        let _ = self.shared.events.send(event);
    }

    pub(super) async fn run(mut self) -> End {
        let ping_every = self.settings.ping_interval;
        let mut attempt: u32 = 1;
        loop {
            self.set_state(MuxState::Connecting { attempt });
            let started = Instant::now();
            let lost = match self.session().await {
                Ok(end) => {
                    self.set_state(match end {
                        End::Stopped => MuxState::Stopped,
                        End::NotOffered => MuxState::NotOffered,
                    });
                    return end;
                }
                Err(lost) => lost,
            };
            if started.elapsed() >= ping_every {
                attempt = 0;
            }
            attempt = attempt.saturating_add(1);
            let delay = self.retry_delay(&lost, attempt);
            let retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            warn!(attempt, retry_in_ms, reason = %lost, "epicbox mux session lost, retrying");
            self.set_state(MuxState::Waiting { attempt, delay });
            if self.wait(delay).await {
                self.set_state(MuxState::Stopped);
                return End::Stopped;
            }
        }
    }

    fn retry_delay(&self, lost: &Lost, attempt: u32) -> Duration {
        let backoff = self
            .settings
            .backoff
            .delay(attempt.max(1), getrandom::u32().unwrap_or(u32::MAX));
        match lost {
            Lost::Rerouted => Duration::ZERO,
            Lost::RateLimited { retry_after } => backoff.max(*retry_after),
            _ => backoff,
        }
    }

    /// Sleeps for `delay` while still taking commands. `true` when the session was stopped.
    pub(super) async fn wait(&mut self, delay: Duration) -> bool {
        let until = deadline_after(delay);
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return true,
                command = self.commands.recv() => match command {
                    Some(command) => self.apply_offline(command),
                    None => return true,
                },
                () = sleep_until(until) => return false,
            }
        }
    }

    /// An answer that was settled while no socket owned the message. A stored message is
    /// remembered, so that the relay's redelivery is acknowledged without being handled again.
    fn settle_offline(&mut self, id: &RelayMessageId, handled: Handled) {
        if handled == Handled::Stored {
            self.stored.insert(id.clone());
        }
    }

    fn apply_offline(&mut self, command: Command) {
        match command {
            Command::Set {
                owner,
                merge,
                identities,
                reply,
            } => {
                let _ = reply.send(
                    self.reconcile(owner, merge, identities)
                        .map(|done| done.claimed()),
                );
            }
            Command::Settle { id, handled } => self.settle_offline(&id, handled),
            Command::Add { identity, reply } => {
                let _ = reply.send(self.add_claimed(identity));
            }
            Command::Remove { key, reply } => {
                let _ = reply.send(self.remove_claimed(&key).is_some());
            }
        }
    }

    pub(super) async fn session(&mut self) -> Result<End, Lost> {
        let endpoint = self.settings.endpoint.clone();
        let connect_timeout = self.settings.connect_timeout;
        let mut connection = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Ok(End::Stopped),
            opened = Connection::open(self.connector.as_ref(), &endpoint, connect_timeout) => opened?,
        };
        bump(&self.shared.counters.sockets_opened);
        let negotiated = tokio::select! {
            biased;
            () = self.cancel.cancelled() => {
                connection.close().await;
                return Ok(End::Stopped);
            }
            negotiated = self.negotiate(&mut connection) => negotiated,
        };
        let negotiated = match negotiated {
            Ok(negotiated) => negotiated,
            Err(Refusal::NotOffered) => {
                info!("epicbox relay does not offer mux/1");
                connection.close().await;
                return Ok(End::NotOffered);
            }
            Err(Refusal::Rejected(error)) if !self.offered => {
                // A relay that has never offered mux/1 and answers the greeting with an error
                // will not carry the session; the caller has the 3.0.0 listener for it.
                info!(error = %ErrorChain(&error), "epicbox relay answered the mux/1 greeting with an error");
                connection.close().await;
                return Ok(End::NotOffered);
            }
            Err(Refusal::Silent(error)) if !self.offered => {
                self.greeting_timeouts = self.greeting_timeouts.saturating_add(1);
                connection.close().await;
                if self.greeting_timeouts >= MAX_GREETING_TIMEOUTS {
                    info!("epicbox relay does not answer the mux/1 greeting");
                    return Ok(End::NotOffered);
                }
                return Err(Lost::Client(error));
            }
            Err(Refusal::Rejected(error) | Refusal::Silent(error) | Refusal::Failed(error)) => {
                connection.close().await;
                return Err(Lost::Client(error));
            }
        };
        self.offered = true;
        self.greeting_timeouts = 0;
        self.mailbox_cap = negotiated
            .limits
            .mailboxes_per_socket
            .clamp(1, MAX_MAILBOXES_PER_SOCKET);
        debug!(
            attach_per_frame = negotiated.limits.attach_per_frame,
            mailboxes_per_socket = negotiated.limits.mailboxes_per_socket,
            inflight_per_socket = negotiated.limits.inflight_per_socket,
            "epicbox mux negotiated"
        );
        let mut link = Link::new(connection, negotiated, self.settings.response_timeout);
        let result = self.run_link(&mut link).await;
        link.connection.close().await;
        // The relay offers unsettled mail again on the next socket.
        self.shared.purge(None);
        result.map(|()| End::Stopped)
    }

    async fn run_link(&mut self, link: &mut Link) -> Result<(), Lost> {
        self.begin(link).await?;
        self.serve(link).await
    }

    /// Resumes with the token, or attaches every mailbox with signatures.
    async fn begin(&mut self, link: &mut Link) -> Result<(), Lost> {
        if self.entries.len() == self.replaced.len() {
            self.token = None;
            self.mark_ready(link);
            return Ok(());
        }
        // A token is single use: the relay has spent it once the frame is sent, so it is not
        // kept. A reply that never arrives is answered by a signed attach on the next socket.
        if let Some(token) = self.token.take() {
            bump(&self.shared.counters.resumes);
            link.resume_pending = true;
            link.send(
                |reference| MuxClientFrame::Resume { reference, token },
                PendingKind::Resume,
            )
            .await
        } else {
            let all = self.unattached(link);
            self.attach(link, all).await
        }
    }

    pub(super) fn mark_ready(&self, link: &mut Link) {
        if !link.ready {
            link.ready = true;
            self.set_state(MuxState::Attached);
        }
    }

    /// Attaches the mailboxes `indexes` with signatures over the socket challenge, in frames of
    /// at most the relay's limit.
    pub(super) async fn attach(&self, link: &mut Link, indexes: Vec<usize>) -> Result<(), Lost> {
        let per_frame = link.limits.attach_per_frame.clamp(1, MAX_ATTACH_PER_FRAME);
        for chunk in indexes.chunks(per_frame) {
            let mut mailboxes = Vec::with_capacity(chunk.len());
            let mut sent = Vec::with_capacity(chunk.len());
            for index in chunk {
                let Some(entry) = self.entries.get(index) else {
                    continue;
                };
                let signature = signed(link.challenge.as_str(), entry.identity.secret())
                    .map_err(|error| Lost::Client(ClientError::Frame(error)))?;
                bump(&self.shared.counters.signatures);
                mailboxes.push(AttachEntry {
                    address: entry.key.clone(),
                    signature,
                });
                sent.push(*index);
            }
            if mailboxes.is_empty() {
                continue;
            }
            bump(&self.shared.counters.attaches);
            link.send(
                |reference| MuxClientFrame::Attach {
                    reference,
                    mailboxes,
                },
                PendingKind::Attach { indexes: sent },
            )
            .await?;
        }
        if link.pending.is_empty() {
            self.mark_ready(link);
        }
        Ok(())
    }

    pub(super) async fn serve(&mut self, link: &mut Link) -> Result<(), Lost> {
        let ping_every = self.settings.ping_interval;
        let silence_limit = ping_every.saturating_mul(2);
        let response_timeout = self.settings.response_timeout;
        let route = link.connection.route;
        let mut pings = interval_at(deadline_after(ping_every), ping_every);
        pings.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut probes = self.options.waiting_every.map(|every| {
            let mut probes = interval_at(deadline_after(every), every);
            probes.set_missed_tick_behavior(MissedTickBehavior::Delay);
            probes
        });
        loop {
            let ack_due = link.ack_due;
            let expiry = link.next_expiry();
            let wake = tokio::select! {
                biased;
                () = self.cancel.cancelled() => Wake::Cancel,
                command = self.commands.recv() => Wake::Command(command),
                text = link.connection.receive_text() => Wake::Text(text),
                () = sleep_until_opt(ack_due) => Wake::AckDue,
                () = sleep_until_opt(expiry) => Wake::Expired,
                _ = pings.tick() => Wake::Ping,
                () = tick_opt(&mut probes) => Wake::Probe,
                () = self.connector.route_changed(&self.settings.endpoint, route) => Wake::Route,
            };
            match wake {
                Wake::Cancel | Wake::Command(None) => {
                    self.leave(link).await;
                    return Ok(());
                }
                Wake::Command(Some(command)) => self.apply_online(link, command).await?,
                Wake::Text(text) => {
                    self.handle_text(link, &text?).await?;
                    if std::mem::take(&mut link.fallback_attach) {
                        let all = self.unattached(link);
                        self.attach(link, all).await?;
                    }
                }
                Wake::AckDue => self.flush_acks(link).await?,
                Wake::Expired => {
                    let now = Instant::now();
                    if link.pending.values().any(|pending| pending.deadline <= now) {
                        return Err(Lost::Client(ClientError::Timeout {
                            awaiting: Awaiting::Answer,
                        }));
                    }
                }
                Wake::Ping => {
                    if link.connection.idle_for() > silence_limit {
                        return Err(Lost::Client(ClientError::Timeout {
                            awaiting: Awaiting::Traffic,
                        }));
                    }
                    timeout(response_timeout, link.connection.ping())
                        .await
                        .map_err(|_| {
                            Lost::Client(ClientError::Timeout {
                                awaiting: Awaiting::Traffic,
                            })
                        })??;
                }
                Wake::Probe => self.probe(link).await?,
                Wake::Route => {
                    info!("epicbox relay route changed, reconnecting");
                    self.leave(link).await;
                    return Err(Lost::Rerouted);
                }
            }
        }
    }

    /// Sends the acknowledgements still queued, without waiting for their answers.
    async fn leave(&self, link: &mut Link) {
        let _ = timeout(LEAVE_GRACE, self.flush_acks(link)).await;
    }

    pub(super) async fn probe(&self, link: &mut Link) -> Result<(), Lost> {
        if !link.ready || link.probe_outstanding || link.attached.is_empty() {
            return Ok(());
        }
        bump(&self.shared.counters.waiting_probes);
        link.probe_outstanding = true;
        link.send(
            |reference| MuxClientFrame::Waiting { reference },
            PendingKind::Waiting,
        )
        .await
    }

    async fn apply_online(&mut self, link: &mut Link, command: Command) -> Result<(), Lost> {
        match command {
            Command::Set {
                owner,
                merge,
                identities,
                reply,
            } => match self.reconcile(owner, merge, identities) {
                Ok(done) => {
                    let _ = reply.send(Ok(done.claimed()));
                    for (index, key) in done.removed {
                        link.drop_mailbox(index, key).await?;
                    }
                    // A resume in flight attaches what it missed once it is answered.
                    if !link.resume_pending && !done.added.is_empty() {
                        self.attach(link, done.added).await?;
                    }
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Command::Settle { id, handled } => {
                if handled == Handled::Stored {
                    self.stored.insert(id.clone());
                }
                if link.inflight.contains_key(&id) {
                    match handled {
                        Handled::Stored => self.queue_ack(link, id).await?,
                        Handled::Later => self.hold(link, id).await?,
                    }
                }
            }
            Command::Add { identity, reply } => match self.add_claimed(identity) {
                Ok(index) => {
                    let _ = reply.send(Ok(index));
                    // A resume in flight attaches what it missed once it is answered.
                    if !link.resume_pending {
                        self.attach(link, vec![index]).await?;
                    }
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Command::Remove { key, reply } => {
                let removed = self.remove_claimed(&key);
                let _ = reply.send(removed.is_some());
                if let Some(index) = removed {
                    link.drop_mailbox(index, key).await?;
                }
            }
        }
        Ok(())
    }
}
