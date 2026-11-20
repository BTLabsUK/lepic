// SPDX-License-Identifier: Apache-2.0
//! The task that owns the socket: it reconnects, resumes or attaches, and serves the socket
//! until it is lost or the session is stopped.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep_until, timeout};
use tracing::{debug, info, warn};

use crate::client::{Awaiting, CancelToken, ClientError, ClientSettings, Identity};
use crate::frame::{CancelSignature, EpicboxTxId, RelayMessageId, signed};
use crate::mailbox::Handled;
use crate::mux_frame::{
    AttachEntry, MAX_ATTACH_PER_FRAME, MAX_MAILBOXES_PER_SOCKET, MuxClientFrame, RelayTxId,
    ResumeToken, attach_text,
};
use crate::session::{Connection, Connector, deadline_after};

use super::budget::WaitingBudget;
use super::claims::Entry;
use super::counters::bump;
use super::link::{Link, Lost, PendingKind, PostReply, StoredIds, sleep_until_opt, tick_opt};
use super::negotiate::Refusal;
use super::{
    Command, Delivery, End, HealthNote, MuxCancelOutcome, MuxError, MuxEvent, MuxOptions,
    MuxPostError, MuxPostNotSent, MuxState, MuxWaiting, Post, Shared,
};

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
    Reclaim,
    RetryAttach,
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
    /// Keys of mailboxes another socket took over, with when to attach each again. They stay in
    /// the session, so that indexes do not move (see [`MuxEvent::Replaced`]).
    pub(super) replaced: HashMap<String, Instant>,
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
    /// The `Waiting` requests left to send, kept across sockets.
    pub(super) waiting: WaitingBudget,
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
            self.shared.lost_socket(&lost.to_string());
            let stayed_up = started.elapsed() >= ping_every;
            if stayed_up {
                attempt = 0;
            }
            attempt = attempt.saturating_add(1);
            let delay = self.retry_delay(&lost, attempt, stayed_up);
            let retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
            warn!(attempt, retry_in_ms, reason = %lost, "epicbox mux session lost, retrying");
            self.set_state(MuxState::Waiting { attempt, delay });
            if self.wait(delay).await {
                self.set_state(MuxState::Stopped);
                return End::Stopped;
            }
        }
    }

    fn retry_delay(&self, lost: &Lost, attempt: u32, stayed_up: bool) -> Duration {
        let random = getrandom::u32().unwrap_or(u32::MAX);
        let backoff = if stayed_up {
            self.first_reconnect(random)
        } else {
            self.settings.backoff.delay(attempt.max(1), random)
        };
        match lost {
            Lost::Rerouted => Duration::ZERO,
            Lost::RateLimited { retry_after } => backoff.max(*retry_after),
            _ => backoff,
        }
    }

    /// A wait between [`MuxOptions::first_reconnect_from`] and
    /// [`MuxOptions::first_reconnect_to`], placed by `random`.
    fn first_reconnect(&self, random: u32) -> Duration {
        let from = self.options.first_reconnect_from;
        let span = self.options.first_reconnect_to.saturating_sub(from);
        let span = u128::from(u64::try_from(span.as_nanos()).unwrap_or(u64::MAX));
        let offset = span
            .checked_mul(u128::from(random))
            .and_then(|scaled| scaled.checked_div(u128::from(u32::MAX)))
            .and_then(|nanos| u64::try_from(nanos).ok())
            .unwrap_or_default();
        from.saturating_add(Duration::from_nanos(offset))
    }

    /// Sleeps for `delay` while still taking commands. `true` when the session was stopped.
    pub(super) async fn wait(&mut self, delay: Duration) -> bool {
        let until = deadline_after(delay);
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return true,
                command = self.commands.recv() => match command {
                    Some(Command::Retry) => return false,
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
            Command::Cancel { reply, .. } => {
                let _ = reply.send(Err(MuxError::NotConnected));
            }
            // The relay pushes the cancellation again on the next attach or resume.
            Command::CancelAck { .. } => {}
            Command::Post { reply, .. } => {
                let _ = reply.send(Err(MuxPostNotSent::NoSocket.into()));
            }
            Command::Waiting { reply, .. } => {
                let _ = reply.send(Err(MuxError::NotConnected));
            }
            Command::Retry => {}
            Command::TakeBack => {
                self.reclaim(None);
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
                self.shared.greeted(false);
                connection.close().await;
                return Ok(End::NotOffered);
            }
            Err(Refusal::Rejected(error)) if !self.offered => {
                // A relay that has never offered mux/1 and answers the greeting with an error
                // will not carry the session; the caller has the 3.0.0 listener for it.
                info!(error = %ErrorChain(&error), "epicbox relay answered the mux/1 greeting with an error");
                self.shared.greeted(false);
                connection.close().await;
                return Ok(End::NotOffered);
            }
            Err(Refusal::Silent(error)) if !self.offered => {
                self.greeting_timeouts = self.greeting_timeouts.saturating_add(1);
                connection.close().await;
                if self.greeting_timeouts >= MAX_GREETING_TIMEOUTS {
                    info!("epicbox relay does not answer the mux/1 greeting");
                    self.shared.greeted(false);
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
        self.shared.greeted(true);
        self.greeting_timeouts = 0;
        self.mailbox_cap = negotiated
            .limits
            .mailboxes_per_socket
            .clamp(1, MAX_MAILBOXES_PER_SOCKET);
        self.publish_layout();
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

    /// Resumes with the token, or attaches every mailbox with signatures. A mailbox another
    /// socket took over stays with it until its hold-off ends: a reconnect is no reason to take
    /// it back, or two installs would trade it on every lost socket.
    async fn begin(&mut self, link: &mut Link) -> Result<(), Lost> {
        self.reclaim(Some(Instant::now()));
        if self
            .entries
            .values()
            .all(|entry| self.replaced.contains_key(&entry.key))
        {
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

    /// Forgets the takeovers whose hold-off ended by `now`, or all of them for `None`, so that
    /// [`Manager::unattached`] lists those mailboxes again. Returns whether one was forgotten.
    fn reclaim(&mut self, now: Option<Instant>) -> bool {
        let before = self.replaced.len();
        self.replaced
            .retain(|_, until| now.is_some_and(|now| *until > now));
        if self.replaced.len() == before {
            return false;
        }
        let kept: std::collections::BTreeSet<String> = self.replaced.keys().cloned().collect();
        self.shared.layout().replaced = kept;
        true
    }

    /// Attaches again the mailboxes whose takeover was forgotten, unless a resume in flight will.
    async fn attach_reclaimed(
        &mut self,
        link: &mut Link,
        now: Option<Instant>,
    ) -> Result<(), Lost> {
        if self.reclaim(now) && !link.resume_pending {
            info!("epicbox mux attaching again the mailboxes another socket took over");
            let all = self.unattached(link);
            self.attach(link, all).await?;
        }
        Ok(())
    }

    /// Attaches again, on the same socket, the mailboxes whose `internal` back-off ended. A
    /// resume in flight attaches them once it is answered, as they are no longer waiting.
    async fn retry_attach(&mut self, link: &mut Link) -> Result<(), Lost> {
        let due = link.take_due_retries(Instant::now());
        if link.resume_pending {
            return Ok(());
        }
        let again: Vec<usize> = due
            .into_iter()
            .filter(|index| {
                !link.attached.contains(index)
                    && self
                        .entries
                        .get(index)
                        .is_some_and(|entry| !self.replaced.contains_key(&entry.key))
            })
            .collect();
        if again.is_empty() {
            return Ok(());
        }
        debug!(
            mailboxes = again.len(),
            "epicbox mux attaching again after an internal error"
        );
        self.attach(link, again).await
    }

    pub(super) fn mark_ready(&self, link: &mut Link) {
        if !link.ready {
            link.ready = true;
            *self.shared.last_error() = None;
            self.shared.note(HealthNote::Attached);
            self.set_state(MuxState::Attached);
        }
    }

    /// Attaches the mailboxes `indexes` with signatures over the socket challenge, in frames of
    /// at most the relay's limit. On a socket that negotiated the host-bound form each signature
    /// covers `epicbox-attach/1:<host>:<challenge>` and the entry names the host.
    pub(super) async fn attach(&self, link: &mut Link, indexes: Vec<usize>) -> Result<(), Lost> {
        let per_frame = link.limits.attach_per_frame.clamp(1, MAX_ATTACH_PER_FRAME);
        for chunk in indexes.chunks(per_frame) {
            let mut mailboxes = Vec::with_capacity(chunk.len());
            let mut sent = Vec::with_capacity(chunk.len());
            let bound = link.attach_host.is_some();
            for index in chunk {
                let Some(entry) = self.entries.get(index) else {
                    continue;
                };
                let host = link.attach_host.clone();
                let text = attach_text(host.as_deref(), link.challenge.as_str());
                let signature = signed(&text, entry.identity.secret())
                    .map_err(|error| Lost::Client(ClientError::Frame(error)))?;
                bump(&self.shared.counters.signatures);
                mailboxes.push(AttachEntry {
                    address: entry.key.clone(),
                    signature,
                    host,
                });
                sent.push(*index);
                link.asked.insert(*index);
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
                PendingKind::Attach {
                    indexes: sent,
                    bound,
                },
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
            let reclaim_at = self.replaced.values().min().copied();
            let retry_at = link.next_attach_retry();
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
                () = sleep_until_opt(reclaim_at) => Wake::Reclaim,
                () = sleep_until_opt(retry_at) => Wake::RetryAttach,
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
                Wake::Reclaim => self.attach_reclaimed(link, Some(Instant::now())).await?,
                Wake::RetryAttach => self.retry_attach(link).await?,
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

    pub(super) async fn probe(&mut self, link: &mut Link) -> Result<(), Lost> {
        if !link.ready || link.probe_outstanding || link.attached.is_empty() {
            return Ok(());
        }
        if let Err(next_in) = self.waiting.take(Instant::now()) {
            debug!(
                retry_in_ms = u64::try_from(next_in.as_millis()).unwrap_or(u64::MAX),
                "epicbox mux waiting check skipped by its pace"
            );
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
            Command::Cancel {
                identity,
                txid,
                reply,
            } => self.send_cancel(link, &identity, txid, reply).await?,
            Command::CancelAck { mailbox, txid } => {
                self.send_cancel_ack(link, mailbox, txid).await?;
            }
            Command::Post { post, reply } => self.send_post(link, post, reply).await?,
            Command::Waiting { socket, reply } => self.ask_waiting(link, socket, reply).await?,
            Command::Retry => {}
            Command::TakeBack => self.attach_reclaimed(link, None).await?,
        }
        Ok(())
    }

    /// Sends `Waiting` for [`MuxSession::waiting`]. Commands are applied one at a time and an
    /// `Attach` is written before the next one is read, so a claim the caller made earlier is
    /// on the wire ahead of this frame. Acknowledgements still gathered for the ack window go
    /// out first, so mail the caller settled as stored is not counted in the answer. A question
    /// asked while an earlier socket was up, or before this one is ready, is answered as not
    /// connected. Past the session's `Waiting` budget, or while the relay's `rate_limited` pause
    /// lasts, it is answered as paced and nothing is sent.
    async fn ask_waiting(
        &mut self,
        link: &mut Link,
        socket: u64,
        reply: oneshot::Sender<Result<MuxWaiting, MuxError>>,
    ) -> Result<(), Lost> {
        if socket != self.shared.counters.sockets_opened.load(Ordering::Relaxed)
            || !link.ready
            || link.pending_full()
        {
            let _ = reply.send(Err(MuxError::NotConnected));
            return Ok(());
        }
        self.flush_acks(link).await?;
        if link.pending_full() {
            let _ = reply.send(Err(MuxError::NotConnected));
            return Ok(());
        }
        if let Err(retry_after) = self.waiting.take(Instant::now()) {
            let _ = reply.send(Err(MuxError::Paced { retry_after }));
            return Ok(());
        }
        bump(&self.shared.counters.waiting_probes);
        link.send(
            |reference| MuxClientFrame::Waiting { reference },
            PendingKind::Asked { reply },
        )
        .await
    }

    /// Sends `PostSlate` on the socket the caller saw attached, with the post's txid only when
    /// the socket negotiated `txcancel/1`. A post made while an earlier socket was up, or one the
    /// pending table has no room for, is answered as not sent.
    async fn send_post(
        &self,
        link: &mut Link,
        post: Post,
        reply: oneshot::Sender<Result<(), MuxPostError>>,
    ) -> Result<(), Lost> {
        if post.socket != self.shared.counters.sockets_opened.load(Ordering::Relaxed) {
            let _ = reply.send(Err(MuxPostNotSent::NoSocket.into()));
            return Ok(());
        }
        if link.pending_full() {
            let _ = reply.send(Err(MuxPostNotSent::Busy.into()));
            return Ok(());
        }
        let Post {
            from,
            to,
            message,
            txid,
            ..
        } = post;
        let (epicboxtxid, epicboxtxidsig) = match txid.filter(|_| link.cancel) {
            Some((txid, signature)) => (Some(txid), Some(signature)),
            None => (None, None),
        };
        let reply = PostReply::new(reply);
        link.send(
            |reference| MuxClientFrame::PostSlate {
                reference,
                from,
                to,
                str: message.str,
                signature: message.signature.to_der_hex(),
                epicboxtxid,
                epicboxtxidsig,
            },
            PendingKind::Post { reply },
        )
        .await
    }

    /// Sends `CancelTx` when the socket negotiated `txcancel/1`, and answers `Unsupported`
    /// without sending anything when it did not.
    async fn send_cancel(
        &self,
        link: &mut Link,
        identity: &Identity,
        txid: EpicboxTxId,
        reply: oneshot::Sender<Result<MuxCancelOutcome, MuxError>>,
    ) -> Result<(), Lost> {
        if !link.cancel {
            let _ = reply.send(Ok(MuxCancelOutcome::Unsupported));
            return Ok(());
        }
        let form = CancelSignature::negotiated(link.cancel_form);
        let signature = match form.sign(&txid, identity.secret()) {
            Ok(signature) => signature,
            Err(error) => {
                let _ = reply.send(Err(MuxError::Client(ClientError::Frame(error))));
                return Ok(());
            }
        };
        let address = identity.address().key_text();
        let sent = txid.clone();
        link.send(
            |reference| MuxClientFrame::CancelTx {
                reference,
                address,
                epicboxtxid: sent,
                signature,
            },
            PendingKind::Cancel { reply },
        )
        .await
    }

    /// Sends `CancelAck` for a mailbox attached on a socket that negotiated `txcancel/1`.
    pub(super) async fn send_cancel_ack(
        &self,
        link: &mut Link,
        mailbox: usize,
        txid: RelayTxId,
    ) -> Result<(), Lost> {
        if !link.cancel || !link.attached.contains(&mailbox) {
            return Ok(());
        }
        let Some(entry) = self.entries.get(&mailbox) else {
            return Ok(());
        };
        let key = entry.key.clone();
        link.send(
            |reference| MuxClientFrame::CancelAck {
                reference,
                mailbox: key,
                epicboxtxid: txid,
            },
            PendingKind::CancelAck,
        )
        .await
    }
}
