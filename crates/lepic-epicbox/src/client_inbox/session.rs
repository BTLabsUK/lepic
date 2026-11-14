// SPDX-License-Identifier: Apache-2.0
//! One connected session: it answers challenges, sends one request at a time, and turns
//! received slates into deliveries.

use std::collections::VecDeque;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::transport::Destination;
use tokio::sync::oneshot;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep_until, timeout, timeout_at};
use tracing::{debug, info, warn};

use crate::address::EpicboxAddress;
use crate::client::{Awaiting, ClientError};
use crate::crypto::ReceivedMessage;
use crate::frame::{ClientFrame, RelayFrame, RelayMessageId, SlateFrame};
use crate::prefilter::Admission;
use crate::session::{Connection, Greeting, deadline_after};

use super::inbox::{Seen, Signed};
use super::manager::{Command, End, Manager};
use super::{ConnectionState, DrainConnection, Mode, RejectionReason};

/// The shortest challenge interval a listener learns from a relay.
const CHALLENGE_INTERVAL_FLOOR: Duration = Duration::from_secs(30);

/// The challenge interval a listener assumes until it has seen two periodic challenges (the
/// greeting is not one).
const UNLEARNED_CHALLENGE_INTERVAL: Duration = Duration::from_secs(60);

/// How long a connection whose route changed is kept for the messages in flight on it.
const REROUTE_GRACE: Duration = Duration::from_secs(30);

/// Requests waiting for the connection. Acknowledgements the client sends on its own are dropped
/// beyond this; the relay redelivers those messages and they are acknowledged then.
const MAX_QUEUED_REQUESTS: usize = 64;

pub(super) enum Request {
    Subscribe,
    Made {
        msg_id: RelayMessageId,
        reply: Option<oneshot::Sender<Result<(), ClientError>>>,
    },
}

pub(super) enum Sent {
    /// Carries the number of the challenge it signed.
    Subscribe { challenge: u64 },
    Made {
        msg_id: RelayMessageId,
        reply: Option<oneshot::Sender<Result<(), ClientError>>>,
    },
}

pub(super) struct Outstanding {
    pub(super) sent: Sent,
    pub(super) deadline: Instant,
}

/// One connected session. Dropping it answers every pending acknowledgement with
/// [`ClientError::NotConnected`].
pub(super) struct Session<'a> {
    pub(super) manager: &'a mut Manager,
    pub(super) connection: Option<Connection>,
    pub(super) challenge: String,
    pub(super) challenge_number: u64,
    pub(super) queue: VecDeque<Request>,
    pub(super) outstanding: Option<Outstanding>,
    /// After `Made` is accepted the relay sends a new challenge, and the next message follows the
    /// `Subscribe` that answers it.
    pub(super) challenge_due: Option<Instant>,
    pub(super) subscribed_at: Option<Instant>,
    /// Rounds this socket saw while a message was held. An acknowledgement does not reset it.
    pub(super) held_rounds: u32,
    /// Set once `held_rounds` reached the limit: the socket is replaced when nothing is in
    /// flight on it, or at this instant.
    pub(super) rotate_by: Option<Instant>,
    pub(super) rotated: bool,
    /// When the last challenge arrived; the greeting's counts as the first.
    pub(super) last_challenge: Instant,
    /// Whether the last challenge came on the relay's own schedule, not as the answer to a
    /// `Made`. The greeting's does not: the gap from it to the first periodic challenge
    /// depends on when the connection opened, so it teaches nothing.
    pub(super) last_challenge_periodic: bool,
    /// The latest gap between two periodic challenges, at least the floor.
    pub(super) challenge_interval: Option<Duration>,
}

impl<'a> Session<'a> {
    pub(super) fn new(
        manager: &'a mut Manager,
        connection: Connection,
        greeting: Greeting,
    ) -> Self {
        Self {
            manager,
            connection: Some(connection),
            challenge: greeting.challenge,
            challenge_number: 0,
            queue: VecDeque::from([Request::Subscribe]),
            outstanding: None,
            challenge_due: None,
            subscribed_at: None,
            held_rounds: 0,
            rotate_by: None,
            rotated: false,
            last_challenge: Instant::now(),
            last_challenge_periodic: false,
            challenge_interval: None,
        }
    }

    /// Runs the session to its end. The reconnect backoff starts over only after a session
    /// stayed subscribed for a ping interval, so a relay that accepts and then drops every
    /// subscription is retried with growing delays.
    pub(super) async fn run(mut self, attempt: &mut u32) -> Result<End, ClientError> {
        let outcome = self.serve().await;
        let ping_every = self.manager.context.settings.ping_interval;
        if self.rotated
            || self
                .subscribed_at
                .is_some_and(|at| at.elapsed() >= ping_every)
        {
            *attempt = 0;
        }
        outcome
    }

    pub(super) async fn serve(&mut self) -> Result<End, ClientError> {
        let settings = &self.manager.context.settings;
        let ping_every = settings.ping_interval;
        let response_timeout = settings.response_timeout;
        let silence_limit = ping_every.saturating_mul(2);
        let first_ping = deadline_after(ping_every);
        let mut pings = interval_at(first_ping, ping_every);
        pings.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let cancel = self.manager.cancel.clone();
        let context = Arc::clone(&self.manager.context);
        let route = self
            .connection
            .as_ref()
            .map_or(0, |connection| connection.route);
        // Set once the route changed: the connection is replaced when nothing is in flight on
        // it, or at this instant.
        let mut reroute_by: Option<Instant> = None;

        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(self.leave().await),
                sent = self.send_next() => sent?,
            }
            self.publish_expecting();
            if let Some(end) = self.end_due(reroute_by).await {
                return end;
            }
            let deadline = self.deadline();
            let challenges_by = self.challenges_by();
            let connection = self.connection.as_mut().ok_or(ClientError::NotConnected)?;
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(self.leave().await),
                command = self.manager.commands.recv() => match command {
                    Some(Command { msg_id, reply }) => self.queue.push_back(Request::Made {
                        msg_id,
                        reply: Some(reply),
                    }),
                    None => return Ok(self.leave().await),
                },
                frame = connection.receive() => self.handle(frame?)?,
                () = context.connector.route_changed(&context.settings.endpoint, route),
                    if reroute_by.is_none() => {
                    reroute_by = Some(deadline_after(REROUTE_GRACE));
                }
                () = sleep_until(reroute_by.unwrap_or_else(Instant::now)), if reroute_by.is_some() => {}
                () = sleep_until(self.rotate_by.unwrap_or_else(Instant::now)), if self.rotate_by.is_some() => {}
                () = sleep_until(challenges_by.unwrap_or_else(Instant::now)), if challenges_by.is_some() => {
                    info!(
                        rounds = self.manager.challenge_rounds,
                        interval_s = self.challenge_interval.map(|interval| interval.as_secs()),
                        "epicbox listener found no challenges, reconnecting"
                    );
                    self.leave().await;
                    return Err(ClientError::Timeout { awaiting: Awaiting::Challenge });
                }
                _ = pings.tick() => {
                    if connection.idle_for() > silence_limit {
                        return Err(ClientError::Timeout { awaiting: Awaiting::Traffic });
                    }
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Ok(self.leave().await),
                        sent = timeout(response_timeout, connection.ping()) => {
                            sent.map_err(|_| ClientError::Timeout { awaiting: Awaiting::Traffic })??;
                        }
                    }
                }
                () = sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                    let awaiting = if self.outstanding.is_some() {
                        Awaiting::Answer
                    } else {
                        Awaiting::Challenge
                    };
                    return Err(ClientError::Timeout { awaiting });
                }
            }
        }
    }

    /// Leaves the socket when its route changed or it is due for rotation, and ends a drain that
    /// is done. `None` keeps serving.
    async fn end_due(&mut self, reroute_by: Option<Instant>) -> Option<Result<End, ClientError>> {
        if let Some(by) = reroute_by
            && (self.is_quiet() || Instant::now() >= by)
        {
            info!("epicbox relay route changed, reconnecting");
            self.leave().await;
            return Some(Err(ClientError::Closed));
        }
        if let Some(by) = self.rotate_by
            && ((self.outstanding.is_none() && self.queue.is_empty()) || Instant::now() >= by)
        {
            info!(
                rounds = self.held_rounds,
                "epicbox listener moving to a fresh socket"
            );
            self.rotated = true;
            self.leave().await;
            return Some(Err(ClientError::Closed));
        }
        if self.is_drained() {
            return Some(Ok(self.finish_drain().await));
        }
        None
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        match (
            self.outstanding.as_ref().map(|o| o.deadline),
            self.challenge_due,
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// When a listener that is subscribed and has nothing in flight gives up on the relay's
    /// challenges. While a request is unanswered, or a challenge is due after a `Made`, the
    /// deadlines of those apply.
    pub(super) fn challenges_by(&self) -> Option<Instant> {
        let rounds = self.manager.challenge_rounds?;
        if self.manager.mode != Mode::Listen
            || self.subscribed_at.is_none()
            || self.outstanding.is_some()
            || self.challenge_due.is_some()
        {
            return None;
        }
        let interval = self
            .challenge_interval
            .unwrap_or(UNLEARNED_CHALLENGE_INTERVAL);
        self.last_challenge
            .checked_add(interval.saturating_mul(rounds))
    }

    /// Notes a challenge that just arrived. The gap between two periodic challenges is the
    /// relay's interval; one that answers a `Made`, or follows one, says nothing about it.
    pub(super) fn note_challenge(&mut self) {
        let now = Instant::now();
        let answers_made = self.challenge_due.is_some()
            || matches!(
                self.outstanding.as_ref().map(|o| &o.sent),
                Some(Sent::Made { .. })
            );
        if !answers_made && self.last_challenge_periodic {
            let gap = now.saturating_duration_since(self.last_challenge);
            self.challenge_interval = Some(gap.max(CHALLENGE_INTERVAL_FLOOR));
        }
        self.last_challenge = now;
        self.last_challenge_periodic = !answers_made;
    }

    pub(super) fn publish_expecting(&self) {
        let expecting =
            self.outstanding.is_some() || !self.queue.is_empty() || self.challenge_due.is_some();
        self.manager
            .shared
            .update(|inbox| inbox.expecting = expecting);
    }

    /// Nothing sent awaits its answer, nothing is queued, and every message handed out was
    /// acknowledged.
    pub(super) fn is_quiet(&self) -> bool {
        self.outstanding.is_none()
            && self.queue.is_empty()
            && self.manager.shared.lock().is_settled()
    }

    pub(super) fn is_drained(&self) -> bool {
        self.manager.mode == Mode::Drain
            && self.subscribed_at.is_some()
            && self.outstanding.is_none()
            && self.queue.is_empty()
            && self.challenge_due.is_none()
            && self.manager.shared.lock().is_settled()
    }

    /// Sends the next queued request when none is unanswered.
    pub(super) async fn send_next(&mut self) -> Result<(), ClientError> {
        if self.outstanding.is_some() {
            return Ok(());
        }
        let Some(request) = self.queue.pop_front() else {
            return Ok(());
        };
        let context = &self.manager.context;
        let identity = &context.identity;
        let (frame, sent) = match request {
            Request::Subscribe => (
                ClientFrame::subscribe(identity.address(), &self.challenge, identity.secret()),
                Sent::Subscribe {
                    challenge: self.challenge_number,
                },
            ),
            Request::Made { msg_id, reply } => (
                ClientFrame::made(identity.address(), &msg_id, identity.secret()),
                Sent::Made { msg_id, reply },
            ),
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                fail_sent(sent, ClientError::Frame(error));
                return Ok(());
            }
        };
        let deadline = deadline_after(context.settings.response_timeout);
        let connection = self.connection.as_mut().ok_or(ClientError::NotConnected)?;
        timeout_at(deadline, connection.send(&frame))
            .await
            .map_err(|_| ClientError::Timeout {
                awaiting: Awaiting::Answer,
            })??;
        if let Sent::Made { msg_id, .. } = &sent {
            debug!(msg_id = %msg_id, "epicbox acknowledgement sent");
        }
        self.outstanding = Some(Outstanding { sent, deadline });
        Ok(())
    }

    pub(super) fn handle(&mut self, frame: RelayFrame) -> Result<(), ClientError> {
        match frame {
            RelayFrame::Challenge { str } => {
                self.note_challenge();
                self.challenge = str;
                self.challenge_number = self.challenge_number.wrapping_add(1);
                self.challenge_due = None;
                self.count_held_round();
                if !self.queue.iter().any(|r| matches!(r, Request::Subscribe)) {
                    self.queue.push_back(Request::Subscribe);
                }
            }
            RelayFrame::Ok => match self.outstanding.take().map(|o| o.sent) {
                Some(Sent::Subscribe { .. }) => self.mark_subscribed(),
                Some(Sent::Made { msg_id, reply }) => {
                    self.manager
                        .shared
                        .update(|inbox| inbox.record_acknowledged(&msg_id));
                    debug!(msg_id = %msg_id, "epicbox message acknowledged");
                    if let Some(reply) = reply {
                        let _ = reply.send(Ok(()));
                    }
                    self.challenge_due = Some(deadline_after(
                        self.manager.context.settings.response_timeout,
                    ));
                }
                None => debug!("epicbox unrequested ok ignored"),
            },
            RelayFrame::Error { kind, .. } => match self.outstanding.take().map(|o| o.sent) {
                Some(Sent::Subscribe { challenge }) if challenge != self.challenge_number => {
                    let error = ClientError::Relay { kind };
                    debug!(error = %ErrorChain(&error), "epicbox subscription to an old challenge refused");
                }
                Some(Sent::Subscribe { .. }) => return Err(ClientError::Relay { kind }),
                Some(sent @ Sent::Made { .. }) => {
                    let error = ClientError::Relay { kind };
                    warn!(error = %ErrorChain(&error), "epicbox acknowledgement refused");
                    fail_sent(sent, error);
                }
                None => {
                    let error = ClientError::Relay { kind };
                    warn!(error = %ErrorChain(&error), "epicbox unrequested error ignored");
                }
            },
            RelayFrame::Slate(slate) => {
                if matches!(
                    self.outstanding.as_ref().map(|o| &o.sent),
                    Some(Sent::Subscribe { .. })
                ) {
                    self.outstanding = None;
                    self.mark_subscribed();
                }
                self.receive_slate(slate);
            }
            RelayFrame::GetVersion { .. } | RelayFrame::Unknown { .. } | RelayFrame::Keepalive => {
                debug!("epicbox frame ignored");
            }
        }
        Ok(())
    }

    /// Counts a round that began while a message is held, for a listener with a limit.
    pub(super) fn count_held_round(&mut self) {
        let Some(limit) = self.manager.held_rounds else {
            return;
        };
        if self.manager.mode != Mode::Listen || self.manager.shared.lock().is_settled() {
            return;
        }
        self.held_rounds = self.held_rounds.saturating_add(1);
        if self.held_rounds >= limit && self.rotate_by.is_none() {
            self.rotate_by = Some(deadline_after(REROUTE_GRACE));
        }
    }

    pub(super) fn mark_subscribed(&mut self) {
        if self.subscribed_at.is_none() {
            self.subscribed_at = Some(Instant::now());
            info!("epicbox subscribed");
            self.manager.shared.set_state(ConnectionState::Subscribed);
        }
    }

    pub(super) fn receive_slate(&mut self, mut slate: SlateFrame) {
        let shared = &self.manager.shared;
        shared.update(|inbox| inbox.counters.seen = inbox.counters.seen.saturating_add(1));
        let msg_id = slate.epicboxmsgid.take();
        let seen = match &msg_id {
            Some(msg_id) => shared.lock().seen(msg_id),
            None => Seen::New,
        };
        match (seen, msg_id) {
            (Seen::Held, Some(msg_id)) => {
                debug!(msg_id = %msg_id, "epicbox redelivery ignored");
            }
            (Seen::Acknowledged, Some(msg_id)) => {
                debug!(msg_id = %msg_id, "epicbox redelivery acknowledged again");
                self.acknowledge_unasked(msg_id);
            }
            (_, msg_id) => self.take_new(&slate, msg_id),
        }
    }

    /// Takes a message not seen before: drops it when the prefilter says so, defers it when the
    /// queue is full, and otherwise opens it and queues the slate or the rejection.
    fn take_new(&mut self, slate: &SlateFrame, msg_id: Option<RelayMessageId>) {
        let shared = &self.manager.shared;
        if !self.admits(&slate.from) {
            shared.update(|inbox| {
                inbox.counters.dropped = inbox.counters.dropped.saturating_add(1);
            });
            debug!(
                msg_id = id_field(msg_id.as_ref()),
                "epicbox message dropped by the prefilter"
            );
            if let Some(msg_id) = msg_id {
                self.acknowledge_unasked(msg_id);
            }
            return;
        }
        if !shared.lock().has_room_for(slate.str.len()) {
            debug!(
                msg_id = id_field(msg_id.as_ref()),
                "epicbox delivery deferred"
            );
            return;
        }
        shared.update(|inbox| {
            inbox.counters.opened = inbox.counters.opened.saturating_add(1);
        });
        let identity = &self.manager.context.identity;
        match ReceivedMessage::open(
            &slate.from,
            &slate.str,
            &slate.signature,
            identity.address(),
            identity.secret(),
        ) {
            Ok(received) => {
                info!(msg_id = id_field(msg_id.as_ref()), "slate received");
                let reply_to = Destination::new(received.sender.to_string());
                let wire =
                    WireSlate::text(MediaType::JSON, received.plaintext.expose_str().to_owned());
                let signed = Signed {
                    from: slate.from.clone(),
                    str: slate.str.clone(),
                    signature: slate.signature.clone(),
                };
                shared.update(|inbox| inbox.push(msg_id, reply_to, wire, signed));
            }
            Err(error) => {
                warn!(
                    msg_id = id_field(msg_id.as_ref()),
                    error = %ErrorChain(&error),
                    "epicbox message rejected"
                );
                let sender = EpicboxAddress::parse(&slate.from, identity.address().network())
                    .ok()
                    .map(|address| address.to_string());
                let reason = RejectionReason::from(&error);
                shared.update(|inbox| inbox.push_rejection(msg_id, sender, reason));
            }
        }
    }

    /// Whether the client's prefilter lets a message from `from` be opened. Without a prefilter
    /// every message is opened.
    pub(super) fn admits(&self, from: &str) -> bool {
        let context = &self.manager.context;
        let Some(prefilter) = &context.prefilter else {
            return true;
        };
        EpicboxAddress::parse(from, context.identity.address().network())
            .is_ok_and(|sender| prefilter.admit(sender.public_key()) == Admission::Accept)
    }

    pub(super) fn acknowledge_unasked(&mut self, msg_id: RelayMessageId) {
        let queued = self
            .queue
            .iter()
            .any(|request| matches!(request, Request::Made { msg_id: id, .. } if *id == msg_id));
        if !queued && self.queue.len() < MAX_QUEUED_REQUESTS {
            self.queue.push_back(Request::Made {
                msg_id,
                reply: None,
            });
        }
    }

    /// Unsubscribes and closes, best effort and briefly.
    pub(super) async fn leave(&mut self) -> End {
        if let Some(mut connection) = self.connection.take() {
            let unsubscribe = ClientFrame::unsubscribe(self.manager.context.identity.address());
            let _ = timeout(Duration::from_millis(250), connection.send(&unsubscribe)).await;
            connection.close().await;
        }
        End::Stopped
    }

    /// Ends a drain. One that hands its connection on keeps it open, with the latest challenge,
    /// for [`Subscription::take_connection`](super::Subscription::take_connection); `is_drained` already holds, so it is quiet.
    pub(super) async fn finish_drain(&mut self) -> End {
        if self.manager.carry.is_some()
            && let Some(connection) = self.connection.take()
        {
            let greeting = Greeting {
                challenge: std::mem::take(&mut self.challenge),
                version: self.manager.shared.lock().relay_version,
            };
            *self
                .manager
                .shared
                .carried
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(DrainConnection {
                connection,
                greeting,
            });
            return End::Drained;
        }
        self.leave().await;
        End::Drained
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let Some(outstanding) = self.outstanding.take() {
            fail_sent(outstanding.sent, ClientError::NotConnected);
        }
        for request in self.queue.drain(..) {
            if let Request::Made {
                reply: Some(reply), ..
            } = request
            {
                let _ = reply.send(Err(ClientError::NotConnected));
            }
        }
    }
}

fn fail_sent(sent: Sent, error: ClientError) {
    if let Sent::Made {
        reply: Some(reply), ..
    } = sent
    {
        let _ = reply.send(Err(error));
    }
}

/// A message id as a log field: empty when the relay sent none.
fn id_field(msg_id: Option<&RelayMessageId>) -> &str {
    msg_id.map_or("", RelayMessageId::as_str)
}
