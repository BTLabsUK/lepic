// SPDX-License-Identifier: Apache-2.0
//! One socket and what is lost with it: the requests waiting for an answer, the mail in
//! flight and the acknowledgements not yet sent.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tokio::time::{Instant, Interval, sleep_until, timeout};

use crate::client::{Awaiting, ClientError};
use tokio::sync::oneshot;

use crate::frame::RelayMessageId;
use crate::mux_frame::{MuxChallenge, MuxClientFrame, MuxLimits};
use crate::session::{Connection, deadline_after};

use super::negotiate::Negotiated;
use super::{MuxCancelOutcome, MuxError, MuxPostError, MuxWaiting};

/// Requests sent and not yet answered. A relay that lets this many pile up is not answering.
const MAX_PENDING: usize = 1024;

/// Message ids kept to recognise a redelivery after an acknowledgement was lost.
const STORED_IDS: usize = 4096;

/// The most bytes of mail a socket keeps in flight: pushed, and not yet acknowledged or held.
/// The relay's `inflight_per_socket` may allow up to 1,024 messages of up to 4 MiB each; past
/// this many bytes a further push is held, as one past the count limit is, and the relay offers
/// it again once the hold ends.
pub(crate) const MAX_INFLIGHT_BYTES: usize = 16 * 1024 * 1024;

/// Messages handed out and not yet acknowledged or held: the mailbox of each and its size.
#[derive(Default)]
pub(super) struct Inflight {
    by_id: HashMap<RelayMessageId, (usize, usize)>,
    bytes: usize,
}

impl Inflight {
    pub(super) fn contains_key(&self, id: &RelayMessageId) -> bool {
        self.by_id.contains_key(id)
    }

    pub(super) fn len(&self) -> usize {
        self.by_id.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// The bytes of all messages in flight.
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether a message of `size` bytes would take the socket past [`MAX_INFLIGHT_BYTES`].
    /// A message is always taken when nothing else is in flight, so one large message cannot
    /// stall the socket.
    pub(super) fn would_overflow(&self, size: usize) -> bool {
        !self.is_empty() && self.bytes.saturating_add(size) > MAX_INFLIGHT_BYTES
    }

    pub(super) fn insert(&mut self, id: RelayMessageId, mailbox: usize, size: usize) {
        if let Some((_, old)) = self.by_id.insert(id, (mailbox, size)) {
            self.bytes = self.bytes.saturating_sub(old);
        }
        self.bytes = self.bytes.saturating_add(size);
    }

    pub(super) fn remove(&mut self, id: &RelayMessageId) {
        if let Some((_, size)) = self.by_id.remove(id) {
            self.bytes = self.bytes.saturating_sub(size);
        }
    }

    /// Forgets the messages of mailbox `index`.
    pub(super) fn forget_mailbox(&mut self, index: usize) {
        let bytes = &mut self.bytes;
        self.by_id.retain(|_, (owner, size)| {
            let keep = *owner != index;
            if !keep {
                *bytes = bytes.saturating_sub(*size);
            }
            keep
        });
    }
}

/// Ids of messages the handler stored, to recognise a redelivery after a lost acknowledgement.
#[derive(Default)]
pub(super) struct StoredIds {
    pub(super) order: VecDeque<RelayMessageId>,
    pub(super) set: HashSet<RelayMessageId>,
}

impl StoredIds {
    pub(super) fn contains(&self, id: &RelayMessageId) -> bool {
        self.set.contains(id)
    }

    pub(super) fn insert(&mut self, id: RelayMessageId) {
        if self.set.insert(id.clone()) {
            self.order.push_back(id);
            if self.order.len() > STORED_IDS
                && let Some(oldest) = self.order.pop_front()
            {
                self.set.remove(&oldest);
            }
        }
    }
}

/// Why a socket was given up.
pub(super) enum Lost {
    Client(ClientError),
    /// Waiting mail was never pushed.
    Stalled,
    /// The relay is draining.
    Shutdown,
    /// The connector's route changed.
    Rerouted,
    RateLimited {
        retry_after: Duration,
    },
}

impl From<ClientError> for Lost {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(error) => write!(f, "{}", ErrorChain(error)),
            Self::Stalled => f.write_str("waiting mail was not pushed"),
            Self::Shutdown => f.write_str("relay is shutting down"),
            Self::Rerouted => f.write_str("route changed"),
            Self::RateLimited { retry_after } => {
                write!(f, "relay rate limited the session for {retry_after:?}")
            }
        }
    }
}

pub(super) enum PendingKind {
    Attach {
        indexes: Vec<usize>,
        /// The signatures name the dialled host: a `wrong_host` answer is retried bare.
        bound: bool,
    },
    Resume,
    Detach,
    Ack {
        ids: Vec<RelayMessageId>,
    },
    Hold,
    Waiting,
    /// A `Waiting` the caller asked for; it does not count toward the stall check.
    Asked {
        reply: oneshot::Sender<Result<MuxWaiting, MuxError>>,
    },
    /// A `CancelTx`; the caller waits for the answer.
    Cancel {
        reply: oneshot::Sender<Result<MuxCancelOutcome, MuxError>>,
    },
    /// A `CancelAck`; the answer needs no action.
    CancelAck,
    /// A `PostSlate`; the caller waits for the answer.
    Post {
        reply: PostReply,
    },
}

/// The caller's end of a post that is being written. Dropped without an answer, when the
/// write failed, the socket was lost, the deadline passed or the session stopped, it answers
/// [`MuxPostError::Unanswered`]: once the write began, the relay may hold the message.
pub(super) struct PostReply(Option<oneshot::Sender<Result<(), MuxPostError>>>);

impl PostReply {
    pub(super) fn new(reply: oneshot::Sender<Result<(), MuxPostError>>) -> Self {
        Self(Some(reply))
    }

    pub(super) fn answer(mut self, result: Result<(), MuxPostError>) {
        if let Some(reply) = self.0.take() {
            let _ = reply.send(result);
        }
    }
}

impl Drop for PostReply {
    fn drop(&mut self) {
        if let Some(reply) = self.0.take() {
            let _ = reply.send(Err(MuxPostError::Unanswered));
        }
    }
}

pub(super) struct Pending {
    pub(super) kind: PendingKind,
    pub(super) deadline: Instant,
}

/// One socket's state. Lost with the socket.
pub(super) struct Link {
    pub(super) connection: Connection,
    pub(super) challenge: MuxChallenge,
    pub(super) limits: MuxLimits,
    /// `txcancel/1` was negotiated on this socket.
    pub(super) cancel: bool,
    /// The relay checks cancels signed over the domain-separated text.
    pub(super) cancel_form: bool,
    /// The host attach signatures are bound to, while the relay takes the host-bound form on
    /// this socket. Cleared when the relay answers `wrong_host` to any host-bound frame: the
    /// rest of the socket signs the bare challenge.
    pub(super) attach_host: Option<String>,
    pub(super) response_timeout: Duration,
    pub(super) pending: BTreeMap<u64, Pending>,
    pub(super) next_ref: u64,
    /// Mailboxes the relay accepted on this socket.
    pub(super) attached: HashSet<usize>,
    /// Messages handed to the handler and not yet acknowledged or held, by mailbox.
    pub(super) inflight: Inflight,
    pub(super) acks: Vec<RelayMessageId>,
    pub(super) ack_due: Option<Instant>,
    /// The first answer to an attach or resume has been seen.
    pub(super) ready: bool,
    pub(super) resume_pending: bool,
    /// A resume was refused: attach every mailbox with signatures.
    pub(super) fallback_attach: bool,
    pub(super) mails_seen: u64,
    /// The number of mails seen at the first of two suspicious checks.
    pub(super) stuck_at: Option<u64>,
    pub(super) probe_outstanding: bool,
    /// Mailboxes sent in an `Attach` on this socket: the relay may push their mail even when
    /// it answered the entry `internal`, so such mail is held, not left in flight.
    pub(super) asked: HashSet<usize>,
    /// Mailboxes the relay answered `internal` and when each is attached again.
    pub(super) attach_retry_at: BTreeMap<usize, Instant>,
    /// The last back-off used for each mailbox answered `internal`, until it attaches.
    pub(super) attach_backoff: HashMap<usize, Duration>,
}

impl Link {
    pub(super) fn new(
        connection: Connection,
        negotiated: Negotiated,
        response_timeout: Duration,
    ) -> Self {
        Self {
            connection,
            challenge: negotiated.challenge,
            limits: negotiated.limits,
            cancel: negotiated.cancel,
            cancel_form: negotiated.cancel_form,
            attach_host: negotiated.attach_host,
            response_timeout,
            pending: BTreeMap::new(),
            next_ref: 0,
            attached: HashSet::new(),
            inflight: Inflight::default(),
            acks: Vec::new(),
            ack_due: None,
            ready: false,
            resume_pending: false,
            fallback_attach: false,
            mails_seen: 0,
            stuck_at: None,
            probe_outstanding: false,
            asked: HashSet::new(),
            attach_retry_at: BTreeMap::new(),
            attach_backoff: HashMap::new(),
        }
    }

    /// Whether [`Self::send`] would refuse another request and drop the socket.
    pub(super) fn pending_full(&self) -> bool {
        self.pending.len() >= MAX_PENDING
    }

    /// Sends the frame `build` makes, numbered, and expects an answer to it.
    pub(super) async fn send(
        &mut self,
        build: impl FnOnce(Option<String>) -> MuxClientFrame,
        kind: PendingKind,
    ) -> Result<(), Lost> {
        if self.pending_full() {
            return Err(Lost::Client(ClientError::Timeout {
                awaiting: Awaiting::Answer,
            }));
        }
        self.next_ref = self.next_ref.saturating_add(1);
        let reference = self.next_ref;
        let text = build(Some(reference.to_string()))
            .to_json()
            .map_err(|error| Lost::Client(ClientError::Frame(error)))?;
        timeout(self.response_timeout, self.connection.send_text(text))
            .await
            .map_err(|_| {
                Lost::Client(ClientError::Timeout {
                    awaiting: Awaiting::Answer,
                })
            })??;
        self.pending.insert(
            reference,
            Pending {
                kind,
                deadline: deadline_after(self.response_timeout),
            },
        );
        Ok(())
    }

    pub(super) fn take_pending(&mut self, reference: Option<&str>) -> Option<Pending> {
        let reference = reference?.parse::<u64>().ok()?;
        self.pending.remove(&reference)
    }

    /// Schedules mailbox `index` to be attached again after the relay answered `internal`:
    /// after `first`, then twice the last wait each time, at most `cap`. Returns the wait.
    pub(super) fn retry_attach_later(
        &mut self,
        index: usize,
        first: Duration,
        cap: Duration,
    ) -> Duration {
        let wait = next_backoff(self.attach_backoff.get(&index).copied(), first, cap);
        self.attach_backoff.insert(index, wait);
        self.attach_retry_at.insert(index, deadline_after(wait));
        wait
    }

    /// The earliest time a mailbox answered `internal` is attached again.
    pub(super) fn next_attach_retry(&self) -> Option<Instant> {
        self.attach_retry_at.values().min().copied()
    }

    /// Takes the mailboxes whose retry is due by `now`.
    pub(super) fn take_due_retries(&mut self, now: Instant) -> Vec<usize> {
        let due: Vec<usize> = self
            .attach_retry_at
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(index, _)| *index)
            .collect();
        for index in &due {
            self.attach_retry_at.remove(index);
        }
        due
    }

    pub(super) fn next_expiry(&self) -> Option<Instant> {
        self.pending.values().map(|pending| pending.deadline).min()
    }

    /// Forgets mailbox `index` on this socket: its mail in flight and its attachment. Returns
    /// whether the relay had it attached here.
    pub(super) fn forget_mailbox(&mut self, index: usize) -> bool {
        self.inflight.forget_mailbox(index);
        self.asked.remove(&index);
        self.attach_retry_at.remove(&index);
        self.attach_backoff.remove(&index);
        self.attached.remove(&index)
    }

    /// Asks the relay to stop delivering `mailboxes` (bare keys) on this socket.
    pub(super) async fn detach(&mut self, mailboxes: Vec<String>) -> Result<(), Lost> {
        self.send(
            |reference| MuxClientFrame::Detach {
                reference,
                mailboxes,
            },
            PendingKind::Detach,
        )
        .await
    }

    /// Forgets mailbox `index` and detaches its key `key` when the relay had it attached here.
    pub(super) async fn drop_mailbox(&mut self, index: usize, key: String) -> Result<(), Lost> {
        if self.forget_mailbox(index) {
            self.detach(vec![key]).await?;
        }
        Ok(())
    }
}

/// The wait after `last`: `first` at the start, then twice the last one, at most `cap`.
fn next_backoff(last: Option<Duration>, first: Duration, cap: Duration) -> Duration {
    last.map_or(first, |last| last.saturating_mul(2)).min(cap)
}

pub(super) async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

pub(super) async fn tick_opt(interval: &mut Option<Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_back_off_starts_at_the_first_wait_doubles_and_stops_at_the_cap() {
        let first = Duration::from_secs(1);
        let cap = Duration::from_secs(60);
        let mut last = None;
        let mut waits = Vec::new();
        for _ in 0..9 {
            let wait = next_backoff(last, first, cap);
            waits.push(wait.as_secs());
            last = Some(wait);
        }
        assert_eq!(waits, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }
}
