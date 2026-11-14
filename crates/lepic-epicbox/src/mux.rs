// SPDX-License-Identifier: Apache-2.0
//! A mux/1 session: one websocket that carries many mailboxes, which the relay pushes to as mail
//! arrives. The wire format is `mux_frame`; the relay's `docs/mux-1.md` is the specification.
//!
//! This is a transport only. It negotiates the extension, proves every mailbox once per socket,
//! hands each message to a [`MailboxHandler`] and acknowledges it once the handler stored it. It
//! keeps the session alive across drops with a resume token, which is held in memory only.
//!
//! Nothing starts a session on its own. A relay that does not offer mux/1 gives
//! [`MuxState::NotOffered`], and the caller carries on with the 3.0.0 listener.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lepic_primitives::error_chain::ErrorChain;
use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::{
    Instant, Interval, MissedTickBehavior, interval_at, sleep_until, timeout, timeout_at,
};
use tracing::instrument::WithSubscriber;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::address::EpicboxAddress;
use crate::client::{Awaiting, CancelToken, ClientError, ClientSettings, Identity, TRANSPORT_ID};
use crate::frame::{ClientFrame, FrameError, RelayMessageId, WalletMode, signed};
use crate::mailbox::{Handled, MailboxHandler, MailboxMessage, RelayedMail, open_message};
use crate::mux_frame::{
    AttachEntry, AttachedFrame, DetachReason, DetachedFrame, ErrorFrame, MAX_ACK_IDS,
    MAX_ATTACH_PER_FRAME, MAX_MAILBOXES_PER_SOCKET, MailFrame, MuxChallenge, MuxClientFrame,
    MuxCode, MuxLimits, MuxRelayFrame, OkFrame, ResumeToken,
};
use crate::session::{Connection, Connector, deadline_after};

/// Requests sent and not yet answered. A relay that lets this many pile up is not answering.
const MAX_PENDING: usize = 1024;

/// Message ids kept to recognise a redelivery after an acknowledgement was lost.
const STORED_IDS: usize = 4096;

/// The longest `retry_after` honoured, whatever the relay says.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// How long an acknowledgement of an `internal` error waits before it is sent again.
const INTERNAL_RETRY: Duration = Duration::from_secs(1);

/// How long leaving a socket may take.
const LEAVE_GRACE: Duration = Duration::from_millis(500);

/// Events kept for a receiver that is slow to read.
const EVENT_BACKLOG: usize = 256;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MuxError {
    #[error("no tokio runtime is running")]
    NoRuntime,
    #[error("a mux/1 socket carries at most {max} mailboxes, {count} were asked for")]
    TooManyMailboxes { count: usize, max: usize },
    #[error("the mailbox is already on the session")]
    DuplicateMailbox,
    #[error("the relay does not offer mux/1")]
    NotOffered,
    #[error("the mux/1 session has ended")]
    Ended,
    #[error("the mux/1 session failed")]
    Client(#[from] ClientError),
    #[error("the mux/1 task failed")]
    Task(#[source] JoinError),
}

/// How a session paces its work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxOptions {
    /// How long the relay keeps a message back when the handler answers [`Handled::Later`]. Taken
    /// up to whole seconds, between one second and the relay's `hold_max_s`.
    pub hold: Duration,
    /// How often the push path is checked with a `Waiting` request. `None` never checks. Two
    /// checks in a row that show waiting mail while nothing is in flight or held, and no mail
    /// arrived between them, make the session reconnect.
    pub waiting_every: Option<Duration>,
    /// How long acknowledgements are gathered into one `Ack` frame.
    pub ack_window: Duration,
}

impl Default for MuxOptions {
    fn default() -> Self {
        Self {
            hold: Duration::from_secs(60),
            waiting_every: Some(Duration::from_secs(300)),
            ack_window: Duration::from_millis(100),
        }
    }
}

impl MuxOptions {
    #[must_use]
    pub fn with_hold(mut self, hold: Duration) -> Self {
        self.hold = hold;
        self
    }

    #[must_use]
    pub fn with_waiting_every(mut self, every: Option<Duration>) -> Self {
        self.waiting_every = every;
        self
    }

    #[must_use]
    pub fn with_ack_window(mut self, window: Duration) -> Self {
        self.ack_window = window;
        self
    }
}

/// Where a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MuxState {
    /// Opening a socket, negotiating, or waiting for the answer to the first attach or resume.
    Connecting { attempt: u32 },
    /// The relay answered the first attach or resume of this socket.
    Attached,
    /// The socket was lost; the next attempt starts after `delay`.
    Waiting { attempt: u32, delay: Duration },
    /// The relay does not offer mux/1. The session has ended; the socket is closed.
    NotOffered,
    /// The session was stopped.
    Stopped,
}

impl MuxState {
    /// Whether the session will not run again.
    pub fn has_ended(&self) -> bool {
        matches!(self, Self::NotOffered | Self::Stopped)
    }
}

/// Something that happened to a mailbox of the session. Mailboxes are named by the index
/// [`MuxSession::attach`] returned, or their position in the list given to
/// [`MuxSession::start`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MuxEvent {
    /// The relay accepted the mailbox. `waiting` messages follow.
    Attached { mailbox: usize, waiting: u64 },
    /// The relay refused the mailbox. It is not tried again on this socket.
    Refused { mailbox: usize, code: MuxCode },
    /// The mailbox was attached on another socket. It is removed from the session and never
    /// attached again by it.
    Replaced { mailbox: usize },
    /// The relay stopped delivering the mailbox because an operator limit was lowered.
    Limit { mailbox: usize },
    /// A new socket took over the old session with its token, without new signatures.
    Resumed,
}

/// How much work a session did, since it started. Exact, and cheap to read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MuxCounters {
    pub sockets_opened: u64,
    /// Attach signatures made, one per mailbox per signed attach.
    pub signatures: u64,
    /// `Attach` frames sent.
    pub attaches: u64,
    /// `Resume` frames sent.
    pub resumes: u64,
    /// Resumes the relay refused with `token_unknown`, which fell back to signed attaches.
    pub token_unknown: u64,
    /// `Mail` frames received for attached mailboxes.
    pub mails: u64,
    /// Mail that was already stored: acknowledged again, not handed out again.
    pub duplicates: u64,
    /// Message ids sent in `Ack` frames.
    pub acks: u64,
    /// `Hold` frames sent.
    pub holds: u64,
    /// `Waiting` requests sent.
    pub waiting_probes: u64,
    /// Reconnects caused by waiting mail that was never pushed.
    pub stall_reconnects: u64,
}

#[derive(Debug, Default)]
struct CounterCells {
    sockets_opened: AtomicU64,
    signatures: AtomicU64,
    attaches: AtomicU64,
    resumes: AtomicU64,
    token_unknown: AtomicU64,
    mails: AtomicU64,
    duplicates: AtomicU64,
    acks: AtomicU64,
    holds: AtomicU64,
    waiting_probes: AtomicU64,
    stall_reconnects: AtomicU64,
}

fn bump(cell: &AtomicU64) {
    cell.fetch_add(1, Ordering::Relaxed);
}

fn add(cell: &AtomicU64, count: usize) {
    cell.fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
}

impl CounterCells {
    fn snapshot(&self) -> MuxCounters {
        let read = |cell: &AtomicU64| cell.load(Ordering::Relaxed);
        MuxCounters {
            sockets_opened: read(&self.sockets_opened),
            signatures: read(&self.signatures),
            attaches: read(&self.attaches),
            resumes: read(&self.resumes),
            token_unknown: read(&self.token_unknown),
            mails: read(&self.mails),
            duplicates: read(&self.duplicates),
            acks: read(&self.acks),
            holds: read(&self.holds),
            waiting_probes: read(&self.waiting_probes),
            stall_reconnects: read(&self.stall_reconnects),
        }
    }
}

struct Shared {
    counters: CounterCells,
    state: watch::Sender<MuxState>,
    events: broadcast::Sender<MuxEvent>,
    /// Opened mail of a queued session, in arrival order, until the consumer takes it.
    queue: Mutex<VecDeque<MailboxMessage>>,
    /// Counts the mails queued so far. A consumer waits for it to change.
    queued: watch::Sender<u64>,
}

impl Shared {
    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<MailboxMessage>> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, message: MailboxMessage) {
        self.queue().push_back(message);
        self.queued
            .send_modify(|count| *count = count.saturating_add(1));
    }

    /// Drops the queued mail of one mailbox, or of all when `mailbox` is `None`.
    fn purge(&self, mailbox: Option<usize>) {
        let mut queue = self.queue();
        match mailbox {
            Some(index) => queue.retain(|message| message.mailbox() != index),
            None => queue.clear(),
        }
    }
}

enum Command {
    Add {
        identity: Identity,
        reply: oneshot::Sender<Result<usize, MuxError>>,
    },
    Remove {
        key: String,
        reply: oneshot::Sender<bool>,
    },
    Set {
        owner: String,
        /// Add to the owner's claim instead of replacing it.
        merge: bool,
        identities: Vec<Identity>,
        reply: oneshot::Sender<Result<Claimed, MuxError>>,
    },
    Settle {
        id: RelayMessageId,
        handled: Handled,
    },
}

/// Where the opened mail of a session goes.
enum Delivery {
    /// To a handler, one message at a time, on the session's own task.
    Inline(Mutex<Box<dyn MailboxHandler>>),
    /// To the session's queue. The consumer settles each message.
    Queued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Stopped,
    NotOffered,
}

/// A running mux/1 session. Dropping it stops the session; [`MuxSession::stop`] also waits for
/// the final acknowledgements to go out.
pub struct MuxSession {
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
    cancel: CancelToken,
    task: Option<JoinHandle<End>>,
}

impl fmt::Debug for MuxSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MuxSession")
            .field("state", &*self.shared.state.borrow())
            .finish_non_exhaustive()
    }
}

impl Drop for MuxSession {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl MuxSession {
    /// Starts a session on the current tokio runtime. `identities` are the mailboxes to attach,
    /// at most [`MAX_MAILBOXES_PER_SOCKET`], numbered from zero in the order given. Every
    /// message of every mailbox goes to `handler`, one at a time.
    pub fn start(
        settings: ClientSettings,
        connector: Arc<dyn Connector>,
        identities: Vec<Identity>,
        handler: impl MailboxHandler + 'static,
        options: MuxOptions,
    ) -> Result<Self, MuxError> {
        Self::launch(
            settings,
            connector,
            identities,
            Delivery::Inline(Mutex::new(Box::new(handler))),
            options,
        )
    }

    /// Starts a session that queues the mail it opens instead of handling it. The consumer
    /// calls [`MuxSession::take`], and then [`MuxSession::settle`] for every message: until it
    /// does, the message counts against the relay's in-flight limit, so a consumer that stops
    /// settling stops new mail, which is the backpressure meant. The session loop never waits
    /// for the consumer, so pings and the relay's frames keep flowing.
    ///
    /// Mail not settled when the socket drops is forgotten here, and the relay offers it again.
    /// A message settled as stored is acknowledged again if the relay redelivers it.
    pub fn start_queued(
        settings: ClientSettings,
        connector: Arc<dyn Connector>,
        identities: Vec<Identity>,
        options: MuxOptions,
    ) -> Result<Self, MuxError> {
        Self::launch(settings, connector, identities, Delivery::Queued, options)
    }

    fn launch(
        settings: ClientSettings,
        connector: Arc<dyn Connector>,
        identities: Vec<Identity>,
        delivery: Delivery,
        options: MuxOptions,
    ) -> Result<Self, MuxError> {
        let runtime = Handle::try_current().map_err(|_| MuxError::NoRuntime)?;
        if identities.len() > MAX_MAILBOXES_PER_SOCKET {
            return Err(MuxError::TooManyMailboxes {
                count: identities.len(),
                max: MAX_MAILBOXES_PER_SOCKET,
            });
        }
        let (commands, receiver) = mpsc::unbounded_channel();
        let (state, _) = watch::channel(MuxState::Connecting { attempt: 1 });
        let (events, _) = broadcast::channel(EVENT_BACKLOG);
        let (queued, _) = watch::channel(0);
        let shared = Arc::new(Shared {
            counters: CounterCells::default(),
            state,
            events,
            queue: Mutex::new(VecDeque::new()),
            queued,
        });
        let cancel = CancelToken::new();
        let relay = settings.endpoint.domain().to_string();
        let span = info_span!("epicbox_mux", transport = TRANSPORT_ID.as_str(), relay);
        let mut manager = Manager {
            settings,
            connector,
            options,
            delivery,
            entries: BTreeMap::new(),
            keys: HashMap::new(),
            claims: BTreeMap::new(),
            next_index: 0,
            token: None,
            stored: StoredIds::default(),
            commands: receiver,
            cancel: cancel.clone(),
            shared: Arc::clone(&shared),
        };
        for identity in identities {
            manager.add_claimed(identity)?;
        }
        // The host's subscriber is scoped to the calling thread, so the task carries it along.
        let task = runtime.spawn(manager.run().instrument(span).with_current_subscriber());
        Ok(Self {
            shared,
            commands,
            cancel,
            task: Some(task),
        })
    }

    /// Adds a mailbox to the running session and returns its index. The relay's answer arrives as
    /// a [`MuxEvent`]. Refused when the session already has [`MAX_MAILBOXES_PER_SOCKET`]
    /// mailboxes, or this one.
    pub async fn attach(&self, identity: Identity) -> Result<usize, MuxError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Add { identity, reply })
            .map_err(|_| MuxError::Ended)?;
        answer.await.map_err(|_| MuxError::Ended)?
    }

    /// Takes a mailbox off the running session. `false` when it was not on it.
    pub async fn detach(&self, address: &EpicboxAddress) -> Result<bool, MuxError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Remove {
                key: address.key_text(),
                reply,
            })
            .map_err(|_| MuxError::Ended)?;
        answer.await.map_err(|_| MuxError::Ended)
    }

    /// Makes the session's mailboxes exactly `identities`: attaches what is new, detaches what is
    /// gone and keeps the rest, so only new mailboxes cost a signature. Returns the index of
    /// every distinct identity, in the order given (a repeated identity is listed once). Refused
    /// when more than [`MAX_MAILBOXES_PER_SOCKET`] distinct identities are given.
    ///
    /// This is [`MuxSession::set_claim`] for the owner `""`, which also holds the identities the
    /// session started with and those added by [`MuxSession::attach`]. A session with other
    /// owners keeps their mailboxes.
    pub async fn set_mailboxes(&self, identities: Vec<Identity>) -> Result<Vec<usize>, MuxError> {
        self.set_claim("", identities)
            .await
            .map(|done| done.indexes)
    }

    /// Sets what `owner` wants attached, for a session that several consumers share. The
    /// session's mailboxes are the union of every owner's claim: this call attaches what no owner
    /// had, detaches what no owner wants any more and leaves the rest, so one consumer never
    /// detaches another's mailboxes. An empty claim releases the owner. Refused, and nothing
    /// changed, when the union would exceed [`MAX_MAILBOXES_PER_SOCKET`] distinct identities.
    pub async fn set_claim(
        &self,
        owner: &str,
        identities: Vec<Identity>,
    ) -> Result<Claimed, MuxError> {
        self.send_claim(owner, identities, false).await
    }

    /// Adds `identities` to what `owner` already claims and keeps the rest of its claim. The
    /// answer lists the given identities only. For a look at a few mailboxes that must not
    /// release the others.
    pub async fn add_to_claim(
        &self,
        owner: &str,
        identities: Vec<Identity>,
    ) -> Result<Claimed, MuxError> {
        self.send_claim(owner, identities, true).await
    }

    async fn send_claim(
        &self,
        owner: &str,
        identities: Vec<Identity>,
        merge: bool,
    ) -> Result<Claimed, MuxError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Set {
                owner: owner.to_owned(),
                merge,
                identities,
                reply,
            })
            .map_err(|_| MuxError::Ended)?;
        answer.await.map_err(|_| MuxError::Ended)?
    }

    /// Takes the queued mail of `mailboxes` (indexes), oldest first. Never waits. Always empty
    /// for a session started with [`MuxSession::start`].
    pub fn take(&self, mailboxes: &[usize]) -> Vec<MailboxMessage> {
        let mut queue = self.shared.queue();
        let mut taken = Vec::new();
        let mut kept = VecDeque::with_capacity(queue.len());
        for message in queue.drain(..) {
            if mailboxes.contains(&message.mailbox()) {
                taken.push(message);
            } else {
                kept.push_back(message);
            }
        }
        *queue = kept;
        taken
    }

    /// A receiver that changes every time mail is queued. Keep it, call
    /// [`MuxSession::take`], then wait for `changed()`: mail queued in between is not missed.
    pub fn queued(&self) -> watch::Receiver<u64> {
        self.shared.queued.subscribe()
    }

    /// Says what became of a taken message: [`Handled::Stored`] acknowledges it,
    /// [`Handled::Later`] asks the relay to hold it back for [`MuxOptions::hold`]. Returns at
    /// once; the frame goes out from the session's task. Settling a message the socket no
    /// longer owns is harmless: the relay offers it again.
    pub fn settle(&self, id: &RelayMessageId, handled: Handled) -> Result<(), MuxError> {
        self.commands
            .send(Command::Settle {
                id: id.clone(),
                handled,
            })
            .map_err(|_| MuxError::Ended)
    }

    pub fn state(&self) -> watch::Receiver<MuxState> {
        self.shared.state.subscribe()
    }

    /// Mailbox events from now on. A receiver that falls more than a few hundred events behind
    /// loses the oldest.
    pub fn events(&self) -> broadcast::Receiver<MuxEvent> {
        self.shared.events.subscribe()
    }

    pub fn counters(&self) -> MuxCounters {
        self.shared.counters.snapshot()
    }

    /// Stops the session, sending the acknowledgements still queued, and waits for it to end.
    /// [`MuxError::NotOffered`] when it had already ended because the relay does not offer mux/1.
    pub async fn stop(mut self) -> Result<(), MuxError> {
        self.cancel.cancel();
        let Some(task) = self.task.take() else {
            return Err(MuxError::Ended);
        };
        match task.await {
            Ok(End::Stopped) => Ok(()),
            Ok(End::NotOffered) => Err(MuxError::NotOffered),
            Err(error) => Err(MuxError::Task(error)),
        }
    }
}

/// The answer to [`MuxSession::set_claim`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Claimed {
    /// The index of each distinct identity of the claim, in the order given.
    pub indexes: Vec<usize>,
    /// The indexes of those the session did not have before this call. Mail for them can only
    /// arrive after this call.
    pub fresh: Vec<usize>,
}

struct Reconciled {
    indexes: Vec<usize>,
    added: Vec<usize>,
    removed: Vec<(usize, String)>,
}

impl Reconciled {
    fn claimed(&self) -> Claimed {
        Claimed {
            indexes: self.indexes.clone(),
            fresh: self
                .indexes
                .iter()
                .copied()
                .filter(|index| self.added.contains(index))
                .collect(),
        }
    }
}

struct Entry {
    identity: Identity,
    /// The bare key, as the relay names the mailbox.
    key: String,
}

/// Ids of messages the handler stored, to recognise a redelivery after a lost acknowledgement.
#[derive(Default)]
struct StoredIds {
    order: VecDeque<RelayMessageId>,
    set: HashSet<RelayMessageId>,
}

impl StoredIds {
    fn contains(&self, id: &RelayMessageId) -> bool {
        self.set.contains(id)
    }

    fn insert(&mut self, id: RelayMessageId) {
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
enum Lost {
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

enum Refusal {
    NotOffered,
    Failed(ClientError),
}

struct Negotiated {
    challenge: MuxChallenge,
    limits: MuxLimits,
}

enum PendingKind {
    Attach { indexes: Vec<usize> },
    Resume,
    Detach,
    Ack { ids: Vec<RelayMessageId> },
    Hold,
    Waiting,
}

struct Pending {
    kind: PendingKind,
    deadline: Instant,
}

/// One socket's state. Lost with the socket.
struct Link {
    connection: Connection,
    challenge: MuxChallenge,
    limits: MuxLimits,
    response_timeout: Duration,
    pending: BTreeMap<u64, Pending>,
    next_ref: u64,
    /// Mailboxes the relay accepted on this socket.
    attached: HashSet<usize>,
    /// Messages handed to the handler and not yet acknowledged or held, by mailbox.
    inflight: HashMap<RelayMessageId, usize>,
    acks: Vec<RelayMessageId>,
    ack_due: Option<Instant>,
    /// The first answer to an attach or resume has been seen.
    ready: bool,
    resume_pending: bool,
    /// A resume was refused: attach every mailbox with signatures.
    fallback_attach: bool,
    mails_seen: u64,
    /// The number of mails seen at the first of two suspicious checks.
    stuck_at: Option<u64>,
    probe_outstanding: bool,
}

impl Link {
    fn new(connection: Connection, negotiated: Negotiated, response_timeout: Duration) -> Self {
        Self {
            connection,
            challenge: negotiated.challenge,
            limits: negotiated.limits,
            response_timeout,
            pending: BTreeMap::new(),
            next_ref: 0,
            attached: HashSet::new(),
            inflight: HashMap::new(),
            acks: Vec::new(),
            ack_due: None,
            ready: false,
            resume_pending: false,
            fallback_attach: false,
            mails_seen: 0,
            stuck_at: None,
            probe_outstanding: false,
        }
    }

    /// Sends the frame `build` makes, numbered, and expects an answer to it.
    async fn send(
        &mut self,
        build: impl FnOnce(Option<String>) -> MuxClientFrame,
        kind: PendingKind,
    ) -> Result<(), Lost> {
        if self.pending.len() >= MAX_PENDING {
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

    fn take_pending(&mut self, reference: Option<&str>) -> Option<Pending> {
        let reference = reference?.parse::<u64>().ok()?;
        self.pending.remove(&reference)
    }

    fn next_expiry(&self) -> Option<Instant> {
        self.pending.values().map(|pending| pending.deadline).min()
    }

    fn forget_mailbox(&mut self, index: usize) -> bool {
        self.inflight.retain(|_, owner| *owner != index);
        self.attached.remove(&index)
    }
}

async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn tick_opt(interval: &mut Option<Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

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

struct Manager {
    settings: ClientSettings,
    connector: Arc<dyn Connector>,
    options: MuxOptions,
    /// An inline handler is in a `Mutex` only so that `&Manager` is `Send`: it is not `Sync`, and
    /// is always reached through `&mut`.
    delivery: Delivery,
    /// The session's mailboxes by index. Indexes are never reused.
    entries: BTreeMap<usize, Entry>,
    keys: HashMap<String, usize>,
    /// What each owner wants attached. The session's mailboxes are the union of the claims.
    claims: BTreeMap<String, Vec<Identity>>,
    next_index: usize,
    /// The token of the last `Attached`. In memory only.
    token: Option<ResumeToken>,
    stored: StoredIds,
    commands: mpsc::UnboundedReceiver<Command>,
    cancel: CancelToken,
    shared: Arc<Shared>,
}

impl Manager {
    fn set_state(&self, state: MuxState) {
        self.shared.state.send_replace(state);
    }

    fn emit(&self, event: MuxEvent) {
        // No receiver is not a problem.
        let _ = self.shared.events.send(event);
    }

    fn add_entry(&mut self, identity: Identity) -> Result<usize, MuxError> {
        if self.entries.len() >= MAX_MAILBOXES_PER_SOCKET {
            return Err(MuxError::TooManyMailboxes {
                count: self.entries.len().saturating_add(1),
                max: MAX_MAILBOXES_PER_SOCKET,
            });
        }
        let key = identity.address().key_text();
        if self.keys.contains_key(&key) {
            return Err(MuxError::DuplicateMailbox);
        }
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        self.keys.insert(key.clone(), index);
        self.entries.insert(index, Entry { identity, key });
        Ok(index)
    }

    /// Adds an identity to the session and to the claim of owner `""`.
    fn add_claimed(&mut self, identity: Identity) -> Result<usize, MuxError> {
        let claimed = identity.clone();
        let index = self.add_entry(identity)?;
        self.claims.entry(String::new()).or_default().push(claimed);
        Ok(index)
    }

    /// Removes a mailbox from the session and from every claim.
    fn remove_claimed(&mut self, key: &str) -> Option<usize> {
        for claim in self.claims.values_mut() {
            claim.retain(|identity| identity.address().key_text() != key);
        }
        self.claims.retain(|_, claim| !claim.is_empty());
        self.remove_entry(key)
    }

    fn remove_entry(&mut self, key: &str) -> Option<usize> {
        let index = self.keys.remove(key)?;
        self.entries.remove(&index);
        self.shared.purge(Some(index));
        Some(index)
    }

    async fn run(mut self) -> End {
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
    async fn wait(&mut self, delay: Duration) -> bool {
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

    /// Sets the claim of `owner` and makes the entries match the union of the claims. Returns
    /// the index of each identity of the claim, what was added and what was removed.
    fn reconcile(
        &mut self,
        owner: String,
        merge: bool,
        identities: Vec<Identity>,
    ) -> Result<Reconciled, MuxError> {
        let mut own: Vec<(String, Identity)> = Vec::with_capacity(identities.len());
        for identity in identities {
            let key = identity.address().key_text();
            if !own.iter().any(|(known, _)| *known == key) {
                own.push((key, identity));
            }
        }
        let mut kept: Vec<Identity> = Vec::new();
        if merge && let Some(claim) = self.claims.get(&owner) {
            for identity in claim {
                let key = identity.address().key_text();
                if !own.iter().any(|(known, _)| *known == key) {
                    kept.push(identity.clone());
                }
            }
        }
        let mut wanted: Vec<String> = own.iter().map(|(key, _)| key.clone()).collect();
        wanted.extend(kept.iter().map(|identity| identity.address().key_text()));
        for (other, claim) in &self.claims {
            if *other == owner {
                continue;
            }
            for identity in claim {
                let key = identity.address().key_text();
                if !wanted.contains(&key) {
                    wanted.push(key);
                }
            }
        }
        if wanted.len() > MAX_MAILBOXES_PER_SOCKET {
            return Err(MuxError::TooManyMailboxes {
                count: wanted.len(),
                max: MAX_MAILBOXES_PER_SOCKET,
            });
        }
        let claim: Vec<Identity> = own
            .iter()
            .map(|(_, identity)| identity.clone())
            .chain(kept)
            .collect();
        if claim.is_empty() {
            self.claims.remove(&owner);
        } else {
            self.claims.insert(owner, claim);
        }
        let gone: Vec<String> = self
            .keys
            .keys()
            .filter(|key| !wanted.contains(*key))
            .cloned()
            .collect();
        let mut removed = Vec::with_capacity(gone.len());
        for key in gone {
            if let Some(index) = self.remove_entry(&key) {
                removed.push((index, key));
            }
        }
        let mut indexes = Vec::with_capacity(own.len());
        let mut added = Vec::new();
        for (key, identity) in own {
            if let Some(&index) = self.keys.get(&key) {
                indexes.push(index);
            } else {
                let index = self.add_entry(identity)?;
                added.push(index);
                indexes.push(index);
            }
        }
        Ok(Reconciled {
            indexes,
            added,
            removed,
        })
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

    async fn session(&mut self) -> Result<End, Lost> {
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
            Err(Refusal::Failed(error)) => {
                connection.close().await;
                return Err(Lost::Client(error));
            }
        };
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

    /// Asks for mux/1 and reads the relay's answer. The first `Challenge` a relay may send is
    /// ignored: only the challenge of the `Ok` is signed.
    async fn negotiate(&self, connection: &mut Connection) -> Result<Negotiated, Refusal> {
        let timed_out = || {
            Refusal::Failed(ClientError::Timeout {
                awaiting: Awaiting::Answer,
            })
        };
        let deadline = deadline_after(self.settings.response_timeout);
        let details = ClientFrame::client_details_with_mux(
            &self.settings.wallet_version,
            WalletMode::Listener,
        )
        .to_json()
        .map_err(|error| Refusal::Failed(ClientError::Frame(error)))?;
        timeout_at(deadline, connection.send_text(details))
            .await
            .map_err(|_| timed_out())?
            .map_err(Refusal::Failed)?;
        loop {
            let text = timeout_at(deadline, connection.receive_text())
                .await
                .map_err(|_| timed_out())?
                .map_err(Refusal::Failed)?;
            match MuxRelayFrame::from_json(&text) {
                Ok(MuxRelayFrame::Ok(ok)) => return Self::accept(ok),
                Ok(MuxRelayFrame::Error(error)) => {
                    return Err(Refusal::Failed(ClientError::Relay { kind: error.kind }));
                }
                Ok(_) => debug!("epicbox frame ignored during mux negotiation"),
                Err(FrameError::MuxChallenge) => {
                    warn!("epicbox relay sent a mux challenge of the wrong shape");
                    return Err(Refusal::Failed(ClientError::Frame(
                        FrameError::MuxChallenge,
                    )));
                }
                Err(error) => {
                    debug!(error = %ErrorChain(&error), "epicbox frame ignored during mux negotiation");
                }
            }
        }
    }

    fn accept(ok: OkFrame) -> Result<Negotiated, Refusal> {
        if !ok.offers_mux() {
            return Err(Refusal::NotOffered);
        }
        match ok.challenge {
            Some(challenge) => Ok(Negotiated {
                challenge,
                limits: ok.limits,
            }),
            None => Err(Refusal::Failed(ClientError::Frame(
                FrameError::MuxChallenge,
            ))),
        }
    }

    async fn run_link(&mut self, link: &mut Link) -> Result<(), Lost> {
        self.begin(link).await?;
        self.serve(link).await
    }

    /// Resumes with the token, or attaches every mailbox with signatures.
    async fn begin(&mut self, link: &mut Link) -> Result<(), Lost> {
        if self.entries.is_empty() {
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
            let all: Vec<usize> = self.entries.keys().copied().collect();
            self.attach(link, all).await
        }
    }

    fn mark_ready(&self, link: &mut Link) {
        if !link.ready {
            link.ready = true;
            self.set_state(MuxState::Attached);
        }
    }

    /// Attaches the mailboxes `indexes` with signatures over the socket challenge, in frames of
    /// at most the relay's limit.
    async fn attach(&self, link: &mut Link, indexes: Vec<usize>) -> Result<(), Lost> {
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

    async fn serve(&mut self, link: &mut Link) -> Result<(), Lost> {
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
                        let all: Vec<usize> = self.entries.keys().copied().collect();
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

    async fn probe(&self, link: &mut Link) -> Result<(), Lost> {
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
                        if link.forget_mailbox(index) {
                            link.send(
                                |reference| MuxClientFrame::Detach {
                                    reference,
                                    mailboxes: vec![key],
                                },
                                PendingKind::Detach,
                            )
                            .await?;
                        }
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
                if let Some(index) = removed
                    && link.forget_mailbox(index)
                {
                    link.send(
                        |reference| MuxClientFrame::Detach {
                            reference,
                            mailboxes: vec![key],
                        },
                        PendingKind::Detach,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_text(&mut self, link: &mut Link, text: &str) -> Result<(), Lost> {
        let frame = match MuxRelayFrame::from_json(text) {
            Ok(frame) => frame,
            Err(error) => {
                debug!(error = %ErrorChain(&error), "epicbox mux frame ignored");
                return Ok(());
            }
        };
        match frame {
            MuxRelayFrame::Ok(ok) => self.on_ok(link, &ok),
            MuxRelayFrame::Attached(attached) => self.on_attached(link, attached).await,
            MuxRelayFrame::Mail(mail) => self.on_mail(link, mail).await,
            MuxRelayFrame::Detached(detached) => self.on_detached(link, &detached),
            MuxRelayFrame::Error(error) => self.on_error(link, error),
            MuxRelayFrame::Challenge | MuxRelayFrame::Unknown { .. } | MuxRelayFrame::Keepalive => {
                Ok(())
            }
        }
    }

    fn on_ok(&self, link: &mut Link, ok: &OkFrame) -> Result<(), Lost> {
        let Some(pending) = link.take_pending(ok.reference.as_deref()) else {
            debug!("epicbox mux ok without a matching request ignored");
            return Ok(());
        };
        if let PendingKind::Waiting = pending.kind {
            link.probe_outstanding = false;
            if Self::stalled(link, ok) {
                bump(&self.shared.counters.stall_reconnects);
                warn!("epicbox relay holds waiting mail it does not push, reconnecting");
                return Err(Lost::Stalled);
            }
        }
        Ok(())
    }

    /// Whether this probe is the second in a row that finds waiting mail with nothing in flight
    /// or held, and no mail arrived since the first.
    fn stalled(link: &mut Link, ok: &OkFrame) -> bool {
        let waiting = ok
            .waiting
            .as_ref()
            .is_some_and(|waiting| waiting.values().any(|count| *count > 0));
        if !(waiting && ok.inflight == 0 && ok.held == 0 && link.inflight.is_empty()) {
            link.stuck_at = None;
            return false;
        }
        match link.stuck_at {
            Some(mails) if mails == link.mails_seen => true,
            _ => {
                link.stuck_at = Some(link.mails_seen);
                false
            }
        }
    }

    async fn on_attached(&mut self, link: &mut Link, frame: AttachedFrame) -> Result<(), Lost> {
        let Some(pending) = link.take_pending(frame.reference.as_deref()) else {
            debug!("epicbox mux attached without a matching request ignored");
            return Ok(());
        };
        let resumed = matches!(pending.kind, PendingKind::Resume);
        if let Some(token) = frame.token {
            self.token = Some(token);
        }
        let mut unwanted = Vec::new();
        for entry in &frame.mailboxes {
            let Some(&index) = self.keys.get(&entry.mailbox) else {
                if entry.ok {
                    unwanted.push(entry.mailbox.clone());
                }
                continue;
            };
            if entry.ok {
                link.attached.insert(index);
                self.emit(MuxEvent::Attached {
                    mailbox: index,
                    waiting: entry.waiting.unwrap_or_default(),
                });
            } else if !resumed {
                let code = entry
                    .code
                    .clone()
                    .unwrap_or_else(|| MuxCode::Other("unspecified".to_owned()));
                warn!(mailbox = index, code = %code, "epicbox relay refused a mailbox");
                self.emit(MuxEvent::Refused {
                    mailbox: index,
                    code,
                });
            }
        }
        if resumed {
            link.resume_pending = false;
            self.emit(MuxEvent::Resumed);
            // The session the relay held may differ from ours: sign for what it dropped.
            let missing: Vec<usize> = self
                .entries
                .keys()
                .copied()
                .filter(|index| !link.attached.contains(index))
                .collect();
            self.attach(link, missing).await?;
        }
        for chunk in unwanted.chunks(MAX_ATTACH_PER_FRAME) {
            let mailboxes = chunk.to_vec();
            link.send(
                |reference| MuxClientFrame::Detach {
                    reference,
                    mailboxes,
                },
                PendingKind::Detach,
            )
            .await?;
        }
        self.mark_ready(link);
        Ok(())
    }

    async fn on_mail(&mut self, link: &mut Link, mail: MailFrame) -> Result<(), Lost> {
        let Some(&index) = self.keys.get(&mail.mailbox) else {
            debug!("epicbox mux mail for an unknown mailbox ignored");
            return Ok(());
        };
        if !link.attached.contains(&index) {
            debug!(
                mailbox = index,
                "epicbox mux mail for a mailbox not attached ignored"
            );
            return Ok(());
        }
        bump(&self.shared.counters.mails);
        link.mails_seen = link.mails_seen.saturating_add(1);
        if link.inflight.contains_key(&mail.id) {
            return Ok(());
        }
        if link.inflight.len() >= link.limits.inflight_per_socket {
            warn!("epicbox relay pushed more mail than its in-flight limit, message dropped");
            return Ok(());
        }
        let id = mail.id.clone();
        if self.stored.contains(&id) {
            // Stored before, and the acknowledgement was lost: acknowledge again.
            bump(&self.shared.counters.duplicates);
            link.inflight.insert(id.clone(), index);
            return self.queue_ack(link, id).await;
        }
        let Some(entry) = self.entries.get(&index) else {
            return Ok(());
        };
        let content = open_message(&entry.identity, &mail.from, &mail.str, &mail.signature);
        let mut message = MailboxMessage::new(index, id.clone(), content);
        if matches!(self.delivery, Delivery::Queued) {
            message = message.with_relayed(RelayedMail {
                from: mail.from.clone(),
                str: mail.str.clone(),
                signature: mail.signature.clone(),
            });
        }
        link.inflight.insert(id.clone(), index);
        let handler = match &mut self.delivery {
            Delivery::Inline(handler) => handler.get_mut().unwrap_or_else(PoisonError::into_inner),
            Delivery::Queued => {
                self.shared.push(message);
                return Ok(());
            }
        };
        match handler.handle(message).await {
            Handled::Stored => {
                self.stored.insert(id.clone());
                self.queue_ack(link, id).await
            }
            Handled::Later => self.hold(link, id).await,
        }
    }

    async fn queue_ack(&self, link: &mut Link, id: RelayMessageId) -> Result<(), Lost> {
        link.acks.push(id);
        let flush_at = MAX_ACK_IDS.min(link.limits.inflight_per_socket);
        if link.acks.len() >= flush_at || self.options.ack_window.is_zero() {
            self.flush_acks(link).await
        } else {
            if link.ack_due.is_none() {
                link.ack_due = Some(deadline_after(self.options.ack_window));
            }
            Ok(())
        }
    }

    async fn flush_acks(&self, link: &mut Link) -> Result<(), Lost> {
        link.ack_due = None;
        while !link.acks.is_empty() {
            let take = link.acks.len().min(MAX_ACK_IDS);
            let ids: Vec<RelayMessageId> = link.acks.drain(..take).collect();
            for id in &ids {
                link.inflight.remove(id);
            }
            add(&self.shared.counters.acks, ids.len());
            let frame_ids = ids.clone();
            link.send(
                |reference| MuxClientFrame::Ack {
                    reference,
                    ids: frame_ids,
                },
                PendingKind::Ack { ids },
            )
            .await?;
        }
        Ok(())
    }

    async fn hold(&self, link: &mut Link, id: RelayMessageId) -> Result<(), Lost> {
        let hold = self.options.hold;
        let whole = hold
            .as_secs()
            .saturating_add(u64::from(hold.subsec_nanos() > 0));
        let seconds = u32::try_from(whole)
            .unwrap_or(u32::MAX)
            .clamp(1, link.limits.hold_max_s);
        link.inflight.remove(&id);
        bump(&self.shared.counters.holds);
        link.send(
            |reference| MuxClientFrame::Hold {
                reference,
                id,
                seconds,
            },
            PendingKind::Hold,
        )
        .await
    }

    fn on_detached(&mut self, link: &mut Link, detached: &DetachedFrame) -> Result<(), Lost> {
        let index = self.keys.get(&detached.mailbox).copied();
        match &detached.reason {
            DetachReason::Replaced => {
                if let Some(index) = index {
                    // Another socket holds the mailbox. Never attached again from here, or two
                    // instances would take it from each other in a loop.
                    self.remove_entry(&detached.mailbox);
                    link.forget_mailbox(index);
                    info!(
                        mailbox = index,
                        "epicbox mailbox replaced by another socket"
                    );
                    self.emit(MuxEvent::Replaced { mailbox: index });
                }
                Ok(())
            }
            DetachReason::Shutdown => Err(Lost::Shutdown),
            DetachReason::Limit => {
                if let Some(index) = index {
                    link.forget_mailbox(index);
                    self.shared.purge(Some(index));
                    warn!(
                        mailbox = index,
                        "epicbox relay stopped delivering a mailbox: limit"
                    );
                    self.emit(MuxEvent::Limit { mailbox: index });
                }
                Ok(())
            }
            DetachReason::Other(_) => {
                debug!("epicbox mux detached for an unknown reason ignored");
                Ok(())
            }
        }
    }

    fn on_error(&mut self, link: &mut Link, error: ErrorFrame) -> Result<(), Lost> {
        let retry_after =
            Duration::from_secs(error.retry_after.unwrap_or_default()).min(MAX_RETRY_AFTER);
        let code = error.code.clone();
        let Some(pending) = link.take_pending(error.reference.as_deref()) else {
            return match code {
                Some(MuxCode::ClassicOnly | MuxCode::NotMux) => {
                    Err(Lost::Client(ClientError::Relay { kind: error.kind }))
                }
                Some(MuxCode::RateLimited) => Err(Lost::RateLimited { retry_after }),
                _ => {
                    debug!(code = ?code, "epicbox mux error without a matching request ignored");
                    Ok(())
                }
            };
        };
        match pending.kind {
            PendingKind::Resume => {
                link.resume_pending = false;
                if code == Some(MuxCode::RateLimited) {
                    return Err(Lost::RateLimited { retry_after });
                }
                bump(&self.shared.counters.token_unknown);
                info!(code = ?code, "epicbox resume refused, attaching with signatures");
                self.token = None;
                // Sending needs `await`: the serve loop picks the fallback up after this frame.
                link.fallback_attach = true;
                Ok(())
            }
            PendingKind::Attach { indexes } => {
                if code == Some(MuxCode::RateLimited) {
                    return Err(Lost::RateLimited { retry_after });
                }
                let code = code.unwrap_or_else(|| MuxCode::Other("unspecified".to_owned()));
                for index in indexes {
                    self.emit(MuxEvent::Refused {
                        mailbox: index,
                        code: code.clone(),
                    });
                }
                self.mark_ready(link);
                Ok(())
            }
            PendingKind::Ack { ids } => {
                let wait = match code {
                    Some(MuxCode::RateLimited) => retry_after.max(self.options.ack_window),
                    Some(MuxCode::Internal) => INTERNAL_RETRY,
                    _ => return Ok(()),
                };
                link.acks.extend(ids);
                let due = deadline_after(wait);
                link.ack_due = Some(link.ack_due.map_or(due, |current| current.max(due)));
                Ok(())
            }
            PendingKind::Waiting => {
                link.probe_outstanding = false;
                Ok(())
            }
            PendingKind::Hold | PendingKind::Detach => {
                debug!(code = ?code, "epicbox mux request refused");
                Ok(())
            }
        }
    }
}
