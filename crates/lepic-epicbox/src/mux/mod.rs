// SPDX-License-Identifier: Apache-2.0
//! A mux/1 session: one websocket that carries many mailboxes, which the relay pushes to as mail
//! arrives. The wire format is `mux_frame`; `docs/protocols/epicbox-mux.md` is the specification.
//!
//! This is a transport only. It negotiates the extension, proves every mailbox once per socket,
//! hands each message to a [`MailboxHandler`] and acknowledges it once the handler stored it. It
//! keeps the session alive across drops with a resume token, which is held in memory only.
//!
//! Nothing starts a session on its own. A relay that does not offer mux/1 gives
//! [`MuxState::NotOffered`], and the caller carries on with the 3.0.0 listener.

mod acks;
mod claims;
mod counters;
mod inbound;
mod link;
mod manager;
mod negotiate;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};
use tracing::instrument::WithSubscriber;
use tracing::{Instrument, info_span};

use crate::address::EpicboxAddress;
use crate::client::{CancelToken, ClientError, ClientSettings, Identity, TRANSPORT_ID};
use crate::frame::RelayMessageId;
use crate::mailbox::{Handled, MailboxHandler, MailboxMessage};
use crate::mux_frame::{MAX_MAILBOXES_PER_SOCKET, MuxCode};
use crate::session::Connector;

use self::counters::CounterCells;
use self::link::StoredIds;
use self::manager::Manager;

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
    /// The mailbox was attached on another socket. It keeps its index, but the session does not
    /// attach it again, whatever an owner's claim says, until no owner claims it any more and one
    /// claims it afresh (which gives it a new index), or the session is started anew. Attaching it
    /// again by itself would make two instances of one wallet take it from each other.
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
    ///
    /// The handler runs on the session's own task: while it works, pings, acknowledgements and
    /// the relay's frames wait. It must not block or take long. A consumer that cannot promise
    /// that uses [`MuxSession::start_queued`], whose loop never waits for it.
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
            replaced: HashSet::new(),
            mailbox_cap: MAX_MAILBOXES_PER_SOCKET,
            offered: false,
            greeting_timeouts: 0,
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
    /// changed, when the union would exceed [`MAX_MAILBOXES_PER_SOCKET`] distinct identities (or
    /// fewer, when the relay's limit is lower).
    ///
    /// An owner is one of the callers inside LEPIC that share a session (the contacts collect
    /// and the payments listener name theirs); a host does not pick owners. A mailbox that
    /// another socket took over ([`MuxEvent::Replaced`]) stays in the claim and keeps its index,
    /// but is not attached again until no owner claims it.
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

    /// Empties the claim of `owner` without waiting for the session to apply it. The command is
    /// queued before this returns, so a later claim of the same owner is applied after it. For a
    /// caller that must not wait: a session that is still opening its socket applies commands
    /// only once it has one.
    pub fn release_claim(&self, owner: &str) -> Result<(), MuxError> {
        self.queue_claim(owner, Vec::new(), false).map(drop)
    }

    fn queue_claim(
        &self,
        owner: &str,
        identities: Vec<Identity>,
        merge: bool,
    ) -> Result<oneshot::Receiver<Result<Claimed, MuxError>>, MuxError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Set {
                owner: owner.to_owned(),
                merge,
                identities,
                reply,
            })
            .map_err(|_| MuxError::Ended)?;
        Ok(answer)
    }

    async fn send_claim(
        &self,
        owner: &str,
        identities: Vec<Identity>,
        merge: bool,
    ) -> Result<Claimed, MuxError> {
        let answer = self.queue_claim(owner, identities, merge)?;
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
