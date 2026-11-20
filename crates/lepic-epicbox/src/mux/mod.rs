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
mod budget;
mod claims;
mod counters;
mod inbound;
mod link;
mod manager;
mod negotiate;
mod probe;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};
use tracing::instrument::WithSubscriber;
use tracing::{Instrument, info_span};

use crate::address::EpicboxAddress;
use crate::client::{
    Awaiting, CancelToken, ClientError, ClientSettings, Identity, TRANSPORT_ID, seal,
};
use crate::crypto::SignedMessage;
use crate::frame::{EpicboxTxId, RelayMessageId, signed};
use crate::mailbox::{Handled, MailboxHandler, MailboxMessage};
use crate::mux_frame::{MAX_MAILBOXES_PER_SOCKET, MuxCode, RelayTxId};
use crate::session::Connector;

use self::budget::WaitingBudget;
use self::counters::CounterCells;
use self::link::StoredIds;
use self::manager::Manager;

pub use self::probe::{MailboxProbe, ProbeStep, probe_mailbox};

/// Events kept for a receiver that is slow to read.
const EVENT_BACKLOG: usize = 256;

/// The most characters of why a socket was lost that a session keeps. The text can carry a
/// relay's words, which have no length limit of their own; 1024 keeps a whole transport error
/// with its causes, four times the 256 a host shows, so the host's own cap decides what is shown
/// while a relay cannot make a session hold more than about 4 KiB.
const LAST_ERROR_MAX_CHARS: usize = 1024;

/// How long a mailbox another socket took over is left to it before this session attaches it
/// again. Two installs of one wallet on one slot then trade it at most this often while both stay
/// online, and the one that lost it takes it back within this time once the other goes away.
const REPLACED_HOLD_OFF: Duration = Duration::from_secs(600);

/// The window the first reconnect after a lost session is drawn from, so that the wallets one
/// relay restart drops do not all return in the same second.
const FIRST_RECONNECT_FROM: Duration = Duration::from_secs(1);
const FIRST_RECONNECT_TO: Duration = Duration::from_secs(10);

/// `Waiting` requests a session sends per [`WAITING_WINDOW`] by default: a third of Epicmail's
/// 60 a minute per socket.
const WAITING_BUDGET: u32 = 20;
const WAITING_WINDOW: Duration = Duration::from_secs(60);

/// `text` cut to [`LAST_ERROR_MAX_CHARS`] characters, never inside one, ending in `…` when cut.
fn kept_error(text: &str) -> String {
    let mut chars = text.chars();
    let mut kept: String = chars.by_ref().take(LAST_ERROR_MAX_CHARS).collect();
    if chars.next().is_some() {
        kept.pop();
        kept.push('…');
    }
    kept
}

/// Why a call on a mux/1 session failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MuxError {
    /// The session was started outside a tokio runtime.
    #[error("no tokio runtime is running")]
    NoRuntime,
    /// More mailboxes were asked for than one socket carries.
    #[error("a mux/1 socket carries at most {max} mailboxes, {count} were asked for")]
    TooManyMailboxes { count: usize, max: usize },
    /// The mailbox is already on the session.
    #[error("the mailbox is already on the session")]
    DuplicateMailbox,
    /// The relay does not offer mux/1; the session has ended.
    #[error("the relay does not offer mux/1")]
    NotOffered,
    /// The session has ended and takes no more commands.
    #[error("the mux/1 session has ended")]
    Ended,
    /// The session failed on the socket.
    #[error("the mux/1 session failed")]
    Client(#[from] ClientError),
    /// The session's task panicked or was cancelled.
    #[error("the mux/1 task failed")]
    Task(#[source] JoinError),
    /// The request needs a socket and the session had none, or lost it before the answer.
    #[error("the mux/1 session has no socket for the request")]
    NotConnected,
    /// The relay answered the request with an `Error`.
    #[error("the relay refused the request{}", .code.as_ref().map(|code| format!(": {code}")).unwrap_or_default())]
    Refused {
        /// The relay's `code`, when it gave one.
        code: Option<MuxCode>,
    },
    /// Nothing was sent: the session has used its `Waiting` requests for now
    /// ([`MuxOptions::waiting_budget`]), or the relay answered one `rate_limited` and its
    /// `retry_after` has not passed.
    #[error("the mux/1 session paces its waiting requests, next in {}ms", .retry_after.as_millis())]
    Paced {
        /// How long until the session sends the next `Waiting`.
        retry_after: Duration,
    },
}

/// How a [`MuxSession::cancel`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MuxCancelOutcome {
    /// The relay confirmed the cancellation with `TransactionCancelled`.
    Cancelled,
    /// The relay answered `Ok` and did nothing: the transaction is unknown to it, or the address
    /// is not one of its participants.
    NotFoundOrNotParticipant,
    /// The relay did not offer `txcancel/1` on this socket. Nothing was sent: cancel on a short
    /// classic connection ([`crate::EpicboxClient::cancel`]) instead.
    Unsupported,
}

/// The relay's answer to [`MuxSession::waiting`]. Mail the relay pushed before it answered is
/// already queued or handled when the caller reads it, so this plus the queue accounts for
/// every message the relay holds for the attached mailboxes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MuxWaiting {
    /// Messages not yet offered, per attached mailbox index.
    pub waiting: BTreeMap<usize, u64>,
    /// Messages pushed on this socket and not yet acknowledged or held.
    pub inflight: u64,
    /// Messages held back by a `Hold` that has not ended.
    pub held: u64,
}

/// Why a [`MuxSession::post`] ended without the relay's `Ok`. The three variants are three
/// different states of the message: not on the relay, perhaps on the relay, refused by it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MuxPostError {
    /// Nothing was written: the relay does not hold the message. Post it another way or later.
    #[error("the post was not sent on the mux/1 session")]
    NotSent(#[from] MuxPostNotSent),
    /// The frame was written, then the socket was lost or the answer's deadline passed. The
    /// relay may hold the message. The session does not send it again.
    #[error("the post was sent on the mux/1 session and not answered")]
    Unanswered,
    /// The relay answered the post with an `Error`.
    #[error("the relay refused the post{}", .code.as_ref().map(|code| format!(": {code}")).unwrap_or_default())]
    Refused {
        /// The relay's `code` (`post_refused`, `rate_limited`), when it gave one.
        code: Option<MuxCode>,
        /// The `retry_after` of the `Error`, at most an hour, when it gave one.
        retry_after: Option<Duration>,
        /// The `description` of the `Error`, cut to [`crate::MAX_REFUSAL_DESCRIPTION_LEN`]
        /// characters; `None` when it was empty.
        description: Option<String>,
    },
}

/// Why a [`MuxSession::post`] wrote nothing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MuxPostNotSent {
    /// The session has no socket whose first attach or resume was answered.
    #[error("the mux/1 session has no attached socket")]
    NoSocket,
    /// The session has ended.
    #[error("the mux/1 session has ended")]
    Ended,
    /// The relay does not offer mux/1; the session has ended.
    #[error("the relay does not offer mux/1")]
    NotOffered,
    /// The socket has as many requests waiting for an answer as it keeps.
    #[error("the mux/1 socket has too many requests waiting for an answer")]
    Busy,
    /// The message could not be sealed for the recipient.
    #[error("the message could not be sealed")]
    Seal(#[source] ClientError),
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
    /// How long a mailbox another socket took over is left to it ([`MuxEvent::Replaced`]).
    pub replaced_hold_off: Duration,
    /// The shortest wait before the first reconnect after a session that stayed up for a ping
    /// interval was lost. Later attempts follow the client's backoff.
    pub first_reconnect_from: Duration,
    /// The longest such wait.
    pub first_reconnect_to: Duration,
    /// How many `Waiting` requests the session sends in [`MuxOptions::waiting_window`], the
    /// caller's ([`MuxSession::waiting`]) and its own checks together. Past it a caller is
    /// answered [`MuxError::Paced`] and a check is skipped. The default is a third of
    /// Epicmail's 60 a minute per socket.
    pub waiting_budget: u32,
    /// The rolling window of [`MuxOptions::waiting_budget`].
    pub waiting_window: Duration,
}

impl Default for MuxOptions {
    fn default() -> Self {
        Self {
            hold: Duration::from_secs(60),
            waiting_every: Some(Duration::from_secs(300)),
            ack_window: Duration::from_millis(100),
            replaced_hold_off: REPLACED_HOLD_OFF,
            first_reconnect_from: FIRST_RECONNECT_FROM,
            first_reconnect_to: FIRST_RECONNECT_TO,
            waiting_budget: WAITING_BUDGET,
            waiting_window: WAITING_WINDOW,
        }
    }
}

impl MuxOptions {
    /// Sets [`MuxOptions::hold`].
    #[must_use]
    pub fn with_hold(mut self, hold: Duration) -> Self {
        self.hold = hold;
        self
    }

    /// Sets [`MuxOptions::waiting_every`].
    #[must_use]
    pub fn with_waiting_every(mut self, every: Option<Duration>) -> Self {
        self.waiting_every = every;
        self
    }

    /// Sets [`MuxOptions::ack_window`].
    #[must_use]
    pub fn with_ack_window(mut self, window: Duration) -> Self {
        self.ack_window = window;
        self
    }

    /// Sets [`MuxOptions::replaced_hold_off`].
    #[must_use]
    pub fn with_replaced_hold_off(mut self, hold_off: Duration) -> Self {
        self.replaced_hold_off = hold_off;
        self
    }

    /// Sets [`MuxOptions::waiting_budget`] and [`MuxOptions::waiting_window`].
    #[must_use]
    pub fn with_waiting_budget(mut self, budget: u32, window: Duration) -> Self {
        self.waiting_budget = budget;
        self.waiting_window = window;
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
    /// The mailbox was attached on another socket. It keeps its index and the session leaves it
    /// to the other socket for [`MuxOptions::replaced_hold_off`], on this socket and the next
    /// ones, then attaches it again; sooner on [`MuxSession::take_back_now`], or when no owner claims
    /// it any more and one claims it afresh (which gives it a new index). Mail the relay pushed and this session did
    /// not acknowledge goes to whichever socket holds the mailbox.
    Replaced { mailbox: usize },
    /// The relay stopped delivering the mailbox because an operator limit was lowered.
    Limit { mailbox: usize },
    /// A new socket took over the old session with its token, without new signatures.
    Resumed,
    /// The other party cancelled transaction `txid` (`txcancel/1`). Apply it, then call
    /// [`MuxSession::ack_cancelled`]; until then the relay pushes it again on every attach or
    /// resume. Applying must be idempotent, as a push can repeat. Events are lossy for a
    /// receiver that falls behind: the relay's repeat covers that.
    Cancelled { mailbox: usize, txid: EpicboxTxId },
}

/// How much work a session did, since it started. Exact, and cheap to read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MuxCounters {
    /// Sockets opened, the first one included.
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
    /// `Cancelled` pushes received for attached mailboxes.
    pub cancelled: u64,
}

/// Adds the counters of several sessions field by field, saturating.
impl std::iter::Sum for MuxCounters {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |total, one| Self {
            sockets_opened: total.sockets_opened.saturating_add(one.sockets_opened),
            signatures: total.signatures.saturating_add(one.signatures),
            attaches: total.attaches.saturating_add(one.attaches),
            resumes: total.resumes.saturating_add(one.resumes),
            token_unknown: total.token_unknown.saturating_add(one.token_unknown),
            mails: total.mails.saturating_add(one.mails),
            duplicates: total.duplicates.saturating_add(one.duplicates),
            acks: total.acks.saturating_add(one.acks),
            holds: total.holds.saturating_add(one.holds),
            waiting_probes: total.waiting_probes.saturating_add(one.waiting_probes),
            stall_reconnects: total.stall_reconnects.saturating_add(one.stall_reconnects),
            cancelled: total.cancelled.saturating_add(one.cancelled),
        })
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
    /// The cap and the claims as the manager last applied them.
    layout: Mutex<Layout>,
    /// Why the last socket was lost, until a socket attaches again.
    last_error: Mutex<Option<String>>,
}

/// What a session tells its registry about the relay as it happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HealthNote {
    /// The relay answered the greeting: `true` when it offered mux/1.
    Greeted(bool),
    /// A socket attached its mailboxes.
    Attached,
    /// A socket was lost, for this reason.
    Lost(String),
}

/// Told each [`HealthNote`] of a session.
pub(crate) type HealthNotes = Arc<dyn Fn(HealthNote) + Send + Sync>;

/// What a caller placing mailboxes over several sessions reads without waiting for the task.
struct Layout {
    /// The most mailboxes the session may hold, as far as the relay has said.
    cap: usize,
    /// The keys each owner claims.
    claims: BTreeMap<String, BTreeSet<String>>,
    /// Whether the relay's last answer to the greeting offered mux/1; `None` until one is read
    /// or the session gives up on a relay that does not answer.
    offers_mux: Option<bool>,
    /// Where each [`HealthNote`] is told, once a registry set it.
    notes: Option<HealthNotes>,
    /// The keys of the mailboxes another socket took over.
    replaced: BTreeSet<String>,
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

    fn layout(&self) -> std::sync::MutexGuard<'_, Layout> {
        self.layout.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn last_error(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps why the last socket was lost, cut to [`LAST_ERROR_MAX_CHARS`].
    fn lost_socket(&self, why: &str) {
        let kept = kept_error(why);
        *self.last_error() = Some(kept.clone());
        self.note(HealthNote::Lost(kept));
    }

    /// Keeps the relay's answer about mux/1 and tells it to the notes.
    fn greeted(&self, offered: bool) {
        self.layout().offers_mux = Some(offered);
        self.note(HealthNote::Greeted(offered));
    }

    /// Tells `note` to the notes, if a registry set them. Called without the layout lock held
    /// by the caller, as the notes take the health lock.
    fn note(&self, note: HealthNote) {
        let notes = self.layout().notes.clone();
        if let Some(notes) = notes {
            notes(note);
        }
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
    Cancel {
        identity: Identity,
        txid: EpicboxTxId,
        reply: oneshot::Sender<Result<MuxCancelOutcome, MuxError>>,
    },
    CancelAck {
        mailbox: usize,
        txid: RelayTxId,
    },
    Post {
        post: Post,
        reply: oneshot::Sender<Result<(), MuxPostError>>,
    },
    Waiting {
        /// The `sockets_opened` count when the caller saw the session attached.
        socket: u64,
        reply: oneshot::Sender<Result<MuxWaiting, MuxError>>,
    },
    /// Ends the wait before the next reconnect attempt.
    Retry,
    /// Ends every takeover's hold-off: on a socket, attaches those mailboxes again at once;
    /// without one, the next socket attaches them.
    TakeBack,
}

/// A sealed message for [`Command::Post`].
struct Post {
    /// The `sockets_opened` count when the caller saw the session attached. The post goes out
    /// only on that socket.
    socket: u64,
    from: String,
    to: String,
    message: SignedMessage,
    /// The transaction id and the signature of `from` over it, sent only on a socket that
    /// negotiated `txcancel/1`.
    txid: Option<(EpicboxTxId, String)>,
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
    /// Bounds [`MuxSession::waiting`], as the session's own requests are bounded.
    answer_timeout: Duration,
    /// Bounds the attempt [`MuxSession::retry_now`] waits for, with two answers.
    connect_timeout: Duration,
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
            layout: Mutex::new(Layout {
                cap: MAX_MAILBOXES_PER_SOCKET,
                claims: BTreeMap::new(),
                offers_mux: None,
                notes: None,
                replaced: BTreeSet::new(),
            }),
            last_error: Mutex::new(None),
        });
        let cancel = CancelToken::new();
        let answer_timeout = settings.response_timeout;
        let connect_timeout = settings.connect_timeout;
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
            replaced: HashMap::new(),
            mailbox_cap: MAX_MAILBOXES_PER_SOCKET,
            offered: false,
            greeting_timeouts: 0,
            next_index: 0,
            token: None,
            stored: StoredIds::default(),
            commands: receiver,
            cancel: cancel.clone(),
            shared: Arc::clone(&shared),
            waiting: WaitingBudget::new(options.waiting_budget, options.waiting_window),
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
            answer_timeout,
            connect_timeout,
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

    /// Cancels transaction `txid` as `identity`: sends `CancelTx` signed over the id and waits
    /// for the relay's answer. [`MuxCancelOutcome::Unsupported`] when the relay did not offer
    /// `txcancel/1` on the current socket (nothing is sent). [`MuxError::NotConnected`] when
    /// there is no socket, or it was lost before the answer: the cancel may or may not have
    /// happened, and repeating it is safe. [`MuxError::Refused`] carries the relay's `code`
    /// (`cancel_failed`, `bad_signature`, `bad_request`, `rate_limited`).
    pub async fn cancel(
        &self,
        identity: &Identity,
        txid: &EpicboxTxId,
    ) -> Result<MuxCancelOutcome, MuxError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Cancel {
                identity: identity.clone(),
                txid: txid.clone(),
                reply,
            })
            .map_err(|_| MuxError::Ended)?;
        answer.await.map_err(|_| MuxError::NotConnected)?
    }

    /// Posts `plaintext` from `from` to `to` on the session's socket: seals it as
    /// [`crate::MailboxClient::post`] does, sends `PostSlate` with a `ref` and no transaction id,
    /// and waits for the relay's answer. `from` signs the frame and need not be a mailbox of the
    /// session. With no attached socket it returns [`MuxPostNotSent::NoSocket`] at once; it never
    /// opens or waits for one, and the session never sends the post again on a later socket.
    pub async fn post(
        &self,
        from: &Identity,
        to: &EpicboxAddress,
        plaintext: &str,
    ) -> Result<(), MuxPostError> {
        self.post_with(from, to, plaintext, None).await
    }

    /// As [`Self::post`], and on a socket that negotiated `txcancel/1` the frame carries `txid`
    /// with the signature of `from` over it, so that `from` can cancel the copy later with
    /// [`Self::cancel`] or [`crate::EpicboxClient::cancel`]. Without `txcancel/1` the post goes
    /// out without the id. A relay that holds a cancellation of `txid` refuses the post with
    /// `post_refused`.
    pub async fn post_tx(
        &self,
        from: &Identity,
        to: &EpicboxAddress,
        plaintext: &str,
        txid: &EpicboxTxId,
    ) -> Result<(), MuxPostError> {
        self.post_with(from, to, plaintext, Some(txid)).await
    }

    async fn post_with(
        &self,
        from: &Identity,
        to: &EpicboxAddress,
        plaintext: &str,
        txid: Option<&EpicboxTxId>,
    ) -> Result<(), MuxPostError> {
        // Read before the state: a socket opened in between makes the post not sent.
        let socket = self.shared.counters.sockets_opened.load(Ordering::Relaxed);
        match *self.shared.state.borrow() {
            MuxState::Attached => {}
            MuxState::NotOffered => return Err(MuxPostNotSent::NotOffered.into()),
            MuxState::Stopped => return Err(MuxPostNotSent::Ended.into()),
            _ => return Err(MuxPostNotSent::NoSocket.into()),
        }
        let message = seal(plaintext, to, from.secret()).map_err(MuxPostNotSent::Seal)?;
        let txid = match txid {
            Some(txid) => Some((
                txid.clone(),
                signed(txid.as_str(), from.secret())
                    .map_err(|error| MuxPostNotSent::Seal(ClientError::Frame(error)))?,
            )),
            None => None,
        };
        let (reply, answer) = oneshot::channel();
        let post = Post {
            socket,
            from: from.address().to_string(),
            to: to.to_string(),
            message,
            txid,
        };
        self.commands
            .send(Command::Post { post, reply })
            .map_err(|_| self.post_ended())?;
        // The task answers every post it took; a post it never took was not written.
        answer.await.map_err(|_| self.post_ended())?
    }

    /// Asks the relay once what waits for the attached mailboxes, for a read the user asked for.
    /// A claim made before the call is attached before the question goes out, and every `Mail`
    /// the relay sent before its answer is queued (or handled) before this returns. It does not
    /// count toward the session's stall check. With no attached socket it returns
    /// [`MuxError::NotConnected`] at once and never waits for one; an answer that does not come
    /// within [`ClientSettings::response_timeout`] is [`ClientError::Timeout`].
    pub async fn waiting(&self) -> Result<MuxWaiting, MuxError> {
        // Read before the state: a socket opened in between makes the question not sent.
        let socket = self.shared.counters.sockets_opened.load(Ordering::Relaxed);
        match *self.shared.state.borrow() {
            MuxState::Attached => {}
            MuxState::NotOffered => return Err(MuxError::NotOffered),
            MuxState::Stopped => return Err(MuxError::Ended),
            _ => return Err(MuxError::NotConnected),
        }
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Waiting { socket, reply })
            .map_err(|_| MuxError::Ended)?;
        match tokio::time::timeout(self.answer_timeout, answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(MuxError::NotConnected),
            Err(_) => Err(MuxError::Client(ClientError::Timeout {
                awaiting: Awaiting::Answer,
            })),
        }
    }

    /// Tries to reconnect now, for a read the user asked for: a session waiting before its
    /// next attempt starts it at once, and one already connecting goes on. Waits for that
    /// attempt and returns the state it ended in, [`MuxState::Attached`] once the relay answered
    /// the first attach or resume. An attached or ended session is left alone and returns at
    /// once. A mailbox another socket took over stays with it until its hold-off ends
    /// ([`MuxSession::take_back_now`] ends it sooner), so that two installs that both read
    /// often do not trade it on every read. An attempt still under way after the connect
    /// timeout and two answers' time (the greeting's and the attach's) returns
    /// [`MuxState::Connecting`].
    pub async fn retry_now(&self) -> MuxState {
        let mut state = self.shared.state.subscribe();
        let now = *state.borrow_and_update();
        match now {
            MuxState::Attached | MuxState::NotOffered | MuxState::Stopped => return now,
            MuxState::Waiting { .. } => {
                if self.commands.send(Command::Retry).is_err() {
                    return *state.borrow();
                }
            }
            MuxState::Connecting { .. } => {}
        }
        let bound = self
            .connect_timeout
            .saturating_add(self.answer_timeout.saturating_mul(2));
        let settled = tokio::time::timeout(bound, async {
            // Every change counts, so a new wait equal to the old one still ends this.
            while state.changed().await.is_ok() {
                let next = *state.borrow_and_update();
                if !matches!(next, MuxState::Connecting { .. }) {
                    return next;
                }
            }
            *state.borrow()
        })
        .await;
        settled.unwrap_or_else(|_| *state.borrow())
    }

    /// Ends the hold-off of every mailbox another socket of the wallet took over, for a start
    /// or a return to the app: an attached session attaches them again at once, which takes
    /// them from the other socket; a session without a socket attaches them on its next one.
    pub fn take_back_now(&self) {
        let _ = self.commands.send(Command::TakeBack);
    }

    fn post_ended(&self) -> MuxPostNotSent {
        if *self.shared.state.borrow() == MuxState::NotOffered {
            MuxPostNotSent::NotOffered
        } else {
            MuxPostNotSent::Ended
        }
    }

    /// Acknowledges a [`MuxEvent::Cancelled`] once the consumer has applied it. Returns at once;
    /// the frame goes out from the session's task. Sent only when the mailbox is attached on a
    /// socket that negotiated `txcancel/1`; otherwise the relay pushes the cancellation again on
    /// the next attach or resume, which is harmless.
    pub fn ack_cancelled(&self, mailbox: usize, txid: &EpicboxTxId) -> Result<(), MuxError> {
        self.commands
            .send(Command::CancelAck {
                mailbox,
                txid: txid.clone().into(),
            })
            .map_err(|_| MuxError::Ended)
    }

    /// The session's state, as it changes.
    pub fn state(&self) -> watch::Receiver<MuxState> {
        self.shared.state.subscribe()
    }

    /// Mailbox events from now on. A receiver that falls more than a few hundred events behind
    /// loses the oldest.
    pub fn events(&self) -> broadcast::Receiver<MuxEvent> {
        self.shared.events.subscribe()
    }

    /// The work the session has done so far.
    pub fn counters(&self) -> MuxCounters {
        self.shared.counters.snapshot()
    }

    /// Why the session's last socket was lost; none before the first loss and once a socket
    /// attaches again. The text comes raw from the relay or the transport, cut to 1024
    /// characters and otherwise as it came: a reader escapes it before showing it.
    pub fn last_error(&self) -> Option<String> {
        self.shared.last_error().clone()
    }

    /// How many mailboxes `owner` may claim on this session: the session's cap, less the distinct
    /// mailboxes the other owners claim. The cap is [`MAX_MAILBOXES_PER_SOCKET`] until the relay
    /// names a lower limit. As of the last command the session applied; never waits.
    pub fn room_for(&self, owner: &str) -> usize {
        let layout = self.shared.layout();
        let others: BTreeSet<&String> = layout
            .claims
            .iter()
            .filter(|(other, _)| other.as_str() != owner)
            .flat_map(|(_, keys)| keys)
            .collect();
        layout.cap.saturating_sub(others.len())
    }

    /// The most mailboxes the session may hold: [`MAX_MAILBOXES_PER_SOCKET`] until the relay
    /// names a lower limit. As of the last command the session applied; never waits.
    pub fn mailbox_cap(&self) -> usize {
        self.shared.layout().cap
    }

    /// Whether the relay offered mux/1 in its last answer to the greeting: `Some(false)` for an
    /// answer without it, an error in its place, or a relay that never answered and that the
    /// session gave up on as [`MuxState::NotOffered`]. `None` until one of these. A single
    /// greeting left unanswered reads nothing. Never waits.
    pub fn offers_mux(&self) -> Option<bool> {
        self.shared.layout().offers_mux
    }

    /// Tells `notes` each [`HealthNote`] from now on, and the answer about mux/1 already read,
    /// if any. The same lock covers the read and the setting, so no answer falls between them.
    pub(crate) fn note_health(&self, notes: HealthNotes) {
        let mut layout = self.shared.layout();
        if let Some(offered) = layout.offers_mux {
            notes(HealthNote::Greeted(offered));
        }
        layout.notes = Some(notes);
    }

    /// The keys ([`EpicboxAddress::key_text`]) of the mailboxes `owner` claims. As of the last
    /// command the session applied; never waits.
    pub fn claimed_keys(&self, owner: &str) -> BTreeSet<String> {
        self.shared
            .layout()
            .claims
            .get(owner)
            .cloned()
            .unwrap_or_default()
    }

    /// The keys ([`EpicboxAddress::key_text`]) of the mailboxes another socket took over
    /// ([`MuxEvent::Replaced`]) and that the session leaves alone for now. A key leaves the set
    /// when the session attaches it again or no owner claims it any more. Never waits.
    pub fn replaced_keys(&self) -> BTreeSet<String> {
        self.shared.layout().replaced.clone()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn why_a_socket_was_lost_is_kept_up_to_the_cap() {
        let short = "relay closed: going away";
        assert_eq!(kept_error(short), short);
        let at_cap = "é".repeat(LAST_ERROR_MAX_CHARS);
        assert_eq!(kept_error(&at_cap), at_cap);

        let long = format!("relay said: {}", "é".repeat(5000));
        let kept = kept_error(&long);
        assert_eq!(kept.chars().count(), LAST_ERROR_MAX_CHARS);
        assert!(kept.starts_with("relay said: é"), "{kept}");
        assert!(kept.ends_with("é…"), "{kept}");
    }
}
