//! A relay subscription in `listen` or `drain` mode, and its [`Inbound`] side.
//!
//! One task owns the connection. It answers every challenge with a fresh `Subscribe`, sends at
//! most one request at a time because the relay's `Ok` does not say what it answers, sends
//! websocket pings, and reconnects with backoff in `listen` mode. Received messages are checked,
//! decrypted and queued; the [`Subscription`] hands them out and turns acknowledgements into
//! `Made`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{AckToken, BoxFuture, Destination, Envelope, Inbound};
use tokio::runtime::Handle;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep, sleep_until, timeout};
use tracing::{Instrument, debug, info, info_span, warn};

use crate::client::{Awaiting, CancelToken, ClientContext, ClientError, ErrorChain, TRANSPORT_ID};
use crate::crypto::ReceivedMessage;
use crate::frame::{ClientFrame, RelayFrame, SlateFrame, WalletMode};
use crate::session::{Connection, Greeting, ProtocolVersion, deadline_after};

/// Acknowledged message ids remembered per subscription, so a redelivery after a lost `Made`
/// is acknowledged again instead of handed out twice.
const REMEMBERED_ACKNOWLEDGEMENTS: usize = 4096;

/// Received messages waiting to be handed out. Beyond this a relay that pushes faster than the
/// wallet consumes gets no acknowledgement, so it keeps the message for later.
const MAX_READY: usize = 64;

/// Requests waiting for the connection. Acknowledgements the client sends on its own are dropped
/// beyond this; the relay redelivers those messages and they are acknowledged then.
const MAX_QUEUED_REQUESTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Listen,
    Drain,
}

impl Mode {
    /// `listen` registers as the address's live listener. `drain` does not, so a drain never
    /// takes live delivery from a listener elsewhere; stored messages reach both.
    fn wallet_mode(self) -> WalletMode {
        match self {
            Self::Listen => WalletMode::Listener,
            Self::Drain => WalletMode::Send,
        }
    }
}

/// What a subscription is doing, for the host's connection indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionState {
    Connecting {
        attempt: u32,
    },
    Subscribed,
    /// Waiting `delay` before reconnect attempt `attempt`.
    Waiting {
        attempt: u32,
        delay: Duration,
    },
    Stopped,
    Drained,
    Failed,
}

impl ConnectionState {
    pub fn has_ended(self) -> bool {
        matches!(self, Self::Stopped | Self::Drained | Self::Failed)
    }
}

/// A subscription to the wallet's relay address. Dropping it stops the task.
pub struct Subscription {
    mode: Mode,
    shared: Arc<Shared>,
    cancel: CancelToken,
    task: tokio::sync::Mutex<Option<JoinHandle<Result<(), ClientError>>>>,
    ack_timeout: Duration,
}

impl Subscription {
    pub(crate) fn start(context: Arc<ClientContext>, mode: Mode) -> Result<Self, ClientError> {
        let runtime = Handle::try_current().map_err(|_| ClientError::NoRuntime)?;
        let (commands, receiver) = mpsc::unbounded_channel();
        let (status, _) = watch::channel(ConnectionState::Connecting { attempt: 1 });
        let shared = Arc::new(Shared {
            inbox: Mutex::new(InboxState::new()),
            changed: Notify::new(),
            commands,
            status,
        });
        let cancel = CancelToken::new();
        let ack_timeout = context.settings.response_timeout.saturating_mul(2);
        let relay = context.settings.endpoint.domain().to_string();
        let span = match mode {
            Mode::Listen => info_span!("epicbox_listen", transport = TRANSPORT_ID.as_str(), relay),
            Mode::Drain => info_span!("epicbox_drain", transport = TRANSPORT_ID.as_str(), relay),
        };
        let manager = Manager {
            context,
            shared: Arc::clone(&shared),
            commands: receiver,
            mode,
            cancel: cancel.clone(),
        };
        let task = runtime.spawn(manager.run().instrument(span));
        Ok(Self {
            mode,
            shared,
            cancel,
            task: tokio::sync::Mutex::new(Some(task)),
            ack_timeout,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn state(&self) -> watch::Receiver<ConnectionState> {
        self.shared.status.subscribe()
    }

    /// The version the relay reported in the current or last session; `None` when it did not
    /// report one, in which case only the baseline protocol is used.
    pub fn relay_version(&self) -> Option<ProtocolVersion> {
        self.shared.lock().relay_version
    }

    /// Resolves once an envelope is ready to be handed out or the subscription has ended. In
    /// `listen` mode, call [`Inbound::next_envelope`] until it returns `None`, then wait here.
    pub async fn envelope_available(&self) {
        loop {
            let mut notified = pin!(self.shared.changed.notified());
            notified.as_mut().enable();
            {
                let inbox = self.shared.lock();
                if !inbox.ready.is_empty() || inbox.state.has_ended() {
                    return;
                }
            }
            notified.await;
        }
    }

    /// Stops the subscription and waits for its task, which returns promptly from any state.
    /// Returns the task's error the first time it is joined.
    pub async fn stop(&self) -> Result<(), ClientError> {
        self.cancel.cancel();
        self.join().await
    }

    /// Waits until the subscription ends by itself: a drain that is done, or a failure.
    pub async fn finished(&self) -> Result<(), ClientError> {
        self.join().await
    }

    async fn join(&self) -> Result<(), ClientError> {
        let mut task = self.task.lock().await;
        let Some(handle) = task.as_mut() else {
            return match self.shared.lock().state {
                ConnectionState::Failed => Err(ClientError::Ended),
                _ => Ok(()),
            };
        };
        let outcome = handle.await;
        *task = None;
        outcome.map_err(ClientError::Task)?
    }

    async fn acknowledge_message(&self, token: &AckToken) -> Result<(), TransportError> {
        let msg_id = {
            let mut inbox = self.shared.lock();
            match inbox.handed_out.get(token) {
                None => {
                    return Err(TransportError::UnknownAcknowledgement {
                        transport: TRANSPORT_ID,
                    });
                }
                Some(None) => {
                    inbox.handed_out.remove(token);
                    return Ok(());
                }
                Some(Some(msg_id)) => msg_id.clone(),
            }
        };
        let (reply, answer) = oneshot::channel();
        self.shared
            .commands
            .send(Command { msg_id, reply })
            .map_err(|_| ClientError::Ended)?;
        match timeout(self.ack_timeout, answer).await {
            Err(_) => Err(ClientError::Timeout {
                awaiting: Awaiting::Answer,
            }
            .into()),
            Ok(Err(_)) => Err(ClientError::Ended.into()),
            Ok(Ok(result)) => Ok(result?),
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("mode", &self.mode)
            .field("state", &*self.shared.status.borrow())
            .finish_non_exhaustive()
    }
}

impl Inbound for Subscription {
    /// Waits while the relay may still deliver: while connecting, and while a subscription or
    /// acknowledgement is unanswered. Returns `None` once the relay has nothing more to give now,
    /// which in `listen` mode includes the wait between reconnect attempts.
    fn next_envelope(&self) -> BoxFuture<'_, Result<Option<Envelope>, TransportError>> {
        Box::pin(async move {
            loop {
                let mut notified = pin!(self.shared.changed.notified());
                notified.as_mut().enable();
                if let Some(result) = self.shared.lock().take_envelope(self.mode) {
                    return result.map_err(TransportError::from);
                }
                notified.await;
            }
        })
    }

    /// Sends `Made` for the message and waits for the relay to accept it.
    fn acknowledge<'a>(&'a self, token: &'a AckToken) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(self.acknowledge_message(token))
    }
}

struct Command {
    msg_id: String,
    reply: oneshot::Sender<Result<(), ClientError>>,
}

struct Shared {
    inbox: Mutex<InboxState>,
    changed: Notify,
    commands: mpsc::UnboundedSender<Command>,
    status: watch::Sender<ConnectionState>,
}

impl Shared {
    // Every update leaves the state consistent before it can panic, so a poisoned lock is still
    // safe to use.
    fn lock(&self) -> MutexGuard<'_, InboxState> {
        self.inbox.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn update<T>(&self, change: impl FnOnce(&mut InboxState) -> T) -> T {
        let result = change(&mut self.lock());
        self.changed.notify_waiters();
        result
    }

    fn set_state(&self, state: ConnectionState) {
        self.update(|inbox| inbox.state = state);
        self.status.send_replace(state);
    }
}

/// How a received message id relates to what this subscription has seen.
enum Seen {
    New,
    Held,
    Acknowledged,
}

struct InboxState {
    state: ConnectionState,
    /// Whether the relay may still deliver without the caller doing anything.
    expecting: bool,
    relay_version: Option<ProtocolVersion>,
    ready: VecDeque<(Option<String>, Envelope)>,
    /// Handed-out envelopes by token, with the relay message id to acknowledge, if any.
    handed_out: HashMap<AckToken, Option<String>>,
    acknowledged: HashSet<String>,
    acknowledged_order: VecDeque<String>,
    local_tokens: u64,
}

impl InboxState {
    fn new() -> Self {
        Self {
            state: ConnectionState::Connecting { attempt: 1 },
            expecting: true,
            relay_version: None,
            ready: VecDeque::new(),
            handed_out: HashMap::new(),
            acknowledged: HashSet::new(),
            acknowledged_order: VecDeque::new(),
            local_tokens: 0,
        }
    }

    fn take_envelope(&mut self, mode: Mode) -> Option<Result<Option<Envelope>, ClientError>> {
        if let Some((msg_id, envelope)) = self.ready.pop_front() {
            self.handed_out.insert(envelope.ack_token().clone(), msg_id);
            return Some(Ok(Some(envelope)));
        }
        match self.state {
            ConnectionState::Stopped | ConnectionState::Drained => Some(Ok(None)),
            ConnectionState::Failed => Some(Err(ClientError::Ended)),
            ConnectionState::Subscribed if !self.expecting => Some(Ok(None)),
            ConnectionState::Waiting { .. } if mode == Mode::Listen => Some(Ok(None)),
            _ => None,
        }
    }

    fn seen(&self, msg_id: &str) -> Seen {
        if self.acknowledged.contains(msg_id) {
            Seen::Acknowledged
        } else if self.handed_out.values().flatten().any(|id| id == msg_id)
            || self
                .ready
                .iter()
                .any(|(id, _)| id.as_deref() == Some(msg_id))
        {
            Seen::Held
        } else {
            Seen::New
        }
    }

    fn push(&mut self, msg_id: Option<String>, reply_to: Destination, wire: WireSlate) {
        let token = match &msg_id {
            Some(msg_id) => AckToken::new(msg_id.clone()),
            None => {
                self.local_tokens = self.local_tokens.wrapping_add(1);
                AckToken::new(format!("local-{}", self.local_tokens))
            }
        };
        self.ready
            .push_back((msg_id, Envelope::new(token, Some(reply_to), wire)));
    }

    fn record_acknowledged(&mut self, msg_id: &str) {
        self.handed_out
            .retain(|_, id| id.as_deref() != Some(msg_id));
        if self.acknowledged.insert(msg_id.to_owned()) {
            self.acknowledged_order.push_back(msg_id.to_owned());
        }
        while self.acknowledged_order.len() > REMEMBERED_ACKNOWLEDGEMENTS {
            if let Some(oldest) = self.acknowledged_order.pop_front() {
                self.acknowledged.remove(&oldest);
            }
        }
    }

    /// Nothing is waiting to be handed out or acknowledged.
    fn is_settled(&self) -> bool {
        self.ready.is_empty() && self.handed_out.is_empty()
    }
}

/// How a subscription ended without an error.
enum End {
    Stopped,
    Drained,
}

struct Manager {
    context: Arc<ClientContext>,
    shared: Arc<Shared>,
    commands: mpsc::UnboundedReceiver<Command>,
    mode: Mode,
    cancel: CancelToken,
}

impl Manager {
    async fn run(mut self) -> Result<(), ClientError> {
        let outcome = self.connect_loop().await;
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            let _ = command.reply.send(Err(ClientError::Ended));
        }
        let state = match &outcome {
            Ok(End::Stopped) => ConnectionState::Stopped,
            Ok(End::Drained) => ConnectionState::Drained,
            Err(_) => ConnectionState::Failed,
        };
        self.shared.update(|inbox| inbox.expecting = false);
        self.shared.set_state(state);
        match outcome {
            Ok(End::Stopped) => {
                info!("epicbox stopped");
                Ok(())
            }
            Ok(End::Drained) => {
                info!("epicbox drained");
                Ok(())
            }
            Err(error) => {
                warn!(error = %ErrorChain(&error), "epicbox subscription failed");
                Err(error)
            }
        }
    }

    async fn connect_loop(&mut self) -> Result<End, ClientError> {
        let mut attempt: u32 = 0;
        loop {
            attempt = attempt.saturating_add(1);
            self.shared
                .set_state(ConnectionState::Connecting { attempt });
            let opened = tokio::select! {
                biased;
                () = self.cancel.cancelled() => return Ok(End::Stopped),
                opened = self.open() => opened,
            };
            let failure = match opened {
                Ok((connection, greeting)) => {
                    let session = Session::new(self, connection, greeting);
                    match session.run(&mut attempt).await {
                        Ok(end) => return Ok(end),
                        Err(error) => error,
                    }
                }
                Err(error) => error,
            };
            self.shared.update(|inbox| inbox.expecting = false);
            if self.mode == Mode::Drain {
                return Err(failure);
            }
            let delay = self
                .context
                .settings
                .backoff
                .delay(attempt.max(1), getrandom::u32().unwrap_or(u32::MAX));
            warn!(attempt, error = %ErrorChain(&failure), "epicbox disconnected, retrying");
            self.shared
                .set_state(ConnectionState::Waiting { attempt, delay });
            if self.wait(delay).await {
                return Ok(End::Stopped);
            }
        }
    }

    async fn open(&self) -> Result<(Connection, Greeting), ClientError> {
        let settings = &self.context.settings;
        let mut connection = Connection::open(
            self.context.connector.as_ref(),
            &settings.endpoint,
            settings.connect_timeout,
        )
        .await?;
        let greeting = connection.greet(self.mode.wallet_mode(), settings).await?;
        self.shared
            .update(|inbox| inbox.relay_version = greeting.version);
        Ok((connection, greeting))
    }

    /// Sleeps for `delay` while refusing acknowledgements, which need a connection. Returns
    /// whether the subscription was stopped.
    async fn wait(&mut self, delay: Duration) -> bool {
        let mut nap = pin!(sleep(delay));
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return true,
                () = &mut nap => return false,
                Some(command) = self.commands.recv() => {
                    let _ = command.reply.send(Err(ClientError::NotConnected));
                }
            }
        }
    }
}

enum Request {
    Subscribe,
    Made {
        msg_id: String,
        reply: Option<oneshot::Sender<Result<(), ClientError>>>,
    },
}

enum Sent {
    /// Carries the number of the challenge it signed.
    Subscribe { challenge: u64 },
    Made {
        msg_id: String,
        reply: Option<oneshot::Sender<Result<(), ClientError>>>,
    },
}

struct Outstanding {
    sent: Sent,
    deadline: Instant,
}

/// One connected session. Dropping it answers every pending acknowledgement with
/// [`ClientError::NotConnected`].
struct Session<'a> {
    manager: &'a mut Manager,
    connection: Option<Connection>,
    challenge: String,
    challenge_number: u64,
    queue: VecDeque<Request>,
    outstanding: Option<Outstanding>,
    /// After `Made` is accepted the relay sends a new challenge, and the next message follows the
    /// `Subscribe` that answers it.
    challenge_due: Option<Instant>,
    subscribed: bool,
}

impl<'a> Session<'a> {
    fn new(manager: &'a mut Manager, connection: Connection, greeting: Greeting) -> Self {
        Self {
            manager,
            connection: Some(connection),
            challenge: greeting.challenge,
            challenge_number: 0,
            queue: VecDeque::from([Request::Subscribe]),
            outstanding: None,
            challenge_due: None,
            subscribed: false,
        }
    }

    async fn run(mut self, attempt: &mut u32) -> Result<End, ClientError> {
        let settings = &self.manager.context.settings;
        let ping_every = settings.ping_interval;
        let silence_limit = ping_every.saturating_mul(2);
        let first_ping = deadline_after(ping_every);
        let mut pings = interval_at(first_ping, ping_every);
        pings.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let cancel = self.manager.cancel.clone();

        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(self.leave().await),
                sent = self.send_next() => sent?,
            }
            self.publish_expecting();
            if self.is_drained() {
                return Ok(self.finish_drain().await);
            }
            let deadline = self.deadline();
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
                frame = connection.receive() => self.handle(frame?, attempt)?,
                _ = pings.tick() => {
                    if connection.idle_for() > silence_limit {
                        return Err(ClientError::Timeout { awaiting: Awaiting::Traffic });
                    }
                    connection.ping().await?;
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

    fn deadline(&self) -> Option<Instant> {
        match (
            self.outstanding.as_ref().map(|o| o.deadline),
            self.challenge_due,
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn publish_expecting(&self) {
        let expecting =
            self.outstanding.is_some() || !self.queue.is_empty() || self.challenge_due.is_some();
        self.manager
            .shared
            .update(|inbox| inbox.expecting = expecting);
    }

    fn is_drained(&self) -> bool {
        self.manager.mode == Mode::Drain
            && self.subscribed
            && self.outstanding.is_none()
            && self.queue.is_empty()
            && self.challenge_due.is_none()
            && self.manager.shared.lock().is_settled()
    }

    /// Sends the next queued request when none is unanswered.
    async fn send_next(&mut self) -> Result<(), ClientError> {
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
        let connection = self.connection.as_mut().ok_or(ClientError::NotConnected)?;
        connection.send(&frame).await?;
        if let Sent::Made { msg_id, .. } = &sent {
            debug!(msg_id = %msg_id, "epicbox acknowledgement sent");
        }
        self.outstanding = Some(Outstanding {
            sent,
            deadline: deadline_after(context.settings.response_timeout),
        });
        Ok(())
    }

    fn handle(&mut self, frame: RelayFrame, attempt: &mut u32) -> Result<(), ClientError> {
        match frame {
            RelayFrame::Challenge { str } => {
                self.challenge = str;
                self.challenge_number = self.challenge_number.wrapping_add(1);
                self.challenge_due = None;
                if !self.queue.iter().any(|r| matches!(r, Request::Subscribe)) {
                    self.queue.push_back(Request::Subscribe);
                }
            }
            RelayFrame::Ok => match self.outstanding.take().map(|o| o.sent) {
                Some(Sent::Subscribe { .. }) => self.mark_subscribed(attempt),
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
                    self.mark_subscribed(attempt);
                }
                self.receive_slate(slate);
            }
            RelayFrame::GetVersion { .. } | RelayFrame::Unknown { .. } | RelayFrame::Keepalive => {
                debug!("epicbox frame ignored");
            }
        }
        Ok(())
    }

    fn mark_subscribed(&mut self, attempt: &mut u32) {
        if !self.subscribed {
            self.subscribed = true;
            *attempt = 0;
            info!("epicbox subscribed");
            self.manager.shared.set_state(ConnectionState::Subscribed);
        }
    }

    fn receive_slate(&mut self, slate: SlateFrame) {
        let shared = &self.manager.shared;
        let msg_id = slate.epicboxmsgid;
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
            (_, msg_id) => {
                if shared.lock().ready.len() >= MAX_READY {
                    debug!(
                        msg_id = msg_id.as_deref().unwrap_or(""),
                        "epicbox delivery deferred"
                    );
                    return;
                }
                let identity = &self.manager.context.identity;
                match ReceivedMessage::open(
                    &slate.from,
                    &slate.str,
                    &slate.signature,
                    identity.address(),
                    identity.secret(),
                ) {
                    Ok(received) => {
                        info!(msg_id = msg_id.as_deref().unwrap_or(""), "slate received");
                        let reply_to = Destination::new(received.sender.to_string());
                        let wire = WireSlate::text(
                            MediaType::JSON,
                            received.plaintext.expose_str().to_owned(),
                        );
                        shared.update(|inbox| inbox.push(msg_id, reply_to, wire));
                    }
                    // A message that cannot be opened never will be, and the relay delivers
                    // nothing else to this address until it is acknowledged.
                    Err(error) => {
                        warn!(
                            msg_id = msg_id.as_deref().unwrap_or(""),
                            error = %ErrorChain(&error),
                            "epicbox message rejected"
                        );
                        if let Some(msg_id) = msg_id {
                            self.acknowledge_unasked(msg_id);
                        }
                    }
                }
            }
        }
    }

    fn acknowledge_unasked(&mut self, msg_id: String) {
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
    async fn leave(&mut self) -> End {
        if let Some(mut connection) = self.connection.take() {
            let unsubscribe = ClientFrame::unsubscribe(self.manager.context.identity.address());
            let _ = timeout(Duration::from_millis(250), connection.send(&unsubscribe)).await;
            connection.close().await;
        }
        End::Stopped
    }

    async fn finish_drain(&mut self) -> End {
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
