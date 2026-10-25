//! One-off drains of mailboxes that are not the wallet's own address, such as pairing and
//! contact mailboxes, and posts from their keys (RFC 0002 8.2).
//!
//! A drain uses a connection of its own, never the wallet's listener. It greets the relay as a
//! sender, so the relay never makes it a mailbox's live listener: messages posted while it runs
//! stay stored for the next drain instead of being pushed to it. It subscribes as each mailbox
//! in turn on one connection, signing the latest challenge (`docs/compat/epicbox.md` fact 6).
//! The relay holds back every address on a connection while a message it sent there is not
//! acknowledged, so after a message is kept the drain moves to a new connection.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use lepic_transport::transport::BoxFuture;
use tokio::time::{Instant, timeout, timeout_at};
use tracing::{Instrument, debug, info, info_span, warn};

use crate::address::EpicboxAddress;
use crate::client::{
    Awaiting, ClientContext, ClientError, ClientSettings, ErrorChain, Identity, TRANSPORT_ID,
    post_frame, seal,
};
use crate::client_inbox::RejectionReason;
use crate::crypto::ReceivedMessage;
use crate::frame::{ClientFrame, RelayFrame, RelayMessageId, SlateFrame, WalletMode};
use crate::session::{Connection, Connector, RelayEndpoint, RelayStream, deadline_after};
use crate::tunnel::DialTarget;

/// Messages read from one mailbox in one drain (RFC 0002 10.3).
pub const MAX_MESSAGES_PER_MAILBOX: usize = 32;

/// Mailboxes in one drain (RFC 0002 10.3).
pub const MAX_MAILBOXES_PER_DRAIN: usize = 50;

/// The default bound of a whole drain. It leaves room for a first circuit through tor.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(120);

/// Subscribes re-signed after the relay refused one because its challenge changed meanwhile.
const SUBSCRIBE_RETRIES: u32 = 2;

/// How long leaving a connection may take.
const LEAVE_GRACE: Duration = Duration::from_millis(250);

/// The bounds of one drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainLimits {
    /// Messages the relay may hand out per mailbox, redeliveries included.
    pub messages_per_mailbox: usize,
    /// The whole drain. Mailboxes not reached by then are left for the next drain.
    pub timeout: Duration,
}

impl Default for DrainLimits {
    fn default() -> Self {
        Self {
            messages_per_mailbox: MAX_MESSAGES_PER_MAILBOX,
            timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

/// A message the relay handed out for a mailbox.
#[derive(Debug)]
pub struct MailboxMessage {
    mailbox: usize,
    msg_id: RelayMessageId,
    content: MailboxContent,
}

impl MailboxMessage {
    /// The position of the mailbox in the list given to [`MailboxClient::drain_once`].
    pub fn mailbox(&self) -> usize {
        self.mailbox
    }

    pub fn msg_id(&self) -> &RelayMessageId {
        &self.msg_id
    }

    pub fn content(&self) -> &MailboxContent {
        &self.content
    }

    pub fn into_content(self) -> MailboxContent {
        self.content
    }
}

/// What a mailbox message turned out to be. Anyone may post to a mailbox, so a message that
/// does not open is ordinary.
#[derive(Debug)]
#[non_exhaustive]
pub enum MailboxContent {
    Opened(ReceivedMessage),
    Unopenable {
        /// The sender `from` names, when it parsed. Not proven.
        sender: Option<EpicboxAddress>,
        reason: RejectionReason,
    },
}

/// What a [`MailboxHandler`] did with a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Handled {
    /// The message's effect is stored, or the message is to be dropped: it is acknowledged.
    Stored,
    /// The message stays on the relay for a later drain, and the drain moves on to the next
    /// mailbox.
    Later,
}

/// Receives the messages of a drain, one at a time and in the relay's order.
pub trait MailboxHandler: Send {
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled>;
}

/// How the drain of one mailbox ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MailboxEnd {
    /// The relay had nothing more for it.
    Empty,
    /// [`DrainLimits::messages_per_mailbox`] were handed out; the rest wait for the next drain.
    Capped,
    /// The handler kept a message for later.
    Kept,
    /// The relay refused the acknowledgement; the message stays stored.
    Refused,
    /// The drain's time ran out while this mailbox was drained.
    TimedOut,
    /// The drain ended before this mailbox.
    NotReached,
}

/// What a drain did with one mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MailboxReport {
    /// Messages given to the handler.
    pub handed_out: usize,
    /// Messages acknowledged after the handler stored them.
    pub acknowledged: usize,
    pub end: MailboxEnd,
}

impl MailboxReport {
    fn new(end: MailboxEnd) -> Self {
        Self {
            handed_out: 0,
            acknowledged: 0,
            end,
        }
    }
}

/// What a drain did, one report per mailbox in the order given.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DrainReport {
    pub mailboxes: Vec<MailboxReport>,
    /// Connections the drain opened.
    pub connections: usize,
}

/// Why a drain or a post failed. Messages handed out before a failure were handled; those not
/// acknowledged are handed out again by a later drain.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MailboxError {
    /// No session with the relay could be set up: no connection, no handshake, or no greeting.
    #[error("relay could not be reached")]
    Unreachable(#[source] ClientError),
    /// The connection failed or went silent after the relay greeted.
    #[error("connection to the relay was lost")]
    Lost(#[source] ClientError),
    /// The relay answered in a way the protocol does not allow, or refused a request.
    #[error("relay broke the protocol")]
    Protocol(#[source] ClientError),
    #[error("relay sent a message without a message id")]
    MissingMessageId,
    #[error("{count} mailboxes are more than one drain takes")]
    TooManyMailboxes { count: usize },
    #[error("message could not be prepared")]
    Local(#[source] ClientError),
}

impl MailboxError {
    /// A failure before or while greeting the relay: a refusal is the relay's, anything else
    /// means it could not be reached.
    fn setting_up(error: ClientError) -> Self {
        match error {
            ClientError::Relay { .. }
            | ClientError::UnsupportedRelayVersion { .. }
            | ClientError::Frame(_) => Self::Protocol(error),
            ClientError::Message(_) | ClientError::Randomness(_) => Self::Local(error),
            _ => Self::Unreachable(error),
        }
    }

    fn after_greeting(error: ClientError) -> Self {
        match error {
            ClientError::Relay { .. }
            | ClientError::UnsupportedRelayVersion { .. }
            | ClientError::Frame(_) => Self::Protocol(error),
            ClientError::Message(_) | ClientError::Randomness(_) => Self::Local(error),
            _ => Self::Lost(error),
        }
    }
}

/// Drains mailboxes on one relay and posts from their keys, with keys that need not be the
/// wallet's. Each call uses connections of its own and shares no state with other clients.
#[derive(Clone)]
pub struct MailboxClient {
    settings: ClientSettings,
    connector: Arc<dyn Connector>,
    limits: DrainLimits,
}

impl MailboxClient {
    /// `connector` is the one the wallet's relay client uses, so a drain takes the same way:
    /// through tor when relay traffic goes through it.
    pub fn new(settings: ClientSettings, connector: Arc<dyn Connector>) -> Self {
        Self {
            settings,
            connector,
            limits: DrainLimits::default(),
        }
    }

    /// The same client, which dials the relay at `onion` when its connector goes through a
    /// tunnel and knows no onion of its own for the relay.
    pub fn with_onion(self, onion: DialTarget) -> Self {
        Self {
            connector: Arc::new(OnionConnector {
                inner: self.connector,
                onion,
            }),
            ..self
        }
    }

    pub fn with_limits(self, limits: DrainLimits) -> Self {
        Self { limits, ..self }
    }

    pub fn settings(&self) -> &ClientSettings {
        &self.settings
    }

    pub fn limits(&self) -> DrainLimits {
        self.limits
    }

    /// Drains each mailbox in turn: subscribes as it, gives each message to `handler`, and
    /// acknowledges it only after the handler returns [`Handled::Stored`], until the relay has
    /// none left or a limit is reached. Message ids are deduplicated within the drain: a
    /// message acknowledged once is acknowledged again, not handed out twice.
    ///
    /// Running out of time is not an error: the report says which mailboxes were not done.
    pub async fn drain_once(
        &self,
        mailboxes: &[Identity],
        handler: &mut dyn MailboxHandler,
    ) -> Result<DrainReport, MailboxError> {
        if mailboxes.len() > MAX_MAILBOXES_PER_DRAIN {
            return Err(MailboxError::TooManyMailboxes {
                count: mailboxes.len(),
            });
        }
        let span = info_span!(
            "epicbox_mailbox_drain",
            transport = TRANSPORT_ID.as_str(),
            relay = %self.settings.endpoint.domain(),
        );
        let mut drain = Drain {
            client: self,
            deadline: deadline_after(self.limits.timeout),
            open: None,
            acknowledged: HashSet::new(),
            connections: 0,
            started: Instant::now(),
        };
        drain.run(mailboxes, handler).instrument(span).await
    }

    /// Encrypts `plaintext` from `from` to `to`, posts it on a short connection of its own and
    /// waits for the relay's answer. Any failure to reach the relay or to hear its answer is
    /// [`MailboxError::Unreachable`].
    pub async fn post(
        &self,
        from: &Identity,
        to: &EpicboxAddress,
        plaintext: &str,
    ) -> Result<(), MailboxError> {
        let message = seal(plaintext, to, from.secret()).map_err(MailboxError::Local)?;
        let frame = ClientFrame::post_slate(from.address(), to, &message);
        let context = ClientContext {
            settings: self.settings.clone(),
            identity: from.clone(),
            connector: Arc::clone(&self.connector),
            prefilter: None,
        };
        let span = info_span!(
            "epicbox_mailbox_post",
            transport = TRANSPORT_ID.as_str(),
            relay = %self.settings.endpoint.domain(),
        );
        post_frame(&context, &frame)
            .instrument(span)
            .await
            .map_err(MailboxError::setting_up)
    }
}

impl fmt::Debug for MailboxClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxClient")
            .field("settings", &self.settings)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// A connector that asks its inner one for every connection by way of a given onion.
struct OnionConnector {
    inner: Arc<dyn Connector>,
    onion: DialTarget,
}

impl Connector for OnionConnector {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        self.inner.connect_to_onion(endpoint, &self.onion)
    }

    fn connect_to_onion<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
        onion: &'a DialTarget,
    ) -> BoxFuture<'a, io::Result<Box<dyn RelayStream>>> {
        self.inner.connect_to_onion(endpoint, onion)
    }

    fn connect_timeout(&self, endpoint: &RelayEndpoint, configured: Duration) -> Duration {
        self.inner.connect_timeout(endpoint, configured)
    }

    fn route(&self, endpoint: &RelayEndpoint) -> u64 {
        self.inner.route(endpoint)
    }

    fn route_changed<'a>(&'a self, endpoint: &'a RelayEndpoint, route: u64) -> BoxFuture<'a, ()> {
        self.inner.route_changed(endpoint, route)
    }
}

/// Why the drain of a mailbox stopped short.
enum Stop {
    TimedOut,
    Failed(MailboxError),
}

/// A greeted connection.
struct Open {
    connection: Connection,
    /// The most recent challenge, which the next `Subscribe` signs.
    challenge: String,
    /// The address the connection last subscribed as.
    subscribed: Option<EpicboxAddress>,
}

struct Drain<'a> {
    client: &'a MailboxClient,
    deadline: Instant,
    open: Option<Open>,
    acknowledged: HashSet<RelayMessageId>,
    connections: usize,
    started: Instant,
}

impl Drain<'_> {
    async fn run(
        &mut self,
        mailboxes: &[Identity],
        handler: &mut dyn MailboxHandler,
    ) -> Result<DrainReport, MailboxError> {
        let mut reports = Vec::with_capacity(mailboxes.len());
        let mut failure = None;
        for (index, identity) in mailboxes.iter().enumerate() {
            let mut report = MailboxReport::new(MailboxEnd::NotReached);
            match self.drain(index, identity, handler, &mut report).await {
                Ok(end) => {
                    report.end = end;
                    if matches!(end, MailboxEnd::Kept | MailboxEnd::Refused) {
                        self.leave().await;
                    }
                    reports.push(report);
                }
                Err(Stop::TimedOut) => {
                    report.end = MailboxEnd::TimedOut;
                    reports.push(report);
                    break;
                }
                Err(Stop::Failed(error)) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        self.leave().await;
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if let Some(error) = failure {
            warn!(elapsed_ms, error = %ErrorChain(&error), "epicbox mailbox drain failed");
            return Err(error);
        }
        reports.resize(mailboxes.len(), MailboxReport::new(MailboxEnd::NotReached));
        let count = reports
            .iter()
            .fold(0_usize, |sum, report| sum.saturating_add(report.handed_out));
        info!(elapsed_ms, count, "epicbox mailboxes drained");
        Ok(DrainReport {
            mailboxes: reports,
            connections: self.connections,
        })
    }

    async fn drain(
        &mut self,
        index: usize,
        identity: &Identity,
        handler: &mut dyn MailboxHandler,
        report: &mut MailboxReport,
    ) -> Result<MailboxEnd, Stop> {
        let mut delivered: usize = 0;
        loop {
            if delivered >= self.client.limits.messages_per_mailbox {
                return Ok(MailboxEnd::Capped);
            }
            let Some(slate) = self.subscribe(identity).await? else {
                return Ok(MailboxEnd::Empty);
            };
            delivered = delivered.saturating_add(1);
            let msg_id = slate
                .epicboxmsgid
                .clone()
                .ok_or(Stop::Failed(MailboxError::MissingMessageId))?;
            if self.acknowledged.contains(&msg_id) {
                debug!(msg_id = %msg_id, "epicbox mailbox redelivery acknowledged again");
                if !self.made(identity, &msg_id).await? {
                    return Ok(MailboxEnd::Refused);
                }
                continue;
            }
            debug!(msg_id = %msg_id, "epicbox mailbox message received");
            let content = open_slate(identity, &slate);
            report.handed_out = report.handed_out.saturating_add(1);
            let message = MailboxMessage {
                mailbox: index,
                msg_id: msg_id.clone(),
                content,
            };
            if handler.handle(message).await == Handled::Later {
                debug!(msg_id = %msg_id, "epicbox mailbox message kept for later");
                return Ok(MailboxEnd::Kept);
            }
            if !self.made(identity, &msg_id).await? {
                return Ok(MailboxEnd::Refused);
            }
            report.acknowledged = report.acknowledged.saturating_add(1);
            self.acknowledged.insert(msg_id);
        }
    }

    /// The bound of the next wait for the relay: an answer's own limit, or the drain's end.
    fn wait_deadline(&self) -> Instant {
        deadline_after(self.client.settings.response_timeout).min(self.deadline)
    }

    /// The greeted connection, opened when there is none.
    async fn connection(&mut self) -> Result<&mut Open, Stop> {
        if self.open.is_none() {
            let opened = Self::connect(self.client, self.deadline, self.connections > 0).await?;
            self.connections = self.connections.saturating_add(1);
            self.open = Some(opened);
        }
        self.open
            .as_mut()
            .ok_or(Stop::Failed(MailboxError::Lost(ClientError::NotConnected)))
    }

    /// Opens and greets a connection. It borrows only the client, never the drain, so the
    /// drain's open connection, which is not `Sync`, is not held across an await and the
    /// drain's future stays `Send`. `reached_before` says whether an earlier connection of
    /// this drain reached the relay.
    async fn connect(
        client: &MailboxClient,
        deadline: Instant,
        reached_before: bool,
    ) -> Result<Open, Stop> {
        let settings = &client.settings;
        let attempt = async {
            let mut connection = Connection::open(
                client.connector.as_ref(),
                &settings.endpoint,
                settings.connect_timeout,
            )
            .await?;
            let greeting = connection.greet(WalletMode::Send, settings).await?;
            Ok::<_, ClientError>(Open {
                connection,
                challenge: greeting.challenge,
                subscribed: None,
            })
        };
        match timeout_at(deadline, attempt).await {
            Ok(Ok(open)) => Ok(open),
            Ok(Err(error)) => Err(Stop::Failed(MailboxError::setting_up(error))),
            // A drain that reached the relay before has made progress; one that never did
            // could not reach it.
            Err(_) if reached_before => Err(Stop::TimedOut),
            Err(_) => Err(Stop::Failed(MailboxError::Unreachable(
                ClientError::Timeout {
                    awaiting: Awaiting::Connection,
                },
            ))),
        }
    }

    /// Subscribes as `identity` and returns the message the relay hands out, or `None` when it
    /// has none.
    async fn subscribe(&mut self, identity: &Identity) -> Result<Option<SlateFrame>, Stop> {
        let deadline = self.wait_deadline();
        let overall = self.deadline;
        let stopped = |error| stopped(error, overall);
        let open = self.connection().await?;
        let mut retries: u32 = 0;
        loop {
            let frame =
                ClientFrame::subscribe(identity.address(), &open.challenge, identity.secret())
                    .map_err(|error| {
                        Stop::Failed(MailboxError::Protocol(ClientError::Frame(error)))
                    })?;
            open.connection
                .send_before(&frame, deadline)
                .await
                .map_err(stopped)?;
            open.subscribed = Some(identity.address().clone());
            let mut challenge_changed = false;
            let refused = loop {
                match open
                    .connection
                    .receive_before(deadline, Awaiting::Answer)
                    .await
                    .map_err(stopped)?
                {
                    RelayFrame::Slate(slate) => return Ok(Some(slate)),
                    RelayFrame::Ok => return Ok(None),
                    RelayFrame::Challenge { str } => {
                        open.challenge = str;
                        challenge_changed = true;
                    }
                    RelayFrame::Error { kind, .. } => break kind,
                    _ => debug!("epicbox frame ignored while a subscription was awaited"),
                }
            };
            if !challenge_changed || retries >= SUBSCRIBE_RETRIES {
                return Err(Stop::Failed(MailboxError::Protocol(ClientError::Relay {
                    kind: refused,
                })));
            }
            retries = retries.saturating_add(1);
            debug!("epicbox subscription to an old challenge refused, signing the new one");
        }
    }

    /// Acknowledges `msg_id` as `identity` and waits for the challenge the relay sends after
    /// it. Returns whether the relay accepted it.
    async fn made(&mut self, identity: &Identity, msg_id: &RelayMessageId) -> Result<bool, Stop> {
        let frame = ClientFrame::made(identity.address(), msg_id, identity.secret())
            .map_err(|error| Stop::Failed(MailboxError::Protocol(ClientError::Frame(error))))?;
        // The handler stored the effect, so the acknowledgement gets its full time even when
        // the drain's time is up; that saves a redelivery.
        let answer_by = deadline_after(self.client.settings.response_timeout);
        let challenge_by = self.wait_deadline();
        let overall = self.deadline;
        let stopped = |error| stopped(error, overall);
        let open = self.connection().await?;
        open.connection
            .send_before(&frame, answer_by)
            .await
            .map_err(stopped)?;
        loop {
            match open
                .connection
                .receive_before(answer_by, Awaiting::Answer)
                .await
                .map_err(stopped)?
            {
                RelayFrame::Ok => break,
                RelayFrame::Error { kind, .. } => {
                    let error = ClientError::Relay { kind };
                    warn!(msg_id = %msg_id, error = %ErrorChain(&error), "epicbox mailbox acknowledgement refused");
                    return Ok(false);
                }
                RelayFrame::Challenge { str } => open.challenge = str,
                _ => debug!("epicbox frame ignored while an acknowledgement was awaited"),
            }
        }
        debug!(msg_id = %msg_id, "epicbox mailbox message acknowledged");
        loop {
            match open
                .connection
                .receive_before(challenge_by, Awaiting::Challenge)
                .await
                .map_err(stopped)?
            {
                RelayFrame::Challenge { str } => {
                    open.challenge = str;
                    return Ok(true);
                }
                _ => debug!("epicbox frame ignored while a challenge was awaited"),
            }
        }
    }

    /// Unsubscribes and closes the connection, best effort and briefly.
    async fn leave(&mut self) {
        let Some(mut open) = self.open.take() else {
            return;
        };
        if let Some(address) = &open.subscribed {
            let unsubscribe = ClientFrame::unsubscribe(address);
            let _ = timeout(LEAVE_GRACE, open.connection.send(&unsubscribe)).await;
        }
        open.connection.close().await;
    }
}

/// A failure while waiting on a greeted connection; a timeout at the drain's end, `overall`, is
/// the drain running out of time.
fn stopped(error: ClientError, overall: Instant) -> Stop {
    if matches!(error, ClientError::Timeout { .. }) && Instant::now() >= overall {
        Stop::TimedOut
    } else {
        Stop::Failed(MailboxError::after_greeting(error))
    }
}

fn open_slate(identity: &Identity, slate: &SlateFrame) -> MailboxContent {
    match ReceivedMessage::open(
        &slate.from,
        &slate.str,
        &slate.signature,
        identity.address(),
        identity.secret(),
    ) {
        Ok(received) => MailboxContent::Opened(received),
        Err(error) => {
            debug!(error = %ErrorChain(&error), "epicbox mailbox message does not open");
            MailboxContent::Unopenable {
                sender: EpicboxAddress::parse(&slate.from, identity.address().network()).ok(),
                reason: RejectionReason::from(&error),
            }
        }
    }
}
