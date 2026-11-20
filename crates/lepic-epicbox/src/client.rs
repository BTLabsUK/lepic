// SPDX-License-Identifier: Apache-2.0
//! The Epicbox client (ADR 0004): settings, the wallet's relay identity, sending, and the entry
//! points to listening and draining.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use lepic_crypto::{PublicKey, SecretKey};
use lepic_primitives::error_chain::ErrorChain;
use lepic_slate::codec::WireSlate;
use lepic_transport::error::TransportError;
use lepic_transport::transport::{BoxFuture, Destination, Outbound, TransportId};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{Instrument, debug, info_span, warn};

use crate::address::{AddressError, EpicboxAddress};
use crate::client_inbox::{Carry, DrainConnection, Mode, Subscription};
use crate::crypto::{MessageError, NONCE_LEN, Nonce, SALT_LEN, Salt, SignedMessage};
use crate::frame::{
    CancelSignature, ClientFrame, EpicboxTxId, FrameError, RelayErrorKind, RelayFrame,
    RelayMessageId, WalletMode,
};
use crate::mux::{MuxCancelOutcome, MuxError, MuxSession};
use crate::prefilter::Prefilter;
use crate::session::{
    Answered, Connection, Connector, ProtocolVersion, RelayEndpoint, deadline_after,
};

/// The transport id of the Epicbox method.
pub const TRANSPORT_ID: TransportId = TransportId::new("epicbox");

/// What the client was waiting for when the relay went quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Awaiting {
    /// The TCP, TLS and websocket handshakes.
    Connection,
    /// The relay's challenge.
    Challenge,
    /// The relay's answer to a request.
    Answer,
    /// Any frame or pong on an open connection.
    Traffic,
}

impl fmt::Display for Awaiting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connection => "the connection",
            Self::Challenge => "a challenge",
            Self::Answer => "an answer",
            Self::Traffic => "any traffic",
        })
    }
}

/// Why a call on the Epicbox client failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The client was started outside a tokio runtime.
    #[error("no tokio runtime is running")]
    NoRuntime,
    /// The secret key does not belong to the address it was given with.
    #[error("epicbox secret key does not belong to the address")]
    IdentityMismatch,
    /// The relay could not be reached.
    #[error("could not connect to the relay")]
    Connect(#[source] io::Error),
    /// The websocket failed after it opened.
    #[error("websocket failed")]
    Websocket(#[source] Box<tokio_tungstenite::tungstenite::Error>),
    /// The relay closed the connection.
    #[error("relay closed the connection")]
    Closed,
    /// The relay sent nothing in time.
    #[error("relay sent nothing in time while the client waited for {awaiting}")]
    Timeout { awaiting: Awaiting },
    /// The relay refused a request.
    #[error("relay answered with error {kind:?}")]
    Relay { kind: RelayErrorKind },
    /// The relay refused a post on a short connection, saying why. Every other request's
    /// refusal is [`ClientError::Relay`].
    #[error("relay refused the post with {kind:?}{}", .description.as_ref().map(|text| format!(": {text}")).unwrap_or_default())]
    PostRefused {
        kind: RelayErrorKind,
        /// The frame's `description`, cut to [`crate::MAX_REFUSAL_DESCRIPTION_LEN`]
        /// characters; `None` when it was empty.
        description: Option<String>,
        /// The wait the relay asked for before the next post: named in its description on a
        /// short connection ("retry in {s} s"), by the post's own frame on mux/1.
        retry_after: Option<Duration>,
        /// The relay that refused, `host:port`, when the layer that knew it filled it in; `None`
        /// from a session that does not know its relay. Nothing but the endpoint is in it.
        mailbox: Option<String>,
    },
    /// The relay speaks a protocol older than this client supports.
    #[error("relay speaks protocol {version}, older than the supported baseline")]
    UnsupportedRelayVersion { version: ProtocolVersion },
    /// A frame could not be built or read.
    #[error("relay frame could not be built")]
    Frame(#[source] FrameError),
    /// A message could not be sealed.
    #[error("message could not be sealed")]
    Message(#[source] MessageError),
    /// The destination is not an Epicbox address.
    #[error("destination is not an epicbox address")]
    Destination(#[source] AddressError),
    /// The slate is binary; Epicbox carries only text.
    #[error("slate is binary, and epicbox carries only text")]
    BinarySlate,
    /// The operating system's randomness is unavailable.
    #[error("operating system randomness is unavailable")]
    Randomness(#[source] getrandom::Error),
    /// The client has no connection to the relay.
    #[error("client is not connected to the relay")]
    NotConnected,
    /// The subscription has ended and takes no more calls.
    #[error("subscription has ended")]
    Ended,
    /// The subscription's task panicked or was cancelled.
    #[error("subscription task failed")]
    Task(#[source] tokio::task::JoinError),
    /// The message was not handed out by this subscription.
    #[error("message is not handed out by this subscription")]
    NotHandedOut,
    /// The relay answered a post with the cancellation of its transaction (3.1.0): the other
    /// party cancelled it, and the relay did not take the message.
    #[error("transaction {txid} was cancelled")]
    TransactionCancelled { txid: EpicboxTxId },
}

impl ClientError {
    /// This error with the relay that gave it named, when it is a refusal of a post that names
    /// none yet.
    #[must_use]
    pub fn at_relay(mut self, relay: &RelayEndpoint) -> Self {
        if let Self::PostRefused { mailbox, .. } = &mut self {
            mailbox.get_or_insert_with(|| format!("{}:{}", relay.domain(), relay.port()));
        }
        self
    }

    /// The relay (`host:port`) that refused a post, when the error names it.
    #[must_use]
    pub fn mailbox(&self) -> Option<&str> {
        match self {
            Self::PostRefused { mailbox, .. } => mailbox.as_deref(),
            _ => None,
        }
    }

    /// The wait the relay asked for before the next post, when this is a refusal that named
    /// one.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::PostRefused { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// What a relay writes before the wait, in whole seconds, in the description of a refusal on a
/// short connection: "Rate limit exceeded; retry in 45 s."
pub const RETRY_IN: &str = "retry in ";

/// The wait a refusal's `description` names after [`RETRY_IN`], in whole seconds; `None` when it
/// names none or its digits do not read.
#[must_use]
pub fn retry_in(description: &str) -> Option<Duration> {
    let (_, after) = description.split_once(RETRY_IN)?;
    let digits = after
        .find(|c: char| !c.is_ascii_digit())
        .map_or(after, |end| &after[..end]);
    digits.parse().ok().map(Duration::from_secs)
}

impl From<ClientError> for TransportError {
    fn from(error: ClientError) -> Self {
        Self::Backend {
            transport: TRANSPORT_ID,
            source: Box::new(error),
        }
    }
}

/// Capped exponential backoff between reconnect attempts, with jitter so that many wallets
/// dropped at once do not return at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The ceiling of the first delay.
    pub initial: Duration,
    /// The largest ceiling.
    pub max: Duration,
}

impl Backoff {
    /// The delay before reconnect attempt `attempt`, counted from 1, before jitter.
    pub fn ceiling(&self, attempt: u32) -> Duration {
        let doublings = attempt.saturating_sub(1);
        let factor = 1_u32.checked_shl(doublings).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }

    /// A delay between half the ceiling and the ceiling, placed by `random`.
    pub fn delay(&self, attempt: u32, random: u32) -> Duration {
        let ceiling = self.ceiling(attempt);
        let half = ceiling.checked_div(2).unwrap_or_default();
        let span =
            u128::from(u64::try_from(ceiling.saturating_sub(half).as_nanos()).unwrap_or(u64::MAX));
        let jitter = span
            .checked_mul(u128::from(random))
            .and_then(|scaled| scaled.checked_div(u128::from(u32::MAX)))
            .and_then(|nanos| u64::try_from(nanos).ok())
            .unwrap_or_default();
        half.saturating_add(Duration::from_nanos(jitter))
    }
}

/// When a listener leaves a socket that is still open. Both rules are off by default and never
/// apply to a drain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListenOptions {
    /// Leave after this many rounds that began with a message held, counted per socket and not
    /// reset by an acknowledgement. The held message is taken up again on the new socket.
    pub held_rounds: Option<u32>,
    /// Leave when the relay has sent no challenge for this many of its challenge intervals. The
    /// interval is the gap the listener saw between two periodic challenges, at least 30
    /// seconds, and 60 seconds until it has seen two. The greeting is not a periodic challenge.
    /// The new socket collects what waits.
    pub challenge_rounds: Option<u32>,
    /// Ask a 3.1.0 relay for transaction cancellations: the subscription subscribes with
    /// version 3.1.0, reports each cancellation through [`Subscription::next_cancelled`] and
    /// sends the acknowledgement the relay waits for only when the consumer calls
    /// [`Subscription::ack_cancelled`]. Off by default, because a consumer that never
    /// acknowledges holds back every other message of the connection. Against a relay older than
    /// 3.1.0 it does nothing.
    pub cancel: bool,
}

/// How the client talks to its relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
    /// The relay.
    pub endpoint: RelayEndpoint,
    /// Sent to the relay in `ClientDetails`.
    pub wallet_version: String,
    /// Limit for the TCP, TLS and websocket handshakes together.
    pub connect_timeout: Duration,
    /// Limit for each relay answer.
    pub response_timeout: Duration,
    /// Interval of websocket pings. It must stay below the relay proxy's idle timeout. A
    /// connection that hears nothing for two intervals is treated as lost.
    pub ping_interval: Duration,
    /// The delay between reconnect attempts.
    pub backoff: Backoff,
    /// The bound of a whole mailbox drain. Mailboxes not reached by then wait for the next one.
    pub drain_timeout: Duration,
}

/// The caller's timeouts and reconnect backoff for a relay client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTimings {
    /// See [`ClientSettings::connect_timeout`].
    pub connect_timeout: Duration,
    /// See [`ClientSettings::response_timeout`].
    pub response_timeout: Duration,
    /// See [`ClientSettings::ping_interval`].
    pub ping_interval: Duration,
    /// See [`ClientSettings::backoff`].
    pub backoff: Backoff,
    /// See [`ClientSettings::drain_timeout`].
    pub drain_timeout: Duration,
}

/// The version the relay is told in `ClientDetails`: what `epic-wallet` `v4.1.0` sends, its own
/// package version. The relay stores it and reads only the wallet mode, so a version of LEPIC's
/// own would only tell the relay, and anyone watching it, which keys run LEPIC.
pub const RELAY_WALLET_VERSION: &str = "4.1.0";

impl ClientSettings {
    /// Settings for `endpoint` with the caller's `timings`, telling the relay
    /// [`RELAY_WALLET_VERSION`].
    pub fn new(endpoint: RelayEndpoint, timings: ClientTimings) -> Self {
        Self {
            endpoint,
            wallet_version: RELAY_WALLET_VERSION.to_owned(),
            connect_timeout: timings.connect_timeout,
            response_timeout: timings.response_timeout,
            ping_interval: timings.ping_interval,
            backoff: timings.backoff,
            drain_timeout: timings.drain_timeout,
        }
    }
}

/// The wallet's Epicbox address and its secret key. The key never leaves the client.
#[derive(Clone)]
pub struct Identity {
    address: EpicboxAddress,
    secret: SecretKey,
}

impl Identity {
    /// `address` must carry the public key of `secret`; its domain and port are written as the
    /// sender of every message.
    pub fn new(secret: SecretKey, address: EpicboxAddress) -> Result<Self, ClientError> {
        let public =
            PublicKey::from_secret_key(&secret).map_err(|_| ClientError::IdentityMismatch)?;
        if public != *address.public_key() {
            return Err(ClientError::IdentityMismatch);
        }
        Ok(Self { address, secret })
    }

    /// The identity's address.
    pub fn address(&self) -> &EpicboxAddress {
        &self.address
    }

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// What every connection of a client needs.
pub(crate) struct ClientContext {
    pub(crate) settings: ClientSettings,
    pub(crate) identity: Identity,
    pub(crate) connector: Arc<dyn Connector>,
    pub(crate) prefilter: Option<Arc<dyn Prefilter>>,
}

/// The Epicbox client of one identity. Sending opens a short connection of its own;
/// [`Self::listen`] and [`Self::drain`] start a subscription on a connection of its own.
///
/// The relay serves a connection as the address it last subscribed with, so a wallet with
/// several addresses runs one client per identity, each on its own connection.
#[derive(Clone)]
pub struct EpicboxClient {
    context: Arc<ClientContext>,
}

impl EpicboxClient {
    /// A client of `identity` on the relay of `settings`, which connects through `connector`.
    pub fn new(
        settings: ClientSettings,
        identity: Identity,
        connector: Arc<dyn Connector>,
    ) -> Self {
        Self {
            context: Arc::new(ClientContext {
                settings,
                identity,
                connector,
                prefilter: None,
            }),
        }
    }

    /// The same client, whose subscriptions started from now on ask `prefilter` about each
    /// received message before opening it. A dropped message is acknowledged and is neither
    /// handed out nor reported as a rejection.
    pub fn with_prefilter(self, prefilter: Arc<dyn Prefilter>) -> Self {
        let context = &self.context;
        Self {
            context: Arc::new(ClientContext {
                settings: context.settings.clone(),
                identity: context.identity.clone(),
                connector: Arc::clone(&context.connector),
                prefilter: Some(prefilter),
            }),
        }
    }

    /// The address of the client's identity.
    pub fn address(&self) -> &EpicboxAddress {
        self.context.identity.address()
    }

    /// The relay and timings this client uses.
    pub fn settings(&self) -> &ClientSettings {
        &self.context.settings
    }

    /// Holds a connection, keeps it alive and reconnects after failures until stopped.
    pub fn listen(&self) -> Result<Subscription, ClientError> {
        self.listen_with(ListenOptions::default())
    }

    /// As [`Self::listen`], and the listener moves to a fresh socket after `held_rounds` rounds
    /// that began with a message held, counted per socket and not reset by an acknowledgement.
    /// The held message stays held and is taken up again on the new socket. `None` keeps the
    /// socket.
    pub fn listen_with_held_rounds(
        &self,
        held_rounds: Option<u32>,
    ) -> Result<Subscription, ClientError> {
        self.listen_with(ListenOptions {
            held_rounds,
            ..ListenOptions::default()
        })
    }

    /// As [`Self::listen`], with the leave-the-socket rules of `options`.
    pub fn listen_with(&self, options: ListenOptions) -> Result<Subscription, ClientError> {
        Subscription::start(Arc::clone(&self.context), Mode::Listen, options, None)
    }

    /// Connects once, hands out every pending message, and disconnects when the relay has none
    /// left and every handed-out message was acknowledged. A connection failure ends it.
    pub fn drain(&self) -> Result<Subscription, ClientError> {
        self.drain_with(ListenOptions::default())
    }

    /// As [`Self::drain`], with `options`; only [`ListenOptions::cancel`] applies to a drain.
    pub fn drain_with(&self, options: ListenOptions) -> Result<Subscription, ClientError> {
        Subscription::start(
            Arc::clone(&self.context),
            Mode::Drain,
            ListenOptions {
                held_rounds: None,
                challenge_rounds: None,
                cancel: options.cancel,
            },
            None,
        )
    }

    /// As [`Self::drain`], on `connection` when one is given, which an earlier drain handed on
    /// (possibly for another address, as this client's identity subscribes on it). When this
    /// drain ends quiet (nothing outstanding, nothing held, every message acknowledged), its
    /// connection stays open for [`Subscription::take_connection`]; otherwise it is closed. A
    /// connection the relay already closed fails the drain as any connection failure does. Of
    /// `options` only [`ListenOptions::cancel`] applies, as in [`Self::drain_with`].
    pub fn drain_on_with(
        &self,
        connection: Option<DrainConnection>,
        options: ListenOptions,
    ) -> Result<Subscription, ClientError> {
        Subscription::start(
            Arc::clone(&self.context),
            Mode::Drain,
            ListenOptions {
                held_rounds: None,
                challenge_rounds: None,
                cancel: options.cancel,
            },
            Some(Carry {
                incoming: connection,
            }),
        )
    }

    /// Encrypts `plaintext` for `to`, signs exactly the `str` it sends, posts it through this
    /// client's relay and waits for the relay's answer. Resending is safe because receivers
    /// deduplicate.
    pub async fn post(&self, to: &EpicboxAddress, plaintext: &str) -> Result<(), ClientError> {
        let context = &self.context;
        let span = info_span!(
            "epicbox_post",
            transport = TRANSPORT_ID.as_str(),
            relay = %context.settings.endpoint.domain(),
        );
        async move {
            let message = seal(plaintext, to, context.identity.secret())?;
            let frame = ClientFrame::post_slate(context.identity.address(), to, &message);
            post_frame(context, &frame).await
        }
        .instrument(span)
        .await
    }

    /// As [`Self::post`], and a relay of 3.1.0 or later gets `txid` with the signature of this
    /// address over it, so that either party can cancel the transaction later with
    /// [`Self::cancel`]. A relay that does not have cancel gets the 3.0.0 frame, with no id:
    /// [`PostReceipt::txid_sent`] says which. Persist `txid` before posting; resending with the
    /// same `txid` is safe.
    ///
    /// A relay that holds a cancellation of `txid` refuses the message with
    /// [`ClientError::TransactionCancelled`].
    pub async fn post_tx(
        &self,
        to: &EpicboxAddress,
        plaintext: &str,
        txid: &EpicboxTxId,
    ) -> Result<PostReceipt, ClientError> {
        let context = &self.context;
        let span = info_span!(
            "epicbox_post",
            transport = TRANSPORT_ID.as_str(),
            relay = %context.settings.endpoint.domain(),
        );
        async move {
            let message = seal(plaintext, to, context.identity.secret())?;
            let mut txid_sent = false;
            let answered = exchange_reporting(context, |relay| {
                if ProtocolVersion::relay_supports_cancel(relay) {
                    txid_sent = true;
                    ClientFrame::post_slate_with_txid(
                        context.identity.address(),
                        to,
                        &message,
                        txid,
                        context.identity.secret(),
                    )
                } else {
                    Ok(ClientFrame::post_slate(
                        context.identity.address(),
                        to,
                        &message,
                    ))
                }
            })
            .await
            .map_err(|failed| failed.error)?;
            match answered {
                Answered::Ok {
                    epicboxtxid,
                    epicboxmsgid,
                } => Ok(PostReceipt {
                    txid_sent,
                    epicboxtxid,
                    epicboxmsgid,
                }),
                Answered::Cancelled { epicboxtxid } => {
                    Err(ClientError::TransactionCancelled { txid: epicboxtxid })
                }
            }
        }
        .instrument(span)
        .await
    }

    /// Cancels the transaction `txid` on the relay, on a short connection of its own: greets,
    /// subscribes as this address in send-only mode, sends `CancelTx` with the signature over
    /// the id, and waits for the relay's answer. Frames of other kinds are ignored and no `Made`
    /// is ever sent.
    ///
    /// A relay older than 3.1.0 gets nothing beyond the greeting, and the outcome is
    /// [`CancelOutcome::Unsupported`]. The relay's `Ok` does not say why it took no action (the
    /// transaction is unknown, or this address is not a participant): that is
    /// [`CancelOutcome::NotFoundOrNotParticipant`], and a cancellation is not confirmed until
    /// [`CancelOutcome::Cancelled`].
    ///
    /// The `Subscribe` of this call is the first on its connection, so it acknowledges nothing.
    /// A cancellation the other party made earlier may be delivered on it; it is returned in
    /// [`CancelReport::other_cancelled`] and stays unacknowledged on the relay, which delivers
    /// it again to a listener.
    pub async fn cancel(&self, txid: &EpicboxTxId) -> Result<CancelReport, ClientError> {
        let context = &self.context;
        let span = info_span!(
            "epicbox_cancel",
            transport = TRANSPORT_ID.as_str(),
            relay = %context.settings.endpoint.domain(),
        );
        async move {
            let settings = &context.settings;
            let mut connection = Connection::open(
                context.connector.as_ref(),
                &settings.endpoint,
                settings.connect_timeout,
            )
            .await?;
            let result = cancel_on(&mut connection, context, txid).await;
            connection.close().await;
            match &result {
                Ok(report) => debug!(outcome = ?report.outcome, "epicbox cancel finished"),
                Err(error) => warn!(error = %ErrorChain(error), "epicbox cancel failed"),
            }
            result
        }
        .instrument(span)
        .await
    }

    /// Cancels transaction `txid` as this client's identity over `session`, a mux/1 session on
    /// the same relay (`txcancel/1`), as [`MuxSession::cancel`] does.
    /// [`MuxCancelOutcome::Unsupported`] when the session's socket did not negotiate
    /// `txcancel/1`: nothing was sent, and [`EpicboxClient::cancel`] is the way left.
    pub async fn cancel_on_session(
        &self,
        session: &MuxSession,
        txid: &EpicboxTxId,
    ) -> Result<MuxCancelOutcome, MuxError> {
        session.cancel(&self.context.identity, txid).await
    }
}

/// What the relay said to a [`EpicboxClient::post_tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PostReceipt {
    /// The post carried the transaction id and its signature, which only a relay of 3.1.0 or
    /// later gets. When false, the transaction cannot be cancelled through the relay.
    pub txid_sent: bool,
    /// The transaction id the relay's `Ok` named, when it did.
    pub epicboxtxid: Option<EpicboxTxId>,
    /// The relay's id of the stored message, when its `Ok` named one.
    pub epicboxmsgid: Option<RelayMessageId>,
}

/// How a [`EpicboxClient::cancel`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelOutcome {
    /// The relay confirmed the cancellation with `TransactionCancelled`.
    Cancelled,
    /// The relay answered `Ok` and did nothing: the transaction is unknown to it, or this
    /// address is not one of its participants. The relay does not say which.
    NotFoundOrNotParticipant,
    /// The relay is older than 3.1.0 (`relay` is the version it reported, if any) and has no
    /// cancel.
    Unsupported { relay: Option<ProtocolVersion> },
}

/// The result of [`EpicboxClient::cancel`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CancelReport {
    /// How the cancel ended.
    pub outcome: CancelOutcome,
    /// Cancellations of other transactions that reached the short connection meanwhile, in the
    /// order they arrived.
    pub other_cancelled: Vec<EpicboxTxId>,
}

/// The cancel protocol on an open connection.
async fn cancel_on(
    connection: &mut Connection,
    context: &ClientContext,
    txid: &EpicboxTxId,
) -> Result<CancelReport, ClientError> {
    let settings = &context.settings;
    let identity = &context.identity;
    let greeting = connection
        .greet_offering(WalletMode::Send, settings, true)
        .await?;
    let mut other_cancelled = Vec::new();
    let report = |outcome, other_cancelled| CancelReport {
        outcome,
        other_cancelled,
    };
    if !ProtocolVersion::relay_supports_cancel(greeting.version) {
        return Ok(report(
            CancelOutcome::Unsupported {
                relay: greeting.version,
            },
            other_cancelled,
        ));
    }

    let subscribe = ClientFrame::subscribe_negotiated(
        identity.address(),
        &greeting.challenge,
        identity.secret(),
        greeting.version,
    )
    .map_err(ClientError::Frame)?;
    let deadline = deadline_after(settings.response_timeout);
    connection.send_before(&subscribe, deadline).await?;
    loop {
        match connection
            .receive_before(deadline, Awaiting::Answer)
            .await?
        {
            RelayFrame::Ok { .. } | RelayFrame::Slate(_) => break,
            RelayFrame::TransactionCancelled { epicboxtxid } => {
                if epicboxtxid == *txid {
                    return Ok(report(CancelOutcome::Cancelled, other_cancelled));
                }
                other_cancelled.push(epicboxtxid);
                break;
            }
            RelayFrame::Error { kind, .. } => return Err(ClientError::Relay { kind }),
            _ => debug!("epicbox frame ignored while the cancel subscription was awaited"),
        }
    }

    let cancel = ClientFrame::cancel_tx_with(
        identity.address(),
        txid,
        identity.secret(),
        CancelSignature::negotiated(greeting.cancel_form),
    )
    .map_err(ClientError::Frame)?;
    let deadline = deadline_after(settings.response_timeout);
    connection.send_before(&cancel, deadline).await?;
    loop {
        match connection
            .receive_before(deadline, Awaiting::Answer)
            .await?
        {
            RelayFrame::TransactionCancelled { epicboxtxid } => {
                if epicboxtxid == *txid {
                    return Ok(report(CancelOutcome::Cancelled, other_cancelled));
                }
                if !other_cancelled.contains(&epicboxtxid) {
                    other_cancelled.push(epicboxtxid);
                }
            }
            RelayFrame::Ok { .. } => {
                return Ok(report(
                    CancelOutcome::NotFoundOrNotParticipant,
                    other_cancelled,
                ));
            }
            RelayFrame::Error { kind, .. } => return Err(ClientError::Relay { kind }),
            _ => debug!("epicbox frame ignored while the cancel answer was awaited"),
        }
    }
}

/// Posts `frame`, a `PostSlate`, on a short connection of its own and waits for the relay's
/// answer.
pub(crate) async fn post_frame(
    context: &ClientContext,
    frame: &ClientFrame,
) -> Result<(), ClientError> {
    post_frame_reporting(context, frame)
        .await
        .map_err(|failed| failed.error)
}

/// A post that failed, and whether the frame was written before it did.
pub(crate) struct PostFailed {
    pub(crate) error: ClientError,
    /// The frame was written, or may have been, before the failure; unless the relay
    /// answered with a refusal, it may hold the message.
    pub(crate) sent: bool,
}

/// [`post_frame`], saying whether a failed post wrote its frame. A relay that answers with the
/// cancellation of the transaction fails it with [`ClientError::TransactionCancelled`].
pub(crate) async fn post_frame_reporting(
    context: &ClientContext,
    frame: &ClientFrame,
) -> Result<(), PostFailed> {
    match exchange_reporting(context, |_| Ok(frame.clone())).await? {
        Answered::Ok { .. } => Ok(()),
        Answered::Cancelled { epicboxtxid } => Err(PostFailed {
            error: ClientError::TransactionCancelled { txid: epicboxtxid },
            sent: true,
        }),
    }
}

/// Opens a short connection, greets in send mode, sends the frame `build` makes for the version
/// the relay reported, and returns what the relay answered. `PostFailed::sent` says whether the
/// frame was written before a failure.
pub(crate) async fn exchange_reporting(
    context: &ClientContext,
    build: impl FnOnce(Option<ProtocolVersion>) -> Result<ClientFrame, FrameError>,
) -> Result<Answered, PostFailed> {
    let started = Instant::now();
    let settings = &context.settings;
    let mut connection = Connection::open(
        context.connector.as_ref(),
        &settings.endpoint,
        settings.connect_timeout,
    )
    .await
    .map_err(|error| PostFailed { error, sent: false })?;
    let result = async {
        let unsent = |error| PostFailed { error, sent: false };
        let greeting = connection
            .greet(WalletMode::Send, settings)
            .await
            .map_err(unsent)?;
        let frame = build(greeting.version).map_err(|error| unsent(ClientError::Frame(error)))?;
        let deadline = deadline_after(settings.response_timeout);
        connection
            .send_before(&frame, deadline)
            .await
            .map_err(|error| PostFailed { error, sent: true })?;
        connection
            .answer_detailed(deadline)
            .await
            .map_err(|error| PostFailed { error, sent: true })
    }
    .await;
    connection.close().await;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => debug!(elapsed_ms, "epicbox message posted"),
        Err(failed) => warn!(
            elapsed_ms,
            sent = failed.sent,
            error = %ErrorChain(&failed.error),
            "epicbox post failed"
        ),
    }
    result
}

impl fmt::Debug for EpicboxClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpicboxClient")
            .field("identity", &self.context.identity)
            .field("settings", &self.context.settings)
            .field("prefiltered", &self.context.prefilter.is_some())
            .finish_non_exhaustive()
    }
}

pub(crate) fn seal(
    plaintext: &str,
    to: &EpicboxAddress,
    sender: &SecretKey,
) -> Result<SignedMessage, ClientError> {
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(ClientError::Randomness)?;
    getrandom::fill(&mut nonce).map_err(ClientError::Randomness)?;
    SignedMessage::seal(plaintext, to, sender, Salt::from(salt), Nonce::from(nonce))
        .map_err(ClientError::Message)
}

impl Outbound for EpicboxClient {
    /// `to` is an Epicbox address on this wallet's network; the wire slate must be text.
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let network = self.address().network();
            let to =
                EpicboxAddress::parse(to.as_str(), network).map_err(ClientError::Destination)?;
            let plaintext = wire.as_text().ok_or(ClientError::BinarySlate)?;
            Ok(self.post(&to, plaintext).await?)
        })
    }
}

/// Cancellation shared by a subscription handle and its task, checked at every await.
#[derive(Clone)]
pub(crate) struct CancelToken(Arc<watch::Sender<bool>>);

impl CancelToken {
    pub(crate) fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    pub(crate) fn cancel(&self) {
        self.0.send_replace(true);
    }

    pub(crate) async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        // The sender lives in `self`, so waiting cannot fail.
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_is_told_the_version_epic_wallet_sends() {
        let relay = crate::address::Domain::parse("relay.example.org").unwrap();
        let endpoint = RelayEndpoint::new(relay, None, crate::session::Security::Tls);
        let settings = crate::testing::client_settings(endpoint);
        assert_eq!(settings.wallet_version, "4.1.0");
    }

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let backoff = Backoff {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(500),
        };
        let ceilings: Vec<_> = (1..=5).map(|attempt| backoff.ceiling(attempt)).collect();
        assert_eq!(
            ceilings,
            [100, 200, 400, 500, 500].map(Duration::from_millis)
        );
        assert_eq!(backoff.ceiling(u32::MAX), Duration::from_millis(500));
        assert_eq!(backoff.ceiling(0), Duration::from_millis(100));
    }

    #[test]
    fn jitter_stays_between_half_the_ceiling_and_the_ceiling() {
        let backoff = Backoff {
            initial: Duration::from_millis(400),
            max: Duration::from_secs(60),
        };
        assert_eq!(backoff.delay(1, 0), Duration::from_millis(200));
        assert_eq!(backoff.delay(1, u32::MAX), Duration::from_millis(400));
        let middle = backoff.delay(1, u32::MAX / 2);
        assert!(middle > Duration::from_millis(299) && middle < Duration::from_millis(301));
    }

    #[test]
    fn identity_rejects_an_address_of_another_key() {
        let secret = SecretKey::from_array([1; 32]).unwrap();
        let other = PublicKey::from_secret_key(&SecretKey::from_array([2; 32]).unwrap()).unwrap();
        let address = EpicboxAddress::new(
            other,
            crate::address::Network::Mainnet,
            crate::address::Domain::parse("relay.example.org").unwrap(),
            None,
        );
        assert!(matches!(
            Identity::new(secret, address),
            Err(ClientError::IdentityMismatch)
        ));
    }

    #[test]
    fn identity_debug_leaves_out_the_key() {
        let secret = SecretKey::from_array([1; 32]).unwrap();
        let address = EpicboxAddress::new(
            PublicKey::from_secret_key(&secret).unwrap(),
            crate::address::Network::Mainnet,
            crate::address::Domain::parse("relay.example.org").unwrap(),
            None,
        );
        let identity = Identity::new(secret, address).unwrap();
        let text = format!("{identity:?}");
        assert!(!text.contains("0101"));
        assert!(text.contains("address"));
    }

    #[test]
    fn a_refusal_reads_the_wait_its_description_names() {
        assert_eq!(
            retry_in("Rate limit exceeded; retry in 45 s."),
            Some(Duration::from_secs(45))
        );
        assert_eq!(retry_in("retry in 7"), Some(Duration::from_secs(7)));
        for none in ["Rate limit exceeded.", "retry in s.", "retry in -3 s", ""] {
            assert_eq!(retry_in(none), None, "{none:?}");
        }
    }

    #[test]
    fn only_a_refused_post_gives_a_wait() {
        let refused = ClientError::PostRefused {
            kind: RelayErrorKind::InvalidRequest,
            description: None,
            retry_after: Some(Duration::from_secs(3)),
            mailbox: None,
        };
        assert_eq!(refused.retry_after(), Some(Duration::from_secs(3)));
        assert_eq!(
            ClientError::Relay {
                kind: RelayErrorKind::InvalidRequest
            }
            .retry_after(),
            None
        );
    }
}
