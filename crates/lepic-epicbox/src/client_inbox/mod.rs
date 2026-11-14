// SPDX-License-Identifier: Apache-2.0
// Portions Copyright 2019 The Grin Developers
// Portions Copyright 2026 The Epic Cash Developers
// Ported from EpicCash/epic-wallet impls/src/adapters/epicbox.rs (Apache-2.0); see NOTICE and
// upstream.toml.

//! A relay subscription in `listen` or `drain` mode, and its [`Inbound`] side.
//!
//! One task owns the connection. It answers every challenge with a fresh `Subscribe`, sends at
//! most one request at a time because the relay's `Ok` does not say what it answers, sends
//! websocket pings, and reconnects with backoff in `listen` mode. Received messages are checked,
//! decrypted and queued; the [`Subscription`] hands them out and turns acknowledgements into
//! `Made`.

mod inbox;
mod manager;
mod session;

use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lepic_transport::error::TransportError;
use lepic_transport::transport::{AckToken, BoxFuture, Envelope, Inbound};
use tokio::runtime::Handle;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::instrument::WithSubscriber;
use tracing::{Instrument, info_span};

use crate::client::{
    Awaiting, CancelToken, ClientContext, ClientError, ListenOptions, TRANSPORT_ID, post_frame,
};
use crate::crypto::MessageError;
use crate::frame::{ClientFrame, RelayMessageId, WalletMode};
use crate::session::{Connection, Greeting, ProtocolVersion};

use self::inbox::{Delivery, InboxState, Shared};
use self::manager::{Command, Manager};

/// The longest a relay keeps a stored message: the public relay expires them after seven days.
/// A relay message id received longer ago than this cannot be delivered again.
pub const RELAY_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// What a subscription is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Stays connected and takes live delivery for the address.
    Listen,
    /// Reads what the relay stored for the address and ends.
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
    /// Opening connection attempt `attempt`.
    Connecting { attempt: u32 },
    /// Subscribed and receiving.
    Subscribed,
    /// Waiting `delay` before reconnect attempt `attempt`.
    Waiting { attempt: u32, delay: Duration },
    /// Stopped by the host.
    Stopped,
    /// A drain read everything the relay held.
    Drained,
    /// Ended with an error.
    Failed,
}

impl ConnectionState {
    /// Whether the subscription has ended and no longer changes state.
    pub fn has_ended(self) -> bool {
        matches!(self, Self::Stopped | Self::Drained | Self::Failed)
    }
}

/// Why a received message could not be opened. Each is permanent: the same bytes never open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RejectionReason {
    /// `from` is not an address on this wallet's network.
    InvalidSender,
    /// The signature over `str` does not verify with the sender's key.
    InvalidSignature,
    /// The message is encrypted for another key.
    NotAddressedToUs,
    /// The message does not decrypt, or its plaintext is not text.
    Undecryptable,
    /// `str` is not the expected message JSON.
    Malformed,
}

impl From<&MessageError> for RejectionReason {
    fn from(error: &MessageError) -> Self {
        match error {
            MessageError::Sender(_) => Self::InvalidSender,
            MessageError::Signature(_) => Self::InvalidSignature,
            MessageError::NotAddressedToUs => Self::NotAddressedToUs,
            MessageError::Key(_) | MessageError::Decryption | MessageError::NotUtf8 => {
                Self::Undecryptable
            }
            _ => Self::Malformed,
        }
    }
}

/// What a subscription did with the messages the relay sent it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InboxCounters {
    /// Messages received, redeliveries included.
    pub seen: u64,
    /// Messages the client's [`crate::Prefilter`] dropped without opening them.
    pub dropped: u64,
    /// Messages whose signature was checked and that were then decrypted or rejected.
    pub opened: u64,
}

/// A received message that could not be opened. It stays unacknowledged, and the relay delivers
/// nothing else to the address, until the consumer records it and passes its token to
/// [`Inbound::acknowledge`] (ADR 0004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    ack_token: AckToken,
    delivery: Delivery,
    sender: Option<String>,
    reason: RejectionReason,
}

impl Rejection {
    /// The token to pass to [`Inbound::acknowledge`] once the rejection is recorded.
    pub fn ack_token(&self) -> &AckToken {
        &self.ack_token
    }

    /// The relay message id, when the relay sent one.
    pub fn msg_id(&self) -> Option<&RelayMessageId> {
        self.delivery.relay_id()
    }

    /// The sender's address text, when `from` parsed. A sender that did not sign the message is
    /// a claim, not a fact.
    pub fn sender(&self) -> Option<&str> {
        self.sender.as_deref()
    }

    /// Why the message did not open.
    pub fn reason(&self) -> RejectionReason {
        self.reason
    }
}

/// A subscription to the wallet's relay address. Dropping it stops the task.
///
/// Consume it by calling [`Inbound::next_envelope`] and [`Self::next_rejection`] until both are
/// empty, acknowledging each item once its effect or its rejection is recorded. The relay sends
/// one message at a time, so an unacknowledged item holds back the rest.
///
/// A drain ends with an error when its connection fails, including when the relay sends a frame
/// the websocket layer refuses (too long, or text that is not UTF-8). Unacknowledged messages
/// stay on the relay, so treat a failed drain as "retry later". A listener reconnects instead.
pub struct Subscription {
    mode: Mode,
    context: Arc<ClientContext>,
    shared: Arc<Shared>,
    cancel: CancelToken,
    task: tokio::sync::Mutex<Option<JoinHandle<Result<(), ClientError>>>>,
    ack_timeout: Duration,
}

impl Subscription {
    pub(crate) fn start(
        context: Arc<ClientContext>,
        mode: Mode,
        options: ListenOptions,
        carry: Option<Carry>,
    ) -> Result<Self, ClientError> {
        let runtime = Handle::try_current().map_err(|_| ClientError::NoRuntime)?;
        let (commands, receiver) = mpsc::unbounded_channel();
        let (status, _) = watch::channel(ConnectionState::Connecting { attempt: 1 });
        let shared = Arc::new(Shared {
            inbox: Mutex::new(InboxState::new()),
            changed: Notify::new(),
            commands,
            status,
            disconnect: Mutex::new(None),
            carried: Mutex::new(None),
        });
        let cancel = CancelToken::new();
        let ack_timeout = context.settings.response_timeout.saturating_mul(2);
        let relay = context.settings.endpoint.domain().to_string();
        let span = match mode {
            Mode::Listen => info_span!("epicbox_listen", transport = TRANSPORT_ID.as_str(), relay),
            Mode::Drain => info_span!("epicbox_drain", transport = TRANSPORT_ID.as_str(), relay),
        };
        let manager = Manager {
            context: Arc::clone(&context),
            shared: Arc::clone(&shared),
            commands: receiver,
            mode,
            held_rounds: options.held_rounds,
            challenge_rounds: options.challenge_rounds,
            carry,
            cancel: cancel.clone(),
        };
        // The host's subscriber is scoped to the calling thread, so the task carries it along.
        let task = runtime.spawn(manager.run().instrument(span).with_current_subscriber());
        Ok(Self {
            mode,
            context,
            shared,
            cancel,
            task: tokio::sync::Mutex::new(Some(task)),
            ack_timeout,
        })
    }

    /// Whether this subscription listens or drains.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Why the connection last dropped and the wait before the next attempt; `None` until it
    /// has dropped.
    pub fn last_disconnect(&self) -> Option<Disconnect> {
        self.shared
            .disconnect
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A receiver that sees each change of [`ConnectionState`].
    pub fn state(&self) -> watch::Receiver<ConnectionState> {
        self.shared.status.subscribe()
    }

    /// The connection a drain started with [`crate::EpicboxClient::drain_on`] handed back, once
    /// it has ended quiet. `None` for any other end: a drain that kept a message, was stopped or
    /// failed closes its connection.
    pub fn take_connection(&self) -> Option<DrainConnection> {
        self.shared
            .carried
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// The version the relay reported in the current or last session; `None` when it did not
    /// report one, in which case only the baseline protocol is used.
    pub fn relay_version(&self) -> Option<ProtocolVersion> {
        self.shared.lock().relay_version
    }

    /// What the subscription did with the messages it received so far, over all its sessions.
    pub fn counters(&self) -> InboxCounters {
        self.shared.lock().counters
    }

    /// Resolves once an envelope or a rejection is ready to be handed out, or the subscription
    /// has ended. In `listen` mode, take everything available, then wait here.
    pub async fn delivery_available(&self) {
        loop {
            let mut notified = pin!(self.shared.changed.notified());
            notified.as_mut().enable();
            {
                let inbox = self.shared.lock();
                if !inbox.ready.is_empty() || !inbox.rejected.is_empty() || inbox.state.has_ended()
                {
                    return;
                }
            }
            notified.await;
        }
    }

    /// The next message that could not be opened, if one is waiting. Acknowledge its token after
    /// the rejection is recorded.
    pub fn next_rejection(&self) -> Option<Rejection> {
        let mut inbox = self.shared.lock();
        let rejection = inbox.rejected.pop_front()?;
        inbox
            .handed_out
            .insert(rejection.ack_token.clone(), rejection.delivery.clone());
        Some(rejection)
    }

    /// The relay message id of a handed-out envelope or rejection that is not yet
    /// acknowledged, or `None` when the relay sent the message without one or `token` is not
    /// handed out.
    pub fn relay_message_id(&self, token: &AckToken) -> Option<RelayMessageId> {
        self.shared
            .lock()
            .handed_out
            .get(token)
            .and_then(Delivery::relay_id)
            .cloned()
    }

    /// Posts the handed-out envelope of `token` back to this subscription's address, exactly as
    /// its sender signed it: the same `from`, `str` and `signature`, which is all the relay
    /// checks. The relay queues the copy behind every message already waiting, and another
    /// install listening on the same address can collect it. Acknowledge the original only
    /// after this succeeds, or the message is lost if the post fails. Posting goes over a
    /// short connection of its own, as sending does.
    ///
    /// Fails with [`ClientError::NotHandedOut`] when `token` is not a handed-out envelope, and
    /// as [`crate::EpicboxClient::post`] does when the relay does not take the copy.
    pub async fn requeue(&self, token: &AckToken) -> Result<(), ClientError> {
        let signed = self
            .shared
            .lock()
            .signed
            .get(token)
            .cloned()
            .ok_or(ClientError::NotHandedOut)?;
        let frame = ClientFrame::PostSlate {
            from: signed.from,
            to: self.context.identity.address().to_string(),
            str: signed.str,
            signature: signed.signature,
        };
        let span = info_span!(
            "epicbox_requeue",
            transport = TRANSPORT_ID.as_str(),
            relay = %self.context.settings.endpoint.domain(),
        );
        post_frame(&self.context, &frame).instrument(span).await
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
                Some(Delivery::Local(_)) => {
                    inbox.handed_out.remove(token);
                    inbox.signed.remove(token);
                    return Ok(());
                }
                Some(Delivery::Relay(msg_id)) => msg_id.clone(),
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

    /// Sends `Made` for the envelope or rejection and waits for the relay to accept it.
    fn acknowledge<'a>(&'a self, token: &'a AckToken) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(self.acknowledge_message(token))
    }
}

/// A greeted relay connection a finished drain hands on, so the next drain, possibly for another
/// address, uses it instead of opening one.
///
/// It is only ever handed on from a drain that ended quiet: nothing outstanding, nothing held,
/// every message handed out acknowledged. The relay holds back every address on a connection
/// while a message it sent there is not acknowledged, so a connection with a kept message is
/// closed instead (see [`crate::mailbox`]).
pub struct DrainConnection {
    connection: Connection,
    greeting: Greeting,
}

impl DrainConnection {
    /// Closes the connection.
    pub async fn close(self) {
        self.connection.close().await;
    }
}

impl std::fmt::Debug for DrainConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrainConnection").finish_non_exhaustive()
    }
}

/// A drain that may run on a connection handed in and hands its connection back when it ends
/// quiet.
pub(crate) struct Carry {
    pub(crate) incoming: Option<DrainConnection>,
}

/// Why the last connection ended and how long the client waits before the next attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnect {
    /// The error, as text.
    pub reason: String,
    /// The wait before the next attempt.
    pub retry_in: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The public relay's MongoDB TTL index is `expireAfterSeconds: 604800` (`mongo-init.js` in
    // `epic-epicbox-docker`). A shorter retention would forget ids the relay can still deliver.
    #[test]
    fn relay_retention_matches_the_public_relay_ttl() {
        assert_eq!(RELAY_RETENTION, Duration::from_secs(604_800));
    }
}
