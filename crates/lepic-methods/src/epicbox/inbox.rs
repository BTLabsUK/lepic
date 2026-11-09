// SPDX-License-Identifier: Apache-2.0
//! The Epicbox inbox loop (ADR 0004): it takes each message the relay hands out to the engine
//! with [`Wallet::arrived`], records how it settled and acknowledges it.
//!
//! A message is acknowledged once its effect is stored, or once it was rejected for good and
//! the rejection is recorded, under its relay message id when the relay gave it one; a
//! transient failure leaves it unacknowledged, so the relay delivers it again. A held message
//! holds back everything behind it, because the relay delivers one message at a time. An answer
//! the engine gives back as [`Outcome::Requeue`] is posted back to the address for another
//! install of the wallet before it is acknowledged.

use std::sync::{Arc, Mutex, PoisonError};

use lepic_epicbox::{
    Backoff, ClientError, ConnectionState, EpicboxAddress, EpicboxClient, Identity,
    RELAY_RETENTION, Rejection, RelayMessageId, Subscription, TRANSPORT_ID,
};
use lepic_node::NodeApi;
use lepic_primitives::error_chain::ErrorChain;
use lepic_transport::method::Method;
use lepic_transport::transport::{AckToken, Envelope, Inbound};
use lepic_wallet::event::{
    Connection, Event, TransportDisconnect, TransportState, TransportStatus,
};
use lepic_wallet::inbox::{
    Arrival, Handled, Hold, InboxError, InboxSummary, ListenHandle, Outcome, Requeue,
};
use lepic_wallet::namespace::Listing;
use lepic_wallet::{SecretVault, StoreOpener, Wallet};
use tracing::{debug, info, instrument, warn};

use super::Epicbox;

use super::{NATIVE_NOTICE_LENGTHS, relay_network};

// The engine drops a notice longer than this, so the longest padding must fit.
const _: () = assert!(NATIVE_NOTICE_LENGTHS[2] <= lepic_wallet::notice::MAX_NOTICE_LEN);

/// The relay client's reconnect backoff also paces the retries of a held message.
fn backoff(epicbox: &Epicbox) -> Backoff {
    epicbox.settings().backoff
}

fn transport_state(state: ConnectionState) -> TransportState {
    match state {
        ConnectionState::Connecting { .. } => TransportState::Connecting,
        ConnectionState::Subscribed => TransportState::Connected,
        ConnectionState::Stopped | ConnectionState::Drained => TransportState::Stopped,
        _ => TransportState::Disconnected,
    }
}

/// When one drain or listen last pruned the relay inbox as a message settled.
#[derive(Default)]
pub(super) struct PruneSchedule(Mutex<Option<jiff::Timestamp>>);

impl PruneSchedule {
    fn last(&self) -> Option<jiff::Timestamp> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record(&self, at: jiff::Timestamp) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(at);
    }
}

/// Settled messages are acknowledged; a held one is left for the relay to deliver again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Settled(Handled),
    Held,
}

enum Item {
    /// An envelope with the relay message id the subscription handed it out under, if any.
    Envelope(Envelope, Option<RelayMessageId>),
    Rejection(Rejection),
}

impl Item {
    fn envelope(subscription: &Subscription, envelope: Envelope) -> Self {
        let msg_id = subscription.relay_message_id(envelope.ack_token());
        Self::Envelope(envelope, msg_id)
    }

    fn ack_token(&self) -> &AckToken {
        match self {
            Self::Envelope(envelope, _) => envelope.ack_token(),
            Self::Rejection(rejection) => rejection.ack_token(),
        }
    }

    fn msg_id(&self) -> Option<&str> {
        match self {
            Self::Envelope(_, msg_id) => msg_id.as_ref(),
            Self::Rejection(rejection) => rejection.msg_id(),
        }
        .map(RelayMessageId::as_str)
    }
}

impl Epicbox {
    /// Attaches `wallet`'s Epicbox identity, the address key of the default account at index 0
    /// as `epic-wallet` derives it, so that this method can send and receive for it, and
    /// returns the wallet's address at the relay. Attaching again replaces the identity. The
    /// key stays attached until [`Epicbox::detach`]; hosts detach when they lock.
    ///
    /// Fails with [`InboxError::Wallet`] carrying [`lepic_wallet::WalletError::Locked`], and
    /// with [`InboxError::NetworkMismatch`] when this method serves the other network.
    pub fn attach_wallet<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
    ) -> Result<EpicboxAddress, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        Ok(self.attached_client(wallet)?.address().clone())
    }

    fn attached_client<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
    ) -> Result<EpicboxClient, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        Ok(self.attach(self.identity(wallet)?))
    }

    /// The wallet's Epicbox identity (the default account's first address) at this method's
    /// relay.
    fn identity<N, S, V>(&self, wallet: &Wallet<N, S, V>) -> Result<Identity, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let network = relay_network(wallet.config().network);
        if self.network() != network {
            return Err(InboxError::NetworkMismatch);
        }
        let secret = wallet.address_secret()?;
        let public = lepic_crypto::PublicKey::from_secret_key(&secret)
            .map_err(|_| InboxError::Identity(Box::new(ClientError::IdentityMismatch)))?;
        let endpoint = &self.settings().endpoint;
        let address = EpicboxAddress::new(
            public,
            network,
            endpoint.domain().clone(),
            Some(endpoint.port()),
        );
        Identity::new(secret, address).map_err(|error| InboxError::Identity(Box::new(error)))
    }

    /// Connects to the relay once, handles every pending message for `wallet` and disconnects:
    /// the mode for background work on mobile. Attaches the wallet's identity first, as
    /// [`Epicbox::attach_wallet`] does. Slates that arrive are taken and answered over this
    /// method.
    ///
    /// Stops at the first message that fails for a transient reason, such as the node being
    /// unreachable, and leaves it and everything behind it on the relay for the next drain.
    /// A slate the node's tip says has expired is such a message until a refresh stores a
    /// confirmed height at or past its cutoff; the drain makes one refresh itself before it
    /// holds one. A reply or an expired slate is not held past the bound the engine's inbox
    /// docs give. Fails with [`InboxError::Subscription`] when the relay connection fails;
    /// whatever was handled until then stays handled. Fails as [`Epicbox::attach_wallet`]
    /// does.
    #[instrument(skip_all, fields(wallet = %wallet.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn drain<N, S, V>(&self, wallet: &Wallet<N, S, V>) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let client = self.inbox_client(wallet).await?;
        let subscription = client
            .drain()
            .map_err(|error| InboxError::Subscription(Box::new(error)))?;
        let method: Arc<dyn Method> = Arc::new(self.clone());
        self.run_inbox(wallet, method, &subscription, None).await
    }

    /// Holds a relay connection and handles messages for `wallet` as they arrive, until
    /// `handle` is stopped: the mode while the app is in the foreground. Reconnects on its own
    /// after the relay drops. Emits [`Event::Transport`] as the connection changes, and
    /// attaches the wallet's identity first, as [`Epicbox::attach_wallet`] does.
    ///
    /// A message that fails for a transient reason is tried again with backoff, and nothing
    /// behind it is delivered until it settles. A slate the node's tip says has expired settles
    /// once a refresh stores a confirmed height at or past its cutoff; the listen refreshes the
    /// tip itself before it holds one, at most once a minute. A reply or an expired slate is not
    /// held past the bound the engine's inbox docs give. Fails as [`Epicbox::drain`] does
    /// before it connects.
    #[instrument(skip_all, fields(wallet = %wallet.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn listen<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        handle: &ListenHandle,
    ) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let client = self.inbox_client(wallet).await?;
        let subscription = client
            .listen_with_held_rounds(wallet.config().policy.listener_held_rounds)
            .map_err(|error| InboxError::Subscription(Box::new(error)))?;
        let method: Arc<dyn Method> = Arc::new(self.clone());
        self.run_inbox(wallet, method, &subscription, Some(handle))
            .await
    }

    /// The attached client for a drain or a listen, after pruning the relay inbox. Pruning runs
    /// before the subscription starts, so the host sees every connection state.
    async fn inbox_client<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
    ) -> Result<EpicboxClient, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let client = self.attached_client(wallet)?;
        wallet.prune_arrivals(RELAY_RETENTION).await;
        Ok(client)
    }

    /// Consumes the subscription and stops it, while its connection state goes out as events.
    async fn run_inbox<N, S, V>(
        &self,
        wallet: &Wallet<N, S, V>,
        method: Arc<dyn Method>,
        subscription: &Subscription,
        listen: Option<&ListenHandle>,
    ) -> Result<InboxSummary, InboxError>
    where
        N: NodeApi + 'static,
        S: StoreOpener + 'static,
        V: SecretVault + 'static,
    {
        let run = Run {
            wallet,
            method,
            subscription,
            listen,
            backoff: backoff(self),
            pruning: PruneSchedule::default(),
            listing: None,
        };
        let consume = async {
            let consumed = run.consume().await;
            // A failed connection explains a failed consume better than the consume does.
            subscription
                .stop()
                .await
                .map_err(|error| InboxError::Subscription(Box::new(error)))?;
            consumed
        };
        let connection = match listen {
            Some(_) => Connection::Listener,
            None => Connection::PaymentsDrain,
        };
        let (result, ()) = tokio::join!(consume, forward_states(wallet, subscription, connection));
        result
    }
}

async fn forward_states<N, S, V>(
    wallet: &Wallet<N, S, V>,
    subscription: &Subscription,
    connection: Connection,
) where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    let mut states = subscription.state();
    let mut last = None;
    loop {
        let state = *states.borrow_and_update();
        let mapped = transport_state(state);
        if last != Some(mapped) {
            last = Some(mapped);
            wallet.emit(Event::Transport(TransportStatus {
                transport: TRANSPORT_ID,
                connection,
                state: mapped,
            }));
            if mapped == TransportState::Disconnected {
                let disconnect = subscription.last_disconnect();
                wallet.emit(Event::TransportDisconnected(TransportDisconnect {
                    transport: TRANSPORT_ID,
                    connection,
                    reason: disconnect.as_ref().map_or_else(
                        || "connection ended".to_owned(),
                        |disconnect| disconnect.reason.clone(),
                    ),
                    retry_in: disconnect.map(|disconnect| disconnect.retry_in),
                }));
            }
        }
        if state.has_ended() || states.changed().await.is_err() {
            return;
        }
    }
}

/// One drain or listen of a subscription for a wallet: what its messages are taken with.
pub(super) struct Run<'a, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    pub(super) wallet: &'a Wallet<N, S, V>,
    /// The method the engine answers over: at a listing, one that sends from its address.
    pub(super) method: Arc<dyn Method>,
    pub(super) subscription: &'a Subscription,
    pub(super) listen: Option<&'a ListenHandle>,
    pub(super) backoff: Backoff,
    pub(super) pruning: PruneSchedule,
    pub(super) listing: Option<Listing>,
}

impl<N, S, V> Run<'_, N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    pub(super) async fn consume(&self) -> Result<InboxSummary, InboxError> {
        let subscription = self.subscription;
        let listen = self.listen;
        let mut summary = InboxSummary::default();
        loop {
            let item = match subscription.next_rejection() {
                Some(rejection) => Item::Rejection(rejection),
                None => {
                    let next = match listen {
                        None => subscription.next_envelope().await,
                        Some(handle) => tokio::select! {
                            biased;
                            () = handle.stopped() => return Ok(summary),
                            next = subscription.next_envelope() => next,
                        },
                    };
                    match next.map_err(InboxError::Transport)? {
                        Some(envelope) => Item::envelope(subscription, envelope),
                        // A rejection may have arrived while no envelope did.
                        None if listen.is_none() => match subscription.next_rejection() {
                            Some(rejection) => Item::Rejection(rejection),
                            None => return Ok(summary),
                        },
                        None => {
                            let Some(handle) = listen else {
                                return Ok(summary);
                            };
                            tokio::select! {
                                biased;
                                () = handle.stopped() => return Ok(summary),
                                () = subscription.delivery_available() => {}
                            }
                            if subscription.state().borrow().has_ended() {
                                return Ok(summary);
                            }
                            continue;
                        }
                    }
                }
            };
            match self.settle(&item).await {
                Some(handled) => summary.count(handled),
                None => {
                    summary.held = summary.held.saturating_add(1);
                    return Ok(summary);
                }
            }
        }
    }

    /// Handles `item` until it settles, then acknowledges it. Returns `None` when it is held:
    /// at once in a drain, and in a listen once the listen is stopped while retrying.
    async fn settle(&self, item: &Item) -> Option<Handled> {
        let mut attempt: u32 = 0;
        let handled = loop {
            let try_number = attempt.saturating_add(1);
            let disposition = match self.listen {
                None => self.handle(item, try_number).await,
                Some(handle) => tokio::select! {
                    biased;
                    () = handle.abandoned() => return None,
                    disposition = self.handle(item, try_number) => disposition,
                },
            };
            match (disposition, self.listen) {
                (Disposition::Settled(handled), _) => break handled,
                (Disposition::Held, None) => return None,
                (Disposition::Held, Some(handle)) => {
                    attempt = attempt.saturating_add(1);
                    let delay = self.backoff.ceiling(attempt);
                    debug!(
                        attempt,
                        msg_id = item.msg_id().unwrap_or(""),
                        "epicbox message retry scheduled"
                    );
                    tokio::select! {
                        biased;
                        () = handle.stopped() => return None,
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            }
        };
        self.acknowledge(item, handled).await;
        Some(handled)
    }

    /// Sends `Made` for a settled item. A listen tries again until the relay accepts it,
    /// because the relay delivers nothing else to the address while a message is
    /// unacknowledged. A drain whose acknowledgement fails has lost its connection; the relay
    /// delivers the message again later and its inbox entry settles it at once.
    async fn acknowledge(&self, item: &Item, handled: Handled) {
        let msg_id = item.msg_id().unwrap_or("");
        let mut attempt: u32 = 0;
        while let Err(error) = self.subscription.acknowledge(item.ack_token()).await {
            warn!(msg_id, error = %ErrorChain(&error), "epicbox acknowledgement failed");
            let Some(handle) = self.listen else {
                return;
            };
            attempt = attempt.saturating_add(1);
            tokio::select! {
                biased;
                () = handle.abandoned() => return,
                () = tokio::time::sleep(self.backoff.ceiling(attempt)) => {}
            }
        }
        debug!(msg_id, "epicbox message settled");
        let Some(msg_id) = item.msg_id() else {
            return;
        };
        self.wallet.arrival_acknowledged(msg_id, handled).await;
    }

    /// Handles `item` on its try number `attempt`, counted from 1.
    async fn handle(&self, item: &Item, attempt: u32) -> Disposition {
        let msg_id = item.msg_id().map(str::to_owned);
        let outcome = match item {
            Item::Rejection(rejection) => {
                debug!(
                    msg_id = msg_id.as_deref().unwrap_or(""),
                    error = ?rejection.reason(),
                    "epicbox rejection recorded"
                );
                Ok(Handled::Rejected)
            }
            Item::Envelope(envelope, _) => {
                self.handle_envelope(msg_id.as_deref(), envelope, attempt)
                    .await
            }
        };
        let handled = match outcome {
            Ok(handled) => handled,
            Err(Hold::UnknownSlate) => {
                debug!(
                    msg_id = msg_id.as_deref().unwrap_or(""),
                    "epicbox message held for another install"
                );
                return Disposition::Held;
            }
            Err(hold) => {
                warn!(
                    msg_id = msg_id.as_deref().unwrap_or(""),
                    error = %ErrorChain(&hold),
                    "epicbox message held"
                );
                return Disposition::Held;
            }
        };
        if let Some(msg_id) = msg_id {
            let recorded = self
                .wallet
                .arrival_settled(&msg_id, handled, self.pruning.last(), RELAY_RETENTION)
                .await;
            match recorded {
                Ok(Some(pruned_at)) => self.pruning.record(pruned_at),
                Ok(None) => {}
                Err(error) => {
                    warn!(error = %ErrorChain(&error), "epicbox message held");
                    return Disposition::Held;
                }
            }
        }
        Disposition::Settled(handled)
    }

    async fn handle_envelope(
        &self,
        msg_id: Option<&str>,
        envelope: &Envelope,
        attempt: u32,
    ) -> Result<Handled, Hold> {
        let arrival = Arrival {
            msg_id,
            envelope,
            attempt,
            listing: self.listing,
        };
        match self.wallet.arrived(&self.method, arrival).await {
            Ok(handled) => Ok(handled),
            Err(Outcome::Hold(hold)) => Err(hold),
            Err(Outcome::Requeue(answer)) => self.requeue(msg_id, envelope, answer).await,
        }
    }

    /// Posts the message of `answer` back to the subscription's address for another install,
    /// then lets it be acknowledged. A post that fails holds the message, until it first
    /// arrived the engine's hold patience ago: then it is refused for good.
    async fn requeue(
        &self,
        msg_id: Option<&str>,
        envelope: &Envelope,
        answer: Requeue,
    ) -> Result<Handled, Hold> {
        match self.subscription.requeue(envelope.ack_token()).await {
            Ok(()) => {
                let count = self.wallet.requeued(&answer).await;
                info!(
                    slate_id = %answer.slate_id,
                    stage = answer.stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    count,
                    "answer for an unknown slate requeued for another install"
                );
                Ok(Handled::Requeued)
            }
            Err(error) => {
                if !self.wallet.requeue_failed(msg_id).await? {
                    return Err(Hold::Requeue(Box::new(error)));
                }
                warn!(
                    slate_id = %answer.slate_id,
                    stage = answer.stage.as_str(),
                    msg_id = msg_id.unwrap_or(""),
                    error = %ErrorChain(&error),
                    "answer for an unknown slate not requeued"
                );
                warn!(
                    msg_id = msg_id.unwrap_or(""),
                    error = %ErrorChain(answer.refusal()),
                    "epicbox message rejected"
                );
                Ok(Handled::Rejected)
            }
        }
    }
}
