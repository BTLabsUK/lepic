//! The Epicbox inbox: what the engine does with each message the relay hands out (ADR 0004).
//!
//! A message is decoded with the Epicbox policy and routed by stage: an S1 is received and
//! answered with S2 through the same transport, an S2 is finalized and posted. Its relay message
//! id is tracked in the store's relay inbox. A message is acknowledged once its effect is stored,
//! or once it was rejected for good and the rejection is recorded; a transient failure leaves it
//! unacknowledged, so the relay delivers it again.
//!
//! Every message is idempotent on its relay id and on `(slate_id, stage)`: a redelivered S1 is
//! answered with the S2 stored the first time, never a new one, and finalizing an S2 again
//! changes nothing that is stored.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use lepic_epicbox::transport::{EpicboxTransport, relay_message_id};
use lepic_epicbox::{
    Backoff, ClientError, ConnectionState, EpicboxAddress, EpicboxClient, Identity,
    Network as RelayNetwork, Rejection, Subscription, TRANSPORT_ID,
};
use lepic_node::{NodeApi, Propagation};
use lepic_primitives::params::Network;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::stage::Stage;
use lepic_store::{AccountIndex, InboxEntry, InboxStatus, Repositories, StoreError, WalletStore};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{Destination, Envelope, Inbound, TransportId};
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, info, instrument, warn};

use crate::account;
use crate::error::WalletError;
use crate::event::{Event, TransportState, TransportStatus};
use crate::finalize::FinalizeError;
use crate::ports::{SecretVault, StoreOpener};
use crate::receive::redelivery::{answers, decode_reply, stored_reply};
use crate::receive::{ReceiveError, ReceiveRequest, legacy_codecs};
use crate::wallet::Wallet;

/// `epic-wallet` always uses the address key at index 0 of the account.
const ADDRESS_INDEX: u32 = 0;

/// The account whose address key is the wallet's Epicbox identity.
const ADDRESS_ACCOUNT: AccountIndex = AccountIndex(0);

/// `epic-wallet`'s Epicbox listener posts finalized transactions without fluff.
const POST_PROPAGATION: Propagation = Propagation::Stem;

const MAX_ERROR_SOURCES: usize = 8;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InboxError {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("transport {transport} is not registered")]
    UnknownTransport { transport: TransportId },
    #[error("epicbox transport serves another network than the wallet")]
    NetworkMismatch,
    #[error("epicbox identity rejected")]
    Identity(#[source] ClientError),
    /// The relay connection failed. Unacknowledged messages stay on the relay; try again later.
    #[error("epicbox subscription failed")]
    Subscription(#[source] ClientError),
    #[error("epicbox subscription failed")]
    Transport(#[source] TransportError),
}

/// What one listen or drain did with the messages it was handed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InboxSummary {
    /// S1 slates received and answered with S2.
    pub received: u32,
    /// S2 slates finalized; posting may still be pending.
    pub finalized: u32,
    /// Messages handled before and acknowledged again, an S1 answered again with its stored S2.
    pub repeated: u32,
    /// Messages rejected for good, recorded and acknowledged.
    pub rejected: u32,
    /// Messages left unacknowledged after a transient failure; the relay delivers them again.
    pub held: u32,
}

impl InboxSummary {
    fn count(&mut self, handled: Handled) {
        let counter = match handled {
            Handled::Received => &mut self.received,
            Handled::Finalized => &mut self.finalized,
            Handled::Repeated => &mut self.repeated,
            Handled::Rejected => &mut self.rejected,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Ends an [`Wallet::epicbox_listen`]. Clones stop the same listen.
#[derive(Debug, Clone)]
pub struct ListenHandle(Arc<watch::Sender<bool>>);

impl ListenHandle {
    pub fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    /// Asks the listen to end. It finishes or abandons the message in hand, unsubscribes and
    /// returns.
    pub fn stop(&self) {
        self.0.send_replace(true);
    }

    pub fn is_stopped(&self) -> bool {
        *self.0.borrow()
    }

    async fn stopped(&self) {
        let mut receiver = self.0.subscribe();
        // The sender lives in `self`, so waiting cannot fail.
        let _ = receiver.wait_for(|stopped| *stopped).await;
    }
}

impl Default for ListenHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// What became of one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handled {
    Received,
    Finalized,
    Repeated,
    Rejected,
}

impl Handled {
    fn inbox_status(self) -> InboxStatus {
        match self {
            Self::Rejected => InboxStatus::Rejected,
            Self::Received | Self::Finalized | Self::Repeated => InboxStatus::Processed,
        }
    }
}

/// Settled messages are acknowledged; a held one is left for the relay to deliver again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Settled(Handled),
    Held,
}

enum Item {
    Envelope(Envelope),
    Rejection(Rejection),
}

impl Item {
    fn ack_token(&self) -> &lepic_transport::transport::AckToken {
        match self {
            Self::Envelope(envelope) => envelope.ack_token(),
            Self::Rejection(rejection) => rejection.ack_token(),
        }
    }

    fn msg_id(&self) -> Option<&str> {
        match self {
            Self::Envelope(envelope) => relay_message_id(envelope.ack_token()),
            Self::Rejection(rejection) => rejection.msg_id(),
        }
    }
}

/// Why a message is rejected for good, for the log.
#[derive(Debug, Error)]
enum Refusal {
    #[error("message carries no reply address")]
    NoReplyAddress,
    #[error("slate could not be decoded")]
    Decode(#[source] lepic_slate::error::DecodeError),
    #[error("slate at stage {stage} is not handled over epicbox")]
    UnsupportedStage { stage: Stage },
    #[error("slate id was received before with another slate")]
    SlateIdReused,
    #[error("slate was not received")]
    Receive(#[source] ReceiveError),
    #[error("slate was not finalized")]
    Finalize(#[source] FinalizeError),
}

/// A failure that leaves the message for the relay to deliver again.
#[derive(Debug, Error)]
enum Hold {
    #[error("wallet operation failed")]
    Wallet(#[from] WalletError),
    #[error("transport {transport} cannot deliver the reply")]
    NoOutbound { transport: TransportId },
    #[error("reply was not delivered")]
    Reply(#[source] TransportError),
    #[error("slate was not received")]
    Receive(#[source] ReceiveError),
    #[error("slate was not finalized")]
    Finalize(#[source] FinalizeError),
}

impl From<StoreError> for Hold {
    fn from(error: StoreError) -> Self {
        Self::Wallet(WalletError::Store(error))
    }
}

/// Displays an error with its source chain, for the `error` log field.
struct ErrorChain<'a>(&'a (dyn StdError + 'static));

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let sources = std::iter::successors(self.0.source(), |&error| error.source());
        for source in sources.take(MAX_ERROR_SOURCES) {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

/// Failures of receiving an S1 that the same message would meet again: the slate itself is
/// wrong. Local and node failures pass.
fn receive_is_permanent(error: &ReceiveError) -> bool {
    match error {
        ReceiveError::Wallet(_)
        | ReceiveError::UnknownTransport { .. }
        | ReceiveError::Node(_)
        | ReceiveError::Codecs(_) => false,
        ReceiveError::Decode(_)
        | ReceiveError::WrongStage { .. }
        | ReceiveError::AlreadyReceived { .. }
        | ReceiveError::Expired { .. }
        | ReceiveError::FeeBelowMinimum { .. }
        | ReceiveError::FeeOverflow
        | ReceiveError::MessageSignature { .. }
        | ReceiveError::ForeignProofAddress
        | ReceiveError::Output(_)
        | ReceiveError::Signing(_)
        | ReceiveError::Excess(_)
        | ReceiveError::Slate(_)
        | ReceiveError::Encode(_) => true,
    }
}

/// Failures of finalizing an S2 that the same message would meet again. A slate that was
/// finalized and stored but not posted is not a failure of the message; the caller handles it.
fn finalize_is_permanent(error: &FinalizeError) -> bool {
    match error {
        FinalizeError::Wallet(_)
        | FinalizeError::UnknownTransport { .. }
        | FinalizeError::Node(_)
        | FinalizeError::Codecs(_)
        | FinalizeError::NotPosted { .. } => false,
        FinalizeError::Decode(_)
        | FinalizeError::WrongStage { .. }
        | FinalizeError::UnknownSlate { .. }
        | FinalizeError::AlreadyFinalized { .. }
        | FinalizeError::NotFinalizable { .. }
        | FinalizeError::Expired { .. }
        | FinalizeError::Mismatch { .. }
        | FinalizeError::MissingPaymentProof
        | FinalizeError::ForeignSenderAddress
        | FinalizeError::PaymentProofSignature
        | FinalizeError::MessageSignature(_)
        | FinalizeError::ReceiverSignature(_)
        | FinalizeError::FeeBelowMinimum { .. }
        | FinalizeError::FeeOverflow
        | FinalizeError::Signing(_)
        | FinalizeError::Excess(_)
        | FinalizeError::InvalidTransaction(_)
        | FinalizeError::Slate(_)
        | FinalizeError::Encode(_)
        | FinalizeError::StoredSlate(_)
        | FinalizeError::MissingContext { .. }
        | FinalizeError::MalformedContext
        | FinalizeError::NotPostable { .. } => true,
    }
}

/// The relay client's reconnect backoff also paces the retries of a held message.
fn backoff(epicbox: &EpicboxTransport) -> Backoff {
    epicbox.settings().backoff
}

fn relay_network(network: Network) -> RelayNetwork {
    match network {
        Network::Mainnet => RelayNetwork::Mainnet,
        Network::Floonet => RelayNetwork::Floonet,
    }
}

fn transport_state(state: ConnectionState) -> TransportState {
    match state {
        ConnectionState::Connecting { .. } => TransportState::Connecting,
        ConnectionState::Subscribed => TransportState::Connected,
        ConnectionState::Stopped | ConnectionState::Drained => TransportState::Stopped,
        _ => TransportState::Disconnected,
    }
}

/// Inserts or updates the inbox entry of `msg_id`, keeping when it was first received.
fn put_inbox(
    repos: &mut dyn Repositories,
    msg_id: &str,
    status: InboxStatus,
    now: jiff::Timestamp,
) -> Result<(), StoreError> {
    let received_at = repos.inbox(msg_id)?.map_or(now, |entry| entry.received_at);
    repos.put_inbox(&InboxEntry {
        msg_id: msg_id.to_owned(),
        status,
        received_at,
        updated_at: now,
    })
}

/// The status a message had before this delivery, recording it as received when it is new.
fn begin_inbox(
    repos: &mut dyn Repositories,
    msg_id: &str,
    now: jiff::Timestamp,
) -> Result<Option<InboxStatus>, StoreError> {
    let previous = repos.inbox(msg_id)?.map(|entry| entry.status);
    if previous.is_none() {
        put_inbox(repos, msg_id, InboxStatus::Received, now)?;
    }
    Ok(previous)
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// Attaches this wallet's Epicbox identity, the address key of the default account at index
    /// 0 as `epic-wallet` derives it, to `epicbox`, so that it can send and receive, and returns
    /// the wallet's address at the transport's relay. Attaching again replaces the identity.
    /// The key stays attached until [`EpicboxTransport::detach`]; hosts detach when they lock.
    ///
    /// Fails with [`InboxError::Wallet`] carrying [`WalletError::Locked`], and with
    /// [`InboxError::NetworkMismatch`] when the transport serves the other network.
    pub fn epicbox_attach(&self, epicbox: &EpicboxTransport) -> Result<EpicboxAddress, InboxError> {
        Ok(self.attached_client(epicbox)?.address().clone())
    }

    fn attached_client(&self, epicbox: &EpicboxTransport) -> Result<EpicboxClient, InboxError> {
        let network = relay_network(self.config().network);
        if epicbox.network() != network {
            return Err(InboxError::NetworkMismatch);
        }
        let session = self.session()?;
        let parent = account::parent_key_id(ADDRESS_ACCOUNT)?;
        let secret = session
            .keychain
            .address_key(&parent, ADDRESS_INDEX)
            .map_err(WalletError::Keychain)?;
        let public = lepic_crypto::PublicKey::from_secret_key(&secret)
            .map_err(|_| InboxError::Identity(ClientError::IdentityMismatch))?;
        let endpoint = &epicbox.settings().endpoint;
        let address = EpicboxAddress::new(
            public,
            network,
            endpoint.domain().clone(),
            Some(endpoint.port()),
        );
        let identity = Identity::new(secret, address).map_err(InboxError::Identity)?;
        Ok(epicbox.attach(identity))
    }

    /// Connects to the relay once, handles every pending message and disconnects: the mode for
    /// background work on mobile. Attaches the wallet's identity first, as
    /// [`Wallet::epicbox_attach`] does. `epicbox` must be the transport registered in the
    /// wallet's registry, or a clone of it.
    ///
    /// Stops at the first message that fails for a transient reason, such as the node being
    /// unreachable, and leaves it and everything behind it on the relay for the next drain.
    /// Fails with [`InboxError::Subscription`] when the relay connection fails; whatever was
    /// handled until then stays handled. Fails as [`Wallet::epicbox_attach`] does, and with
    /// [`InboxError::UnknownTransport`] when Epicbox is not registered.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn epicbox_drain(
        &self,
        epicbox: &EpicboxTransport,
    ) -> Result<InboxSummary, InboxError> {
        let client = self.inbox_client(epicbox)?;
        let subscription = client.drain().map_err(InboxError::Subscription)?;
        self.run_inbox(&subscription, None, backoff(epicbox)).await
    }

    /// Holds a relay connection and handles messages as they arrive, until `handle` is stopped:
    /// the mode while the app is in the foreground. Reconnects on its own after the relay
    /// drops. Emits [`Event::Transport`] as the connection changes, and attaches the wallet's
    /// identity first, as [`Wallet::epicbox_attach`] does.
    ///
    /// A message that fails for a transient reason is tried again with backoff, and nothing
    /// behind it is delivered until it settles. Fails as [`Wallet::epicbox_drain`] does before
    /// it connects.
    #[instrument(skip_all, fields(wallet = %self.config().name, transport = TRANSPORT_ID.as_str()))]
    pub async fn epicbox_listen(
        &self,
        epicbox: &EpicboxTransport,
        handle: &ListenHandle,
    ) -> Result<InboxSummary, InboxError> {
        let client = self.inbox_client(epicbox)?;
        let subscription = client.listen().map_err(InboxError::Subscription)?;
        self.run_inbox(&subscription, Some(handle), backoff(epicbox))
            .await
    }

    fn inbox_client(&self, epicbox: &EpicboxTransport) -> Result<EpicboxClient, InboxError> {
        if self.ports().transports.get(TRANSPORT_ID).is_none() {
            return Err(InboxError::UnknownTransport {
                transport: TRANSPORT_ID,
            });
        }
        self.attached_client(epicbox)
    }

    /// Consumes the subscription and stops it, while its connection state goes out as events.
    async fn run_inbox(
        &self,
        subscription: &Subscription,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
    ) -> Result<InboxSummary, InboxError> {
        let consume = async {
            let consumed = self.consume(subscription, listen, backoff).await;
            // A failed connection explains a failed consume better than the consume does.
            subscription
                .stop()
                .await
                .map_err(InboxError::Subscription)?;
            consumed
        };
        let (result, ()) = tokio::join!(consume, self.forward_states(subscription));
        result
    }

    async fn forward_states(&self, subscription: &Subscription) {
        let mut states = subscription.state();
        let mut last = None;
        loop {
            let state = *states.borrow_and_update();
            let mapped = transport_state(state);
            if last != Some(mapped) {
                last = Some(mapped);
                self.emit(Event::Transport(TransportStatus {
                    transport: TRANSPORT_ID,
                    state: mapped,
                }));
            }
            if state.has_ended() || states.changed().await.is_err() {
                return;
            }
        }
    }

    async fn consume(
        &self,
        subscription: &Subscription,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
    ) -> Result<InboxSummary, InboxError> {
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
                        Some(envelope) => Item::Envelope(envelope),
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
            match self.settle(subscription, &item, listen, backoff).await {
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
    async fn settle(
        &self,
        subscription: &Subscription,
        item: &Item,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
    ) -> Option<Handled> {
        let mut attempt: u32 = 0;
        let handled = loop {
            let disposition = match listen {
                None => self.handle(item).await,
                Some(handle) => tokio::select! {
                    biased;
                    () = handle.stopped() => return None,
                    disposition = self.handle(item) => disposition,
                },
            };
            match (disposition, listen) {
                (Disposition::Settled(handled), _) => break handled,
                (Disposition::Held, None) => return None,
                (Disposition::Held, Some(handle)) => {
                    attempt = attempt.saturating_add(1);
                    let delay = backoff.ceiling(attempt);
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
        self.acknowledge(subscription, item, handled, listen, backoff)
            .await;
        Some(handled)
    }

    /// Sends `Made` for a settled item. A listen tries again until the relay accepts it,
    /// because the relay delivers nothing else to the address while a message is
    /// unacknowledged. A drain whose acknowledgement fails has lost its connection; the relay
    /// delivers the message again later and its inbox entry settles it at once.
    async fn acknowledge(
        &self,
        subscription: &Subscription,
        item: &Item,
        handled: Handled,
        listen: Option<&ListenHandle>,
        backoff: Backoff,
    ) {
        let msg_id = item.msg_id().unwrap_or("");
        let mut attempt: u32 = 0;
        while let Err(error) = subscription.acknowledge(item.ack_token()).await {
            warn!(msg_id, error = %ErrorChain(&error), "epicbox acknowledgement failed");
            let Some(handle) = listen else {
                return;
            };
            attempt = attempt.saturating_add(1);
            tokio::select! {
                biased;
                () = handle.stopped() => return,
                () = tokio::time::sleep(backoff.ceiling(attempt)) => {}
            }
        }
        debug!(msg_id, "epicbox message settled");
        if handled == Handled::Rejected {
            return;
        }
        let Some(msg_id) = item.msg_id().map(str::to_owned) else {
            return;
        };
        let recorded = self
            .inbox_write(move |repos, now| {
                put_inbox(repos, &msg_id, InboxStatus::Acknowledged, now)
            })
            .await;
        if let Err(error) = recorded {
            warn!(error = %ErrorChain(&error), "epicbox acknowledgement not recorded");
        }
    }

    async fn handle(&self, item: &Item) -> Disposition {
        let msg_id = item.msg_id().map(str::to_owned);
        let outcome = match item {
            Item::Rejection(rejection) => {
                debug!(
                    msg_id = rejection.msg_id().unwrap_or(""),
                    error = ?rejection.reason(),
                    "epicbox rejection recorded"
                );
                Ok(Handled::Rejected)
            }
            Item::Envelope(envelope) => self.handle_envelope(msg_id.as_deref(), envelope).await,
        };
        let handled = match outcome {
            Ok(handled) => handled,
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
            let status = handled.inbox_status();
            let recorded = self
                .inbox_write(move |repos, now| put_inbox(repos, &msg_id, status, now))
                .await;
            if let Err(error) = recorded {
                warn!(error = %ErrorChain(&error), "epicbox message held");
                return Disposition::Held;
            }
        }
        Disposition::Settled(handled)
    }

    async fn handle_envelope(
        &self,
        msg_id: Option<&str>,
        envelope: &Envelope,
    ) -> Result<Handled, Hold> {
        if let Some(msg_id) = msg_id.map(str::to_owned) {
            let previous = self
                .inbox_write(move |repos, now| begin_inbox(repos, &msg_id, now))
                .await?;
            if matches!(
                previous,
                Some(InboxStatus::Processed | InboxStatus::Acknowledged | InboxStatus::Rejected)
            ) {
                debug!("epicbox message already settled");
                return Ok(Handled::Repeated);
            }
        }
        match self.apply(envelope).await {
            Ok(handled) => Ok(handled),
            Err(Settlement::Hold(hold)) => Err(hold),
            Err(Settlement::Refuse(refusal)) => {
                warn!(
                    msg_id = msg_id.unwrap_or(""),
                    error = %ErrorChain(&refusal),
                    "epicbox message rejected"
                );
                Ok(Handled::Rejected)
            }
        }
    }

    async fn apply(&self, envelope: &Envelope) -> Result<Handled, Settlement> {
        let reply_to = envelope.reply_to().ok_or(Refusal::NoReplyAddress)?;
        let network = self.config().network;
        let transport = self
            .ports()
            .transports
            .get(TRANSPORT_ID)
            .ok_or(WalletError::Config(
                crate::config::ConfigError::UnknownTransport {
                    transport: TRANSPORT_ID,
                },
            ))
            .map_err(Hold::from)?;
        let codecs = legacy_codecs(network).map_err(Hold::Receive)?;
        let slate = transport
            .policy()
            .decode(&codecs, envelope.wire())
            .map_err(Refusal::Decode)?;
        match slate.stage() {
            Stage::S1 => self.answer(envelope, &slate, reply_to).await,
            Stage::S2 => self.complete(envelope).await,
            stage => Err(Refusal::UnsupportedStage { stage }.into()),
        }
    }

    /// Receives an S1 and replies with S2, or replies again with the S2 stored for it.
    async fn answer(
        &self,
        envelope: &Envelope,
        proposal: &Slate,
        reply_to: &Destination,
    ) -> Result<Handled, Settlement> {
        if let Some(handled) = self.answer_again(proposal, reply_to).await? {
            return Ok(handled);
        }
        match self
            .receive(TRANSPORT_ID, envelope.wire(), ReceiveRequest::default())
            .await
        {
            Ok(received) => {
                self.reply(reply_to, &received.reply).await?;
                Ok(Handled::Received)
            }
            Err(ReceiveError::AlreadyReceived { .. }) => self
                .answer_again(proposal, reply_to)
                .await?
                .ok_or_else(|| Refusal::SlateIdReused.into()),
            Err(error) if receive_is_permanent(&error) => Err(Refusal::Receive(error).into()),
            Err(error) => Err(Hold::Receive(error).into()),
        }
    }

    /// Sends the S2 stored for `proposal` again, when this wallet received it before. A
    /// different S1 under a slate id received before is refused.
    async fn answer_again(
        &self,
        proposal: &Slate,
        reply_to: &Destination,
    ) -> Result<Option<Handled>, Settlement> {
        let session = self.session().map_err(Hold::from)?;
        let slate_id = proposal.id();
        let stored = self
            .blocking(move |_, _| Ok(session.store.read(|repos| stored_reply(repos, slate_id))?))
            .await
            .map_err(Hold::from)?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let reply = decode_reply(self.config().network, &stored).map_err(Hold::Receive)?;
        if !answers(&reply, proposal) {
            return Err(Refusal::SlateIdReused.into());
        }
        debug!(tx_id = %stored.tx_id, "slate answered again");
        self.reply(reply_to, &WireSlate::binary(MediaType::JSON, stored.bytes))
            .await?;
        Ok(Some(Handled::Repeated))
    }

    async fn reply(&self, to: &Destination, wire: &WireSlate) -> Result<(), Hold> {
        let outbound = self
            .ports()
            .transports
            .get(TRANSPORT_ID)
            .and_then(|transport| transport.outbound())
            .ok_or(Hold::NoOutbound {
                transport: TRANSPORT_ID,
            })?;
        outbound.deliver(to, wire).await.map_err(Hold::Reply)?;
        info!(stage = Stage::S2.as_str(), "slate sent");
        Ok(())
    }

    /// Finalizes an S2 and posts it. A transaction that was finalized but not posted is
    /// settled: it waits in state `finalized` for [`Wallet::post`].
    async fn complete(&self, envelope: &Envelope) -> Result<Handled, Settlement> {
        match self
            .finalize(TRANSPORT_ID, envelope.wire(), POST_PROPAGATION)
            .await
        {
            Ok(_) => Ok(Handled::Finalized),
            Err(FinalizeError::NotPosted { tx_id, source }) => {
                warn!(tx_id = %tx_id, error = %ErrorChain(&source), "finalized transaction not posted");
                Ok(Handled::Finalized)
            }
            Err(error) if finalize_is_permanent(&error) => Err(Refusal::Finalize(error).into()),
            Err(error) => Err(Hold::Finalize(error).into()),
        }
    }

    async fn inbox_write<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut dyn Repositories, jiff::Timestamp) -> Result<T, StoreError>
        + Send
        + 'static,
    ) -> Result<T, WalletError> {
        let session = self.session()?;
        self.blocking(move |ports, _| {
            let now = ports.clock.now();
            session.store.write(|repos| Ok(work(repos, now)?))
        })
        .await
    }
}

/// How a message that was not handled ends: refused for good, or held for redelivery.
enum Settlement {
    Refuse(Refusal),
    Hold(Hold),
}

impl From<Refusal> for Settlement {
    fn from(refusal: Refusal) -> Self {
        Self::Refuse(refusal)
    }
}

impl From<Hold> for Settlement {
    fn from(hold: Hold) -> Self {
        Self::Hold(hold)
    }
}
