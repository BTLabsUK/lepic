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
use crate::client_inbox::{Mode, Subscription};
use crate::crypto::{MessageError, NONCE_LEN, Nonce, SALT_LEN, Salt, SignedMessage};
use crate::frame::{ClientFrame, FrameError, RelayErrorKind, WalletMode};
use crate::prefilter::Prefilter;
use crate::session::{Connection, Connector, ProtocolVersion, RelayEndpoint, deadline_after};

/// The transport id of the Epicbox method.
pub const TRANSPORT_ID: TransportId = TransportId::new("epicbox");

/// What the client was waiting for when the relay went quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Awaiting {
    Connection,
    Challenge,
    Answer,
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("no tokio runtime is running")]
    NoRuntime,
    #[error("epicbox secret key does not belong to the address")]
    IdentityMismatch,
    #[error("could not connect to the relay")]
    Connect(#[source] io::Error),
    #[error("websocket failed")]
    Websocket(#[source] Box<tokio_tungstenite::tungstenite::Error>),
    #[error("relay closed the connection")]
    Closed,
    #[error("relay sent nothing in time while the client waited for {awaiting}")]
    Timeout { awaiting: Awaiting },
    #[error("relay answered with error {kind:?}")]
    Relay { kind: RelayErrorKind },
    #[error("relay speaks protocol {version}, older than the supported baseline")]
    UnsupportedRelayVersion { version: ProtocolVersion },
    #[error("relay frame could not be built")]
    Frame(#[source] FrameError),
    #[error("message could not be sealed")]
    Message(#[source] MessageError),
    #[error("destination is not an epicbox address")]
    Destination(#[source] AddressError),
    #[error("slate is binary, and epicbox carries only text")]
    BinarySlate,
    #[error("operating system randomness is unavailable")]
    Randomness(#[source] getrandom::Error),
    #[error("client is not connected to the relay")]
    NotConnected,
    #[error("subscription has ended")]
    Ended,
    #[error("subscription task failed")]
    Task(#[source] tokio::task::JoinError),
    #[error("message is not handed out by this subscription")]
    NotHandedOut,
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
    pub initial: Duration,
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

/// How the client talks to its relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
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
    pub backoff: Backoff,
    /// The bound of a whole mailbox drain. Mailboxes not reached by then wait for the next one.
    pub drain_timeout: Duration,
}

/// The caller's timeouts and reconnect backoff for a relay client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTimings {
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub ping_interval: Duration,
    pub backoff: Backoff,
    pub drain_timeout: Duration,
}

/// The version the relay is told in `ClientDetails`: what `epic-wallet` `v4.1.0` sends, its own
/// package version. The relay stores it and reads only the wallet mode, so a version of LEPIC's
/// own would only tell the relay, and anyone watching it, which keys run LEPIC.
pub const RELAY_WALLET_VERSION: &str = "4.1.0";

impl ClientSettings {
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

    pub fn address(&self) -> &EpicboxAddress {
        self.context.identity.address()
    }

    pub fn settings(&self) -> &ClientSettings {
        &self.context.settings
    }

    /// Holds a connection, keeps it alive and reconnects after failures until stopped.
    pub fn listen(&self) -> Result<Subscription, ClientError> {
        self.listen_with_held_rounds(None)
    }

    /// As [`Self::listen`], and the listener moves to a fresh socket after `held_rounds` rounds
    /// that began with a message held, counted per socket and not reset by an acknowledgement.
    /// The held message stays held and is taken up again on the new socket. `None` keeps the
    /// socket.
    pub fn listen_with_held_rounds(
        &self,
        held_rounds: Option<u32>,
    ) -> Result<Subscription, ClientError> {
        Subscription::start(Arc::clone(&self.context), Mode::Listen, held_rounds)
    }

    /// Connects once, hands out every pending message, and disconnects when the relay has none
    /// left and every handed-out message was acknowledged. A connection failure ends it.
    pub fn drain(&self) -> Result<Subscription, ClientError> {
        Subscription::start(Arc::clone(&self.context), Mode::Drain, None)
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
}

/// Posts `frame`, a `PostSlate`, on a short connection of its own and waits for the relay's
/// answer.
pub(crate) async fn post_frame(
    context: &ClientContext,
    frame: &ClientFrame,
) -> Result<(), ClientError> {
    let started = Instant::now();
    let settings = &context.settings;
    let mut connection = Connection::open(
        context.connector.as_ref(),
        &settings.endpoint,
        settings.connect_timeout,
    )
    .await?;
    let result = async {
        connection.greet(WalletMode::Send, settings).await?;
        let deadline = deadline_after(settings.response_timeout);
        connection.send_before(frame, deadline).await?;
        connection.answer(deadline).await
    }
    .await;
    connection.close().await;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(()) => debug!(elapsed_ms, "epicbox message posted"),
        Err(error) => warn!(elapsed_ms, error = %ErrorChain(error), "epicbox post failed"),
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
}
