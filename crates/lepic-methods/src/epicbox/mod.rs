// SPDX-License-Identifier: Apache-2.0
//! The Epicbox method (ADR 0003): its format policy, and the relay client as its outbound
//! side.
//!
//! The transport exists before the wallet is unlocked, because the method registry is built
//! first, while the client needs the wallet's address key. [`Epicbox::attach_wallet`] attaches
//! the wallet's [`Identity`] once it is unlocked and [`Epicbox::detach`] drops it again; clones
//! of a transport share what is attached.

use std::sync::{Arc, PoisonError, RwLock};

use lepic_legacy_slate::v2_json::LEGACY_V2_JSON;
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_primitives::params::Network as WalletNetwork;
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::validate::check_size;
use lepic_transport::error::TransportError;
use lepic_transport::method::Method;
use lepic_transport::policy::{Encoding, FormatPolicy};
use lepic_transport::transport::{
    BoxFuture, Destination, Outbound, PostedSize, RelayCancel, RelayCancelOutcome,
    RelayCancelReport, RelayTxId, Transport, TransportId,
};

use tracing::debug;

use lepic_epicbox::sessions::PushedSessions;
use lepic_epicbox::{
    CancelOutcome, ClientError, ClientSettings, Connector, EpicboxAddress, EpicboxClient,
    EpicboxTxId, Identity, InvalidEpicboxTxId, MessageError, MuxCancelOutcome, MuxError, MuxState,
    Network, RELAY_MAX_STR_BYTES, RelayErrorKind, sealed_str_len,
};
pub use lepic_epicbox::{RELAY_RETENTION, TRANSPORT_ID};

#[cfg(feature = "epicbox-wallet")]
mod identity;
#[cfg(feature = "epicbox-wallet")]
mod inbox;
#[cfg(feature = "epicbox-wallet")]
mod listing;

/// The relay network of addresses for a wallet on `network`.
pub fn relay_network(network: WalletNetwork) -> Network {
    match network {
        WalletNetwork::Mainnet => Network::Mainnet,
        WalletNetwork::Floonet => Network::Floonet,
    }
}

/// The lengths a notice is padded to, one drawn at random for each: about the JSON length of a
/// first slate with one, two and three inputs and one change output.
pub const NOTICE_LENGTHS: [usize; 3] = [
    S1_ONE_INPUT,
    S1_ONE_INPUT + S1_INPUT,
    S1_ONE_INPUT + 2 * S1_INPUT,
];

/// A V2 first slate with one plain input and one change output, as `epic-wallet` writes it
/// (the `send_file_plain_input_s1_v2` vector).
const S1_ONE_INPUT: usize = 2423;

/// What one more plain input adds to it: `,{"features":"Plain","commit":"<66 hex>"}`.
const S1_INPUT: usize = 99;

/// The Epicbox policy of ADR 0003, as `epic-wallet` `v4.1.0` speaks it: the V3 and V2 shapes are
/// accepted, detected by shape with V3 tried first and the header ignored; a new slate goes out
/// in the V2 shape with the header of a slate created here; a reply goes out in the shape it
/// answers, with the received header carried through.
#[derive(Debug, Clone, Copy, Default)]
pub struct EpicboxPolicy;

impl EpicboxPolicy {
    const ACCEPTED: [CodecId; 2] = [LEGACY_V3_JSON, LEGACY_V2_JSON];
}

impl FormatPolicy for EpicboxPolicy {
    fn accepted(&self) -> &[CodecId] {
        &Self::ACCEPTED
    }

    fn for_new_slate(&self, _slate: &Slate, _context: &EncodeContext) -> Encoding {
        Encoding {
            codec: LEGACY_V2_JSON,
            legacy_header: None,
        }
    }

    fn for_reply(&self, slate: &Slate, context: &EncodeContext) -> Encoding {
        match slate.origin() {
            Some(origin) if Self::ACCEPTED.contains(&origin.codec()) => Encoding {
                codec: origin.codec(),
                legacy_header: origin.legacy_header(),
            },
            _ => self.for_new_slate(slate, context),
        }
    }

    /// Asks the codecs in the policy's own order, whatever order the registry holds them in,
    /// because upstream's untagged parse tries the V3 shape before the V2 shape.
    fn decode(&self, codecs: &CodecRegistry, wire: &WireSlate) -> Result<Slate, DecodeError> {
        check_size(wire)?;
        Self::ACCEPTED
            .iter()
            .filter_map(|&id| codecs.get(id))
            .find(|codec| codec.detect(wire))
            .ok_or(DecodeError::UnknownFormat)?
            .decode(wire)
    }
}

/// Why the Epicbox transport could not deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EpicboxTransportError {
    /// A delivery was asked for before an identity was attached.
    #[error("no epicbox identity is attached")]
    NoIdentity,
    /// A relay transaction id that is not an Epicbox transaction id.
    #[error("relay transaction id is not an epicbox transaction id")]
    InvalidTxId(#[source] InvalidEpicboxTxId),
    /// The system gave no randomness for a new transaction id.
    #[error("no randomness for a new epicbox transaction id")]
    Randomness,
}

impl From<EpicboxTransportError> for TransportError {
    fn from(error: EpicboxTransportError) -> Self {
        Self::Backend {
            transport: TRANSPORT_ID,
            source: Box::new(error),
        }
    }
}

/// The Epicbox method: [`EpicboxPolicy`], and delivery through the client of the attached
/// identity. Receiving is not an [`lepic_transport::transport::Inbound`] capability here:
/// [`Epicbox::drain`] and [`Epicbox::listen`] start a subscription from the attached client,
/// which also hands out the messages that could not be opened, and hand each message to the
/// engine.
#[derive(Clone)]
pub struct Epicbox {
    inner: Arc<Inner>,
}

struct Inner {
    settings: ClientSettings,
    network: Network,
    connector: Arc<dyn Connector>,
    policy: EpicboxPolicy,
    client: RwLock<Option<EpicboxClient>>,
    pushed: PushedSessions,
}

impl Epicbox {
    /// A transport for addresses on `network` that talks to the relay in `settings`, with no
    /// identity attached.
    pub fn new(settings: ClientSettings, network: Network, connector: Arc<dyn Connector>) -> Self {
        Self {
            inner: Arc::new(Inner {
                settings,
                network,
                connector,
                policy: EpicboxPolicy,
                client: RwLock::new(None),
                pushed: PushedSessions::default(),
            }),
        }
    }

    /// The client settings of the relay this transport talks to.
    pub fn settings(&self) -> &ClientSettings {
        &self.inner.settings
    }

    /// The mux/1 sessions of this transport, shared by its clones.
    pub fn pushed(&self) -> &PushedSessions {
        &self.inner.pushed
    }

    /// The relay network the addresses of this transport are read on.
    pub fn network(&self) -> Network {
        self.inner.network
    }

    /// The connector this transport dials its relay with, so a [`lepic_epicbox::MailboxClient`] for
    /// another relay takes the same way, through tor when relay traffic goes through it.
    pub fn connector(&self) -> Arc<dyn Connector> {
        Arc::clone(&self.inner.connector)
    }

    /// Replaces the attached identity and returns the client that now speaks for it.
    pub fn attach(&self, identity: Identity) -> EpicboxClient {
        let client = self.client_for(identity);
        *self
            .inner
            .client
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(client.clone());
        client
    }

    /// A client for another address of this wallet, on this transport's relay, that is not
    /// attached: deliveries through the transport keep using the attached identity.
    pub fn client_for(&self, identity: Identity) -> EpicboxClient {
        EpicboxClient::new(
            self.inner.settings.clone(),
            identity,
            Arc::clone(&self.inner.connector),
        )
    }

    /// Drops the attached identity. Subscriptions already started keep theirs until they end.
    pub fn detach(&self) {
        *self
            .inner
            .client
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The client of the attached identity.
    pub fn client(&self) -> Option<EpicboxClient> {
        self.inner
            .client
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl std::fmt::Debug for Epicbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Epicbox")
            .field("relay", self.inner.settings.endpoint.domain())
            .field("network", &self.inner.network)
            .field("attached", &self.client().is_some())
            .finish_non_exhaustive()
    }
}

impl Transport for Epicbox {
    fn id(&self) -> TransportId {
        TRANSPORT_ID
    }

    fn policy(&self) -> &dyn FormatPolicy {
        &self.inner.policy
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }

    fn relay_cancel(&self) -> Option<&dyn RelayCancel> {
        Some(self)
    }
}

impl Method for Epicbox {
    fn peer_key(&self, _network: WalletNetwork, address: &str) -> Result<String, TransportError> {
        // The addresses are read on the relay network the transport was built for, so the
        // wallet network the engine passes is not used.
        key_on(self.network(), address)
    }

    fn delivery_is_permanent(&self, error: &TransportError) -> bool {
        let TransportError::Backend { source, .. } = error else {
            return false;
        };
        source
            .downcast_ref::<ClientError>()
            .is_some_and(|error| match error {
                ClientError::Relay { kind } | ClientError::PostRefused { kind, .. } => {
                    *kind == RelayErrorKind::InvalidRequest
                }
                ClientError::Destination(_)
                | ClientError::Message(_)
                | ClientError::Frame(_)
                | ClientError::BinarySlate => true,
                _ => false,
            })
    }

    fn delivery_cancelled_on_relay(&self, error: &TransportError) -> bool {
        let TransportError::Backend { source, .. } = error else {
            return false;
        };
        matches!(
            source.downcast_ref::<ClientError>(),
            Some(ClientError::TransactionCancelled { .. })
        )
    }
}

/// The Epicbox transaction id a relay transaction id names.
fn epicbox_txid(txid: &RelayTxId) -> Result<EpicboxTxId, EpicboxTransportError> {
    EpicboxTxId::parse(txid.as_str()).map_err(EpicboxTransportError::InvalidTxId)
}

/// The relay transaction id of an Epicbox transaction id.
pub(crate) fn relay_txid(txid: &EpicboxTxId) -> RelayTxId {
    RelayTxId::new(txid.as_str().to_owned())
}

impl Outbound for Epicbox {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let client = self.client().ok_or(EpicboxTransportError::NoIdentity)?;
            client.deliver(to, wire).await
        })
    }

    fn new_relay_txid(&self) -> Result<Option<RelayTxId>, TransportError> {
        let txid = EpicboxTxId::generate().map_err(|_| EpicboxTransportError::Randomness)?;
        Ok(Some(relay_txid(&txid)))
    }

    /// Posts with the transaction id to a relay of 3.1.0 or later, and without it to an older
    /// one. A relay that holds a cancellation of the transaction refuses the post with
    /// [`ClientError::TransactionCancelled`].
    fn deliver_tx<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
        txid: Option<&'a RelayTxId>,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let client = self.client().ok_or(EpicboxTransportError::NoIdentity)?;
            let Some(txid) = txid else {
                return client.deliver(to, wire).await;
            };
            let txid = epicbox_txid(txid)?;
            let to = EpicboxAddress::parse(to.as_str(), client.address().network())
                .map_err(ClientError::Destination)?;
            let plaintext = wire.as_text().ok_or(ClientError::BinarySlate)?;
            let receipt = client.post_tx(&to, plaintext, &txid).await?;
            #[cfg(feature = "epicbox-wallet")]
            debug!(txid_sent = receipt.txid_sent, "epicbox transaction posted");
            #[cfg(not(feature = "epicbox-wallet"))]
            let _ = receipt;
            Ok(())
        })
    }

    /// The `str` the relay gets for the text sealed to `to`. `None` without an identity or for
    /// an address that is not an Epicbox one on this relay network.
    fn posted_size(&self, to: &Destination, len: usize) -> Option<PostedSize> {
        let client = self.client()?;
        let to = EpicboxAddress::parse(to.as_str(), client.address().network()).ok()?;
        Some(str_size(len, &to))
    }

    /// The `str` the relay gets for the text sealed to the attached identity's address.
    fn reply_size(&self, len: usize) -> Option<PostedSize> {
        let client = self.client()?;
        Some(str_size(len, client.address()))
    }
}

/// The size of the `str` that carries a text of `len` bytes to `to`, against the relay's
/// limit. A text over the bound LEPIC reads counts its encrypted hex alone, already over the
/// limit.
fn str_size(len: usize, to: &EpicboxAddress) -> PostedSize {
    let bytes = match sealed_str_len(len, to) {
        Ok(bytes) => bytes,
        Err(MessageError::TooLong { actual, .. }) => actual.saturating_mul(2),
        Err(_) => usize::MAX,
    };
    PostedSize {
        bytes,
        limit: RELAY_MAX_STR_BYTES,
    }
}

/// Cancels on the relay of the attached identity: over a mux/1 session on that relay whose
/// socket negotiated `txcancel/1`, and on a short classic connection of its own when there is
/// none (no session, the relay does not offer `txcancel/1`, or the socket is not up).
impl RelayCancel for Epicbox {
    fn cancel_on_relay<'a>(
        &'a self,
        txid: &'a RelayTxId,
    ) -> BoxFuture<'a, Result<RelayCancelReport, TransportError>> {
        Box::pin(async move {
            let client = self.client().ok_or(EpicboxTransportError::NoIdentity)?;
            let txid = epicbox_txid(txid)?;
            if let Some(report) = self.cancel_on_session(&client, &txid).await? {
                return Ok(report);
            }
            debug!(via = "socket", "epicbox cancel");
            let report = client.cancel(&txid).await?;
            let outcome = match report.outcome {
                CancelOutcome::Cancelled => RelayCancelOutcome::Cancelled,
                CancelOutcome::NotFoundOrNotParticipant => {
                    RelayCancelOutcome::NotFoundOrNotParticipant
                }
                // `Unsupported`, and any outcome a later client adds: nothing was cancelled.
                _ => RelayCancelOutcome::Unsupported,
            };
            let other = report.other_cancelled.iter().map(relay_txid).collect();
            Ok(RelayCancelReport::new(outcome, other))
        })
    }
}

impl Epicbox {
    /// Cancels `txid` over an attached mux/1 session on this transport's relay. `None` when no
    /// session could carry it: there is none, its socket did not negotiate `txcancel/1`, or the
    /// socket was lost before the answer (a repeat is safe, so the caller cancels on a socket).
    /// A cancellation the other party made reaches the session's consumer as a pushed event,
    /// so the report lists none.
    async fn cancel_on_session(
        &self,
        client: &EpicboxClient,
        txid: &EpicboxTxId,
    ) -> Result<Option<RelayCancelReport>, TransportError> {
        let endpoint = &self.inner.settings.endpoint;
        let relay = format!("{}:{}", endpoint.domain(), endpoint.port());
        for session in self.pushed().on_relay(&relay) {
            if *session.state().borrow() != MuxState::Attached {
                continue;
            }
            let outcome = match client.cancel_on_session(&session, txid).await {
                Ok(MuxCancelOutcome::Cancelled) => RelayCancelOutcome::Cancelled,
                Ok(MuxCancelOutcome::NotFoundOrNotParticipant) => {
                    RelayCancelOutcome::NotFoundOrNotParticipant
                }
                // The relay does not offer `txcancel/1`; its other sessions would not either.
                Ok(_) => return Ok(None),
                Err(error @ MuxError::Refused { .. }) => {
                    return Err(TransportError::Backend {
                        transport: TRANSPORT_ID,
                        source: Box::new(error),
                    });
                }
                // No socket, or it ended before the answer: try the next session.
                Err(_) => continue,
            };
            debug!(via = "mux", outcome = ?outcome, "epicbox cancel finished");
            return Ok(Some(RelayCancelReport::new(outcome, Vec::new())));
        }
        Ok(None)
    }
}

/// The key under which the engine stores what it knows of `address`, an Epicbox address of the
/// relay network of the wallet's `network`, as [`Method::peer_key`] of the Epicbox method gives
/// it. Fails with [`TransportError::InvalidDestination`] for an address that does not parse.
pub fn peer_key(network: WalletNetwork, address: &str) -> Result<String, TransportError> {
    key_on(relay_network(network), address)
}

fn key_on(network: Network, address: &str) -> Result<String, TransportError> {
    EpicboxAddress::parse_key(address, network)
        .map(|key| EpicboxAddress::key_text_of(&key, network))
        .map_err(|error| TransportError::InvalidDestination {
            transport: TRANSPORT_ID,
            source: Box::new(error),
        })
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use lepic_crypto::{PublicKey, SecretKey};
    use lepic_slate::codec::MediaType;

    use std::time::Duration;

    use lepic_epicbox::mock_mux::MuxMockRelay;
    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_epicbox::sessions::Owner;
    use lepic_epicbox::{
        Domain, MuxCode, MuxOptions, MuxSession, Nonce, RelayEndpoint, Salt, Security,
        SignedMessage,
    };

    use super::*;

    #[test]
    fn the_notice_lengths_are_those_of_a_first_slate_with_one_to_three_inputs() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/vectors/slates/send_file_plain_input_s1_v2.json");
        let vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let json = vector["expected"]["json"].as_str().unwrap();
        assert_eq!(NOTICE_LENGTHS, [2423, 2522, 2621]);
        assert_eq!(NOTICE_LENGTHS[0], json.len());
        let slate: serde_json::Value = serde_json::from_str(json).unwrap();
        let input = &slate["tx"]["body"]["inputs"][0];
        assert_eq!(input["features"], "Plain");
        assert_eq!(serde_json::to_string(input).unwrap().len() + 1, S1_INPUT);
    }

    fn transport() -> Epicbox {
        let settings = lepic_epicbox::testing::client_settings(RelayEndpoint::new(
            Domain::parse("relay.test").unwrap(),
            None,
            Security::Plain,
        ));
        let relay = MockRelay::new(Network::Mainnet);
        Epicbox::new(settings, Network::Mainnet, relay.connector())
    }

    fn identity() -> Identity {
        let secret = SecretKey::from_array([1; 32]).unwrap();
        let address = EpicboxAddress::new(
            PublicKey::from_secret_key(&secret).unwrap(),
            Network::Mainnet,
            Domain::parse("relay.test").unwrap(),
            None,
        );
        Identity::new(secret, address).unwrap()
    }

    #[tokio::test]
    async fn delivery_without_an_attached_identity_is_a_typed_error() {
        let transport = transport();
        let wire = WireSlate::text(MediaType::JSON, "{}".to_owned());
        let error = transport
            .deliver(&Destination::new(String::new()), &wire)
            .await
            .unwrap_err();
        let TransportError::Backend {
            transport: id,
            source,
        } = error
        else {
            panic!("unexpected error {error:?}");
        };
        assert_eq!(id, TRANSPORT_ID);
        assert_eq!(
            source.downcast_ref::<EpicboxTransportError>(),
            Some(&EpicboxTransportError::NoIdentity)
        );
    }

    #[test]
    fn a_client_for_another_identity_leaves_the_attached_one() {
        let transport = transport();
        let attached = transport.attach(identity());
        let secret = SecretKey::from_array([2; 32]).unwrap();
        let address = EpicboxAddress::new(
            PublicKey::from_secret_key(&secret).unwrap(),
            Network::Mainnet,
            Domain::parse("relay.test").unwrap(),
            None,
        );
        let other = transport.client_for(Identity::new(secret, address.clone()).unwrap());
        assert_eq!(other.address(), &address);
        assert_eq!(transport.client().unwrap().address(), attached.address());
    }

    #[test]
    fn clones_share_the_attached_identity_until_it_is_detached() {
        let transport = transport();
        let registered = transport.clone();
        let client = transport.attach(identity());
        assert_eq!(registered.client().unwrap().address(), client.address());
        registered.detach();
        assert!(transport.client().is_none());
    }

    const TXID: &str = "0123456789ab4def8123456789abcdef";

    fn other_identity() -> Identity {
        let secret = SecretKey::from_array([2; 32]).unwrap();
        let address = EpicboxAddress::new(
            PublicKey::from_secret_key(&secret).unwrap(),
            Network::Mainnet,
            Domain::parse("relay.test").unwrap(),
            None,
        );
        Identity::new(secret, address).unwrap()
    }

    fn message_to(to: &Identity) -> SignedMessage {
        let secret = SecretKey::from_array([1; 32]).unwrap();
        SignedMessage::seal(
            "{}",
            to.address(),
            &secret,
            Salt::from([4; 8]),
            Nonce::from([5; 12]),
        )
        .unwrap()
    }

    async fn until(condition: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("timed out");
    }

    /// A transport whose short connections reach `classic`, with `identity()` attached and the
    /// transaction [`TXID`] known to both relays, sent by it to [`other_identity`].
    fn cancel_rig() -> (Epicbox, MockRelay, MuxMockRelay) {
        let settings = lepic_epicbox::testing::client_settings(RelayEndpoint::new(
            Domain::parse("relay.test").unwrap(),
            None,
            Security::Plain,
        ));
        let classic = MockRelay::new(Network::Mainnet);
        classic.set_version(Some("3.1.0"));
        let mux = MuxMockRelay::new(Network::Mainnet);
        let transport = Epicbox::new(settings, Network::Mainnet, classic.connector());
        transport.attach(identity());
        let (sender, receiver) = (identity(), other_identity());
        let message = message_to(&receiver);
        classic.store_with_txid(sender.address(), receiver.address(), &message, TXID);
        mux.store_with_txid(sender.address(), receiver.address(), &message, TXID);
        (transport, classic, mux)
    }

    /// Starts a mux session to `mux` in `transport`'s registry, as the payments listener does,
    /// and waits for it to attach.
    async fn start_session(transport: &Epicbox, mux: &MuxMockRelay) -> Arc<MuxSession> {
        let settings = transport.inner.settings.clone();
        let endpoint = &settings.endpoint;
        let relay = format!("{}:{}", endpoint.domain(), endpoint.port());
        let connector = mux.connector();
        let session = transport
            .pushed()
            .get_or_start(&relay, "payments", Owner::Payments, || {
                MuxSession::start_queued(
                    settings.clone(),
                    connector,
                    vec![identity()],
                    MuxOptions::default(),
                )
            })
            .unwrap();
        until(|| *session.state().borrow() == MuxState::Attached).await;
        session
    }

    #[tokio::test]
    async fn a_cancel_goes_over_a_session_that_negotiated_txcancel() {
        let (transport, classic, mux) = cancel_rig();
        let _session = start_session(&transport, &mux).await;
        assert!(mux.cancel_negotiated());

        let report = transport
            .cancel_on_relay(&RelayTxId::new(TXID.to_owned()))
            .await
            .unwrap();
        assert_eq!(report.outcome, RelayCancelOutcome::Cancelled);
        assert!(report.other_cancelled.is_empty());
        assert_eq!(mux.received("CancelTx"), 1);
        assert_eq!(classic.connections_made(), 0, "no short connection");
        assert!(!classic.is_cancelled(TXID));
    }

    #[tokio::test]
    async fn an_unknown_transaction_over_a_session_is_reported_as_not_found() {
        let (transport, classic, mux) = cancel_rig();
        let _session = start_session(&transport, &mux).await;

        let unknown = "fedcba9876544321a123456789abcdef";
        let report = transport
            .cancel_on_relay(&RelayTxId::new(unknown.to_owned()))
            .await
            .unwrap();
        assert_eq!(report.outcome, RelayCancelOutcome::NotFoundOrNotParticipant);
        assert_eq!(classic.connections_made(), 0);
    }

    #[tokio::test]
    async fn a_relay_without_txcancel_is_cancelled_on_a_short_connection() {
        let (transport, classic, mux) = cancel_rig();
        mux.offer_cancel(false);
        let _session = start_session(&transport, &mux).await;
        assert!(!mux.cancel_negotiated());

        let report = transport
            .cancel_on_relay(&RelayTxId::new(TXID.to_owned()))
            .await
            .unwrap();
        assert_eq!(report.outcome, RelayCancelOutcome::Cancelled);
        assert_eq!(mux.received("CancelTx"), 0, "nothing sent over mux");
        assert_eq!(classic.received("CancelTx"), 1);
        assert!(classic.is_cancelled(TXID));
    }

    #[tokio::test]
    async fn without_a_session_the_cancel_uses_a_short_connection() {
        let (transport, classic, _mux) = cancel_rig();

        let report = transport
            .cancel_on_relay(&RelayTxId::new(TXID.to_owned()))
            .await
            .unwrap();
        assert_eq!(report.outcome, RelayCancelOutcome::Cancelled);
        assert_eq!(classic.received("CancelTx"), 1);
        assert!(classic.is_cancelled(TXID));
    }

    #[tokio::test]
    async fn a_session_that_is_not_attached_leaves_the_cancel_to_a_short_connection() {
        let (transport, classic, mux) = cancel_rig();
        mux.offer_mux(false);
        let settings = transport.inner.settings.clone();
        let endpoint = &settings.endpoint;
        let relay = format!("{}:{}", endpoint.domain(), endpoint.port());
        let connector = mux.connector();
        let session = transport
            .pushed()
            .get_or_start(&relay, "payments", Owner::Payments, || {
                MuxSession::start_queued(
                    settings.clone(),
                    connector,
                    vec![identity()],
                    MuxOptions::default(),
                )
            })
            .unwrap();
        until(|| *session.state().borrow() == MuxState::NotOffered).await;

        let report = transport
            .cancel_on_relay(&RelayTxId::new(TXID.to_owned()))
            .await
            .unwrap();
        assert_eq!(report.outcome, RelayCancelOutcome::Cancelled);
        assert_eq!(mux.received("CancelTx"), 0);
        assert_eq!(classic.received("CancelTx"), 1);
    }

    #[tokio::test]
    async fn a_cancel_the_relay_refuses_over_a_session_is_an_error_without_a_retry() {
        let (transport, classic, mux) = cancel_rig();
        mux.set_cancel_error(Some("bad_signature"));
        let _session = start_session(&transport, &mux).await;

        let error = transport
            .cancel_on_relay(&RelayTxId::new(TXID.to_owned()))
            .await
            .unwrap_err();
        let TransportError::Backend { source, .. } = error else {
            panic!("unexpected error {error:?}");
        };
        assert!(matches!(
            source.downcast_ref::<MuxError>(),
            Some(MuxError::Refused {
                code: Some(MuxCode::BadSignature)
            })
        ));
        assert_eq!(classic.connections_made(), 0, "not repeated on a socket");
    }

    #[test]
    fn the_posted_size_is_the_length_of_the_sealed_str() {
        let transport = transport();
        let to = other_identity();
        let destination = Destination::new(to.address().to_string());
        assert_eq!(transport.posted_size(&destination, 10), None, "no identity");
        assert_eq!(transport.reply_size(10), None, "no identity");
        transport.attach(identity());
        let secret = SecretKey::from_array([1; 32]).unwrap();
        for text in ["{}", &"x".repeat(5_000)] {
            let sealed = |to: &EpicboxAddress| {
                SignedMessage::seal(text, to, &secret, Salt::from([4; 8]), Nonce::from([5; 12]))
                    .unwrap()
            };
            let posted = transport.posted_size(&destination, text.len()).unwrap();
            assert_eq!(posted.bytes, sealed(to.address()).str.len());
            assert_eq!(posted.limit, RELAY_MAX_STR_BYTES);
            let reply = transport.reply_size(text.len()).unwrap();
            assert_eq!(reply.bytes, sealed(identity().address()).str.len());
        }
        let over = transport.reply_size(RELAY_MAX_STR_BYTES).unwrap();
        assert!(!over.fits());
        assert_eq!(
            transport.posted_size(&Destination::new("not an address".to_owned()), 10),
            None
        );
    }

    #[tokio::test]
    async fn a_reply_at_the_relay_limit_is_posted_and_a_longer_one_fails_for_good_unsent() {
        let settings = lepic_epicbox::testing::client_settings(RelayEndpoint::new(
            Domain::parse("relay.test").unwrap(),
            None,
            Security::Plain,
        ));
        let relay = MockRelay::new(Network::Mainnet);
        let transport = Epicbox::new(settings, Network::Mainnet, relay.connector());
        transport.attach(identity());
        let to = other_identity();
        let destination = Destination::new(to.address().to_string());
        // Two hex digits a byte: the sealed text grows by two for each byte of the reply.
        let empty = sealed_str_len(0, to.address()).unwrap();
        let longest = (RELAY_MAX_STR_BYTES - empty) / 2;
        assert!(sealed_str_len(longest, to.address()).unwrap() <= RELAY_MAX_STR_BYTES);
        assert!(sealed_str_len(longest + 1, to.address()).unwrap() > RELAY_MAX_STR_BYTES);

        let fits = WireSlate::text(MediaType::JSON, "a".repeat(longest));
        transport.deliver(&destination, &fits).await.unwrap();
        assert_eq!(relay.received("PostSlate"), 1);

        let over = WireSlate::text(MediaType::JSON, "a".repeat(longest + 1));
        let error = transport.deliver(&destination, &over).await.unwrap_err();
        assert!(transport.delivery_is_permanent(&error), "{error:?}");
        let TransportError::Backend { source, .. } = &error else {
            panic!("unexpected error {error:?}");
        };
        assert!(matches!(
            source.downcast_ref::<ClientError>(),
            Some(ClientError::Message(MessageError::OverRelayLimit { bytes, limit }))
                if *bytes == sealed_str_len(longest + 1, to.address()).unwrap()
                    && *limit == RELAY_MAX_STR_BYTES
        ));
        let error = transport
            .deliver_tx(&destination, &over, None)
            .await
            .unwrap_err();
        assert!(transport.delivery_is_permanent(&error), "{error:?}");
        assert_eq!(relay.received("PostSlate"), 1, "nothing more posted");
    }

    #[tokio::test]
    async fn a_post_answered_busy_is_not_a_permanent_failure() {
        let settings = lepic_epicbox::testing::client_settings(RelayEndpoint::new(
            Domain::parse("relay.test").unwrap(),
            None,
            Security::Plain,
        ));
        let relay = MockRelay::new(Network::Mainnet);
        relay.set_busy(true);
        let transport = Epicbox::new(settings, Network::Mainnet, relay.connector());
        transport.attach(identity());
        let destination = Destination::new(other_identity().address().to_string());
        let wire = WireSlate::text(MediaType::JSON, "a".to_owned());
        let error = transport.deliver(&destination, &wire).await.unwrap_err();
        assert!(!transport.delivery_is_permanent(&error), "{error:?}");
        assert_eq!(relay.received("PostSlate"), 1);
    }
}
