// SPDX-License-Identifier: Apache-2.0
//! The Epicbox method (ADR 0003): its format policy, and the relay client as its outbound
//! side.
//!
//! The transport exists before the wallet is unlocked, because the method registry is built
//! first, while the client needs the wallet's address key. [`Epicbox::attach_wallet`] attaches
//! the wallet's [`Identity`] once it is unlocked and [`Epicbox::detach`] drops it again; clones
//! of a transport share what is attached.

use std::sync::{Arc, PoisonError, RwLock};

use lepic_legacy_slate::marker::v2::MarkedV2JsonCodec;
use lepic_legacy_slate::marker::v3::{
    MarkedV3JsonCodec, carries_lepic_marker, lepic_marker_features, lepic_marker_reply_key,
};
use lepic_legacy_slate::v2_json::LEGACY_V2_JSON;
use lepic_legacy_slate::v2_json::V2JsonCodec;
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_primitives::params::Network as WalletNetwork;
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::stage::Stage;
use lepic_slate::validate::check_size;
use lepic_transport::codecs;
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::method::{Carries, Encoded, Method, SenderFacts, Sending};
use lepic_transport::policy::{Encoding, FormatPolicy, encode_with};
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport, TransportId};

use lepic_epicbox::{
    ClientError, ClientSettings, Connector, EpicboxAddress, EpicboxClient, Identity, Network,
    RelayErrorKind,
};
pub use lepic_epicbox::{RELAY_RETENTION, TRANSPORT_ID};

#[cfg(feature = "epicbox-wallet")]
mod identity;
#[cfg(feature = "epicbox-wallet")]
mod inbox;
#[cfg(feature = "epicbox-wallet")]
mod listing;
mod sessions;

pub use sessions::{
    CONTACTS_OWNER, PAYMENTS_OWNER, PushedConfig, PushedSessions, SessionEvent, SessionInfo,
};

/// The relay network of addresses for a wallet on `network`.
pub fn relay_network(network: WalletNetwork) -> Network {
    match network {
        WalletNetwork::Mainnet => Network::Mainnet,
        WalletNetwork::Floonet => Network::Floonet,
    }
}

/// The lengths a notice over Epicbox is padded to, one drawn at random for each: the JSON
/// length of the first slate of a payment this wallet sends over Epicbox, with one, two and
/// three inputs and one change output, carrying the LEPIC marker with its features.
pub const NOTICE_LENGTHS: [usize; 3] = [
    S1_ONE_INPUT,
    S1_ONE_INPUT + S1_INPUT,
    S1_ONE_INPUT + 2 * S1_INPUT,
];

/// A V2 first slate with one plain input and one change output, as `epic-wallet` writes it
/// (the `send_file_plain_input_s1_v2` vector), plus `,"lepic":{"version":1,"f":15}`.
const S1_ONE_INPUT: usize = 2423 + 29;

/// What one more plain input adds to it: `,{"features":"Plain","commit":"<66 hex>"}`.
const S1_INPUT: usize = 99;

/// The lengths of [`NOTICE_LENGTHS`] when this wallet takes native slates over Epicbox: its
/// first slates then carry the claim marker, `,"lepic":{"version":1,"f":F,"reply":"<64 hex>"}`
/// with `F` from 207 to 255.
pub const NATIVE_NOTICE_LENGTHS: [usize; 3] = [
    NOTICE_LENGTHS[0] + CLAIM_EXTRA,
    NOTICE_LENGTHS[1] + CLAIM_EXTRA,
    NOTICE_LENGTHS[2] + CLAIM_EXTRA,
];

/// What the claim marker adds to `,"lepic":{"version":1,"f":15}`: one more digit of `f` and
/// `,"reply":"<64 hex>"`.
const CLAIM_EXTRA: usize = 1 + 75;

/// The lengths a notice over Epicbox is padded to when the wallet's marker is `sending`'s: those
/// of its first slates, with the claim marker when it claims native slates.
pub const fn notice_lengths_for(sending: &Sending) -> &'static [usize; 3] {
    if sending.seal_key.is_some() {
        &NATIVE_NOTICE_LENGTHS
    } else {
        &NOTICE_LENGTHS
    }
}

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

/// The marked V2 codec of a slate this wallet sends: the marker claims `sending.features`, and
/// carries the key native slates are sealed to when the wallet takes them (RFC 0003 5.15).
fn marked_v2(base_fee: lepic_primitives::amount::Fee, sending: &Sending) -> MarkedV2JsonCodec {
    let codec = MarkedV2JsonCodec::new(V2JsonCodec::new(base_fee));
    match sending.seal_key {
        Some(key) => codec.with_native_claim(sending.features, key),
        None => codec.with_features(sending.features),
    }
}

/// [`marked_v2`] in the V3 shape.
fn marked_v3(base_fee: lepic_primitives::amount::Fee, sending: &Sending) -> MarkedV3JsonCodec {
    let codec = MarkedV3JsonCodec::new(V3JsonCodec::new(base_fee));
    match sending.seal_key {
        Some(key) => codec.with_native_claim(sending.features, key),
        None => codec.with_features(sending.features),
    }
}

/// Why the Epicbox transport could not deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EpicboxTransportError {
    /// A delivery was asked for before an identity was attached.
    #[error("no epicbox identity is attached")]
    NoIdentity,
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
}

impl Method for Epicbox {
    fn carries(&self) -> Carries {
        Carries::default()
    }

    fn sender_facts(&self, wire: &WireSlate) -> SenderFacts {
        SenderFacts::new(
            carries_lepic_marker(wire),
            lepic_marker_features(wire),
            lepic_marker_reply_key(wire),
        )
    }

    fn encode_new(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
    ) -> Result<Encoded, FormatError> {
        let base_fee = sending.network.params().default_base_fee();
        let (encoding, codecs) = match slate.stage() {
            // The marker rides the V2 shape of a new S1, so a reply that keeps it proves the
            // receiver runs LEPIC, and a stock receiver drops it.
            Stage::S1 => (
                self.policy().for_new_slate(slate, context),
                codecs::legacy_with(
                    Box::new(V3JsonCodec::new(base_fee)),
                    Box::new(marked_v2(base_fee, sending)),
                ),
            ),
            // An I1 goes out as V3, which upstream's untagged parse reads first, because the
            // payer's TTL on I2 has no field in V2.
            Stage::I1 => (
                Encoding {
                    codec: LEGACY_V3_JSON,
                    legacy_header: None,
                },
                codecs::legacy_with(
                    Box::new(marked_v3(base_fee, sending)),
                    Box::new(V2JsonCodec::new(base_fee)),
                ),
            ),
            _ => (
                self.policy().for_new_slate(slate, context),
                codecs::legacy(base_fee),
            ),
        };
        let wire = encode_with(&codecs, encoding, slate, context)?;
        Ok(Encoded {
            wire,
            codec: encoding.codec,
        })
    }

    fn encode_reply(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
        from: &SenderFacts,
    ) -> Result<Encoded, FormatError> {
        let base_fee = sending.network.params().default_base_fee();
        let encoding = self.policy().for_reply(slate, context);
        // An I2 answers an invoice, which only LEPIC sends over Epicbox, so its V3 shape always
        // carries the marker. Only a sender that marked its S1 gets a marked S2, so a stock
        // sender never sees the key.
        let codecs = if slate.stage() == Stage::I2 {
            codecs::legacy_with(
                Box::new(marked_v3(base_fee, sending)),
                Box::new(V2JsonCodec::new(base_fee)),
            )
        } else if from.marked {
            codecs::legacy_with(
                Box::new(marked_v3(base_fee, sending)),
                Box::new(marked_v2(base_fee, sending)),
            )
        } else {
            codecs::legacy(base_fee)
        };
        let wire = encode_with(&codecs, encoding, slate, context)?;
        Ok(Encoded {
            wire,
            codec: encoding.codec,
        })
    }

    fn notice_lengths(&self) -> &'static [usize] {
        &NOTICE_LENGTHS
    }

    fn notice_lengths_for(&self, sending: &Sending) -> &'static [usize] {
        notice_lengths_for(sending)
    }

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
                ClientError::Relay { kind } => *kind == RelayErrorKind::InvalidRequest,
                ClientError::Destination(_)
                | ClientError::Message(_)
                | ClientError::Frame(_)
                | ClientError::BinarySlate => true,
                _ => false,
            })
    }
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
}

/// The Epicbox method as notices about its payments see it, for a wallet that may have no
/// relay to reach: the peer keys and notice lengths of [`Epicbox`], with no delivery. A notice
/// another install received over Epicbox and passed on is matched with it, so it is taken
/// whether or not this wallet has a relay.
#[derive(Debug, Clone, Copy)]
pub struct EpicboxNotices {
    network: Network,
}

impl EpicboxNotices {
    /// The Epicbox notices of a wallet on `network`.
    pub fn new(network: WalletNetwork) -> Self {
        Self {
            network: relay_network(network),
        }
    }
}

impl Transport for EpicboxNotices {
    fn id(&self) -> TransportId {
        TRANSPORT_ID
    }

    fn policy(&self) -> &dyn FormatPolicy {
        &EpicboxPolicy
    }
}

impl Method for EpicboxNotices {
    fn carries(&self) -> Carries {
        Carries::default()
    }

    fn notice_lengths(&self) -> &'static [usize] {
        &NOTICE_LENGTHS
    }

    fn notice_lengths_for(&self, sending: &Sending) -> &'static [usize] {
        notice_lengths_for(sending)
    }

    fn peer_key(&self, _network: WalletNetwork, address: &str) -> Result<String, TransportError> {
        key_on(self.network, address)
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

    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_epicbox::{Domain, RelayEndpoint, Security};

    use super::*;

    #[test]
    fn marked_registries_hold_both_shapes_in_detection_order() {
        let fee = lepic_primitives::amount::Fee::new(1_000_000);
        let marked = codecs::legacy_with(
            Box::new(MarkedV3JsonCodec::new(V3JsonCodec::new(fee))),
            Box::new(MarkedV2JsonCodec::new(V2JsonCodec::new(fee))),
        );
        let ids: Vec<_> = marked.ids().collect();
        assert_eq!(ids, [LEGACY_V3_JSON, LEGACY_V2_JSON]);
    }

    #[test]
    fn the_notice_lengths_are_those_of_a_first_slate_with_one_to_three_inputs() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/vectors/slates/send_file_plain_input_s1_v2.json");
        let vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let json = vector["expected"]["json"].as_str().unwrap();
        let marker = r#","lepic":{"version":1,"f":15}"#;
        assert_eq!(NOTICE_LENGTHS[0], json.len() + marker.len());
        let slate: serde_json::Value = serde_json::from_str(json).unwrap();
        let input = &slate["tx"]["body"]["inputs"][0];
        assert_eq!(input["features"], "Plain");
        assert_eq!(serde_json::to_string(input).unwrap().len() + 1, S1_INPUT);
    }

    #[test]
    fn without_a_native_claim_the_notice_lengths_are_unchanged() {
        assert_eq!(NOTICE_LENGTHS, [2452, 2551, 2650]);
        let plain = Sending::new(WalletNetwork::Mainnet, 79, None);
        assert_eq!(notice_lengths_for(&plain), &NOTICE_LENGTHS);
        let transport = transport();
        assert_eq!(transport.notice_lengths_for(&plain), NOTICE_LENGTHS);
        assert_eq!(transport.notice_lengths(), NOTICE_LENGTHS);
    }

    #[test]
    fn with_a_native_claim_the_notice_lengths_carry_the_claim_marker() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/vectors/epicbox/marker_s1_v2_native_claim_207.json");
        let vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let plain = vector["inputs"]["plain_s1"].as_str().unwrap();
        let claimed = vector["expected"]["json"].as_str().unwrap();
        let marker = r#","lepic":{"version":1,"f":15}"#;
        assert_eq!(claimed.len() - plain.len(), marker.len() + CLAIM_EXTRA);

        let native = Sending::new(WalletNetwork::Mainnet, 207, None).with_seal_key([7; 32]);
        assert_eq!(notice_lengths_for(&native), &NATIVE_NOTICE_LENGTHS);
        assert_eq!(
            transport().notice_lengths_for(&native),
            NOTICE_LENGTHS.map(|length| length + CLAIM_EXTRA)
        );
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
}
