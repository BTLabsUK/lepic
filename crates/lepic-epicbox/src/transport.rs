// SPDX-License-Identifier: Apache-2.0
//! The Epicbox method as a transport (ADR 0003): its format policy, and the relay client as its
//! outbound side.
//!
//! The transport exists before the wallet is unlocked, because the transport registry is built
//! first, while the client needs the wallet's address key. The engine attaches an [`Identity`]
//! once it has one and detaches it again; clones of a transport share what is attached.

use std::sync::{Arc, PoisonError, RwLock};

use lepic_primitives::params::Network as WalletNetwork;
use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
use lepic_slate::codec::legacy::v2_json::V2JsonCodec;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::stage::Stage;
use lepic_slate::validate::check_size;
use lepic_transport::codecs;
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::marker::v2::MarkedV2JsonCodec;
use lepic_transport::marker::v3::{
    MarkedV3JsonCodec, carries_lepic_marker, lepic_marker_features, lepic_marker_reply_key,
};
use lepic_transport::method::{Carries, Encoded, Method, SenderFacts, Sending};
use lepic_transport::policy::{Encoding, FormatPolicy, encode_with};
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport, TransportId};

use crate::address::{EpicboxAddress, Network};
use crate::client::{ClientSettings, EpicboxClient, Identity, TRANSPORT_ID};
use crate::session::Connector;
use crate::{ClientError, RelayErrorKind};

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

/// The Epicbox policy of ADR 0003, as `epic-wallet` `v4.0.2` speaks it: the V3 and V2 shapes are
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
/// identity. Receiving is not an [`lepic_transport::transport::Inbound`] capability here: the
/// engine starts a listen or drain subscription from [`EpicboxTransport::client`], which also
/// hands out the messages that could not be opened.
#[derive(Clone)]
pub struct EpicboxTransport {
    inner: Arc<Inner>,
}

struct Inner {
    settings: ClientSettings,
    network: Network,
    connector: Arc<dyn Connector>,
    policy: EpicboxPolicy,
    client: RwLock<Option<EpicboxClient>>,
}

impl EpicboxTransport {
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
            }),
        }
    }

    pub fn settings(&self) -> &ClientSettings {
        &self.inner.settings
    }

    pub fn network(&self) -> Network {
        self.inner.network
    }

    /// The connector this transport dials its relay with, so a [`crate::MailboxClient`] for
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

impl std::fmt::Debug for EpicboxTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpicboxTransport")
            .field("relay", self.inner.settings.endpoint.domain())
            .field("network", &self.inner.network)
            .field("attached", &self.client().is_some())
            .finish_non_exhaustive()
    }
}

impl Transport for EpicboxTransport {
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

impl Method for EpicboxTransport {
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
                    Box::new(
                        MarkedV2JsonCodec::new(V2JsonCodec::new(base_fee))
                            .with_features(sending.features),
                    ),
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
                    Box::new(
                        MarkedV3JsonCodec::new(V3JsonCodec::new(base_fee))
                            .with_features(sending.features),
                    ),
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
                Box::new(
                    MarkedV3JsonCodec::new(V3JsonCodec::new(base_fee))
                        .with_features(sending.features),
                ),
                Box::new(V2JsonCodec::new(base_fee)),
            )
        } else if from.marked {
            codecs::legacy_with(
                Box::new(
                    MarkedV3JsonCodec::new(V3JsonCodec::new(base_fee))
                        .with_features(sending.features),
                ),
                Box::new(
                    MarkedV2JsonCodec::new(V2JsonCodec::new(base_fee))
                        .with_features(sending.features),
                ),
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

    fn peer_key(&self, _network: WalletNetwork, address: &str) -> Result<String, TransportError> {
        // The addresses are read on the relay network the transport was built for, so the
        // wallet network the engine passes is not used.
        EpicboxAddress::parse_key(address, self.network())
            .map(|key| EpicboxAddress::key_text_of(&key, self.network()))
            .map_err(|error| TransportError::InvalidDestination {
                transport: TRANSPORT_ID,
                source: Box::new(error),
            })
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

impl Outbound for EpicboxTransport {
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

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use lepic_crypto::{PublicKey, SecretKey};
    use lepic_slate::codec::MediaType;

    use super::*;
    use crate::address::{Domain, EpicboxAddress};
    use crate::mock_relay::MockRelay;
    use crate::session::{RelayEndpoint, Security};

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

    fn transport() -> EpicboxTransport {
        let settings = crate::testing::client_settings(RelayEndpoint::new(
            Domain::parse("relay.test").unwrap(),
            None,
            Security::Plain,
        ));
        let relay = MockRelay::new(Network::Mainnet);
        EpicboxTransport::new(settings, Network::Mainnet, relay.connector())
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
