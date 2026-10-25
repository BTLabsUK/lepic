//! The Epicbox method as a transport (ADR 0003): its format policy, and the relay client as its
//! outbound side.
//!
//! The transport exists before the wallet is unlocked, because the transport registry is built
//! first, while the client needs the wallet's address key. The engine attaches an [`Identity`]
//! once it has one and detaches it again; clones of a transport share what is attached.

use std::sync::{Arc, PoisonError, RwLock};

use lepic_slate::codec::legacy::v2_json::LEGACY_V2_JSON;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_slate::validate::check_size;
use lepic_transport::error::TransportError;
use lepic_transport::policy::{Encoding, FormatPolicy};
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport, TransportId};

use crate::address::Network;
use crate::client::{ClientSettings, EpicboxClient, Identity, TRANSPORT_ID};
use crate::session::Connector;

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

    fn transport() -> EpicboxTransport {
        let settings = ClientSettings::new(RelayEndpoint::new(
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
