// SPDX-License-Identifier: Apache-2.0
//! Moving an open wallet to another node or Epicbox relay without locking it.
//!
//! A switch takes the session's server gate for writing: the wallet calls running when it
//! starts end first, and calls made after it wait until it is done (`tokio`'s lock is fair, so
//! a stream of new calls cannot hold the switch off). A running scan, which could hold the
//! gate for minutes while every later call queues behind the switch, is cancelled. A running
//! listener moves to a new relay once no message is in hand, so no receive or acknowledgement
//! is cut.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use lepic_epicbox::TRANSPORT_ID;
use lepic_methods::epicbox::{Epicbox, EpicboxPolicy};
use lepic_primitives::params::Network;
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::method::{Carries, EncodeContext, Encoded, Method, SenderFacts, Sending};
use lepic_transport::policy::FormatPolicy;
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport, TransportId};
use lepic_wallet::inbox::ListenHandle;
use lepic_wallet::slate::{DecodeError, Slate, WireSlate};
use tokio::time::timeout;
use tracing::{info, warn};

use super::{Session, epicbox_transport, invalid, lock, relay_endpoint};
use crate::api::error::WalletError;
use crate::api::types::WalletConfig;
use crate::node::NodeSecret;

/// How often a switch waiting for the gate cancels the scan again, for a scan that took the
/// gate just before the switch asked for it and claimed its cancel slot after.
const SCAN_CANCEL_EVERY: Duration = Duration::from_secs(1);

/// How long a listener moving to a new relay may take to settle the message in hand before
/// it is abandoned; an abandoned message stays on the old relay.
const LISTENER_GRACE: Duration = Duration::from_secs(30);

/// How long a node request already on its way when a switch begins may still take before it
/// is cut off: a node that answers answers within it, one that does not would hold the switch
/// for its connect and request timeouts, retries included.
const NODE_CUT_GRACE: Duration = Duration::from_secs(3);

/// The Epicbox transport registered in the engine, whose relay a switch replaces. Clones share
/// it; a delivery goes through the relay set when it starts.
#[derive(Clone)]
pub(crate) struct EpicboxSlot {
    current: Arc<RwLock<Epicbox>>,
    policy: EpicboxPolicy,
}

impl EpicboxSlot {
    pub(crate) fn new(transport: Epicbox) -> Self {
        Self {
            current: Arc::new(RwLock::new(transport)),
            policy: EpicboxPolicy,
        }
    }

    pub(crate) fn current(&self) -> Epicbox {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn replace(&self, transport: Epicbox) -> Epicbox {
        std::mem::replace(
            &mut *self.current.write().unwrap_or_else(PoisonError::into_inner),
            transport,
        )
    }
}

impl Transport for EpicboxSlot {
    fn id(&self) -> TransportId {
        TRANSPORT_ID
    }

    fn policy(&self) -> &dyn FormatPolicy {
        &self.policy
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }
}

impl Method for EpicboxSlot {
    fn carries(&self) -> Carries {
        self.current().carries()
    }

    fn decode(&self, network: Network, wire: &WireSlate) -> Result<Slate, DecodeError> {
        self.current().decode(network, wire)
    }

    fn sender_facts(&self, wire: &WireSlate) -> SenderFacts {
        self.current().sender_facts(wire)
    }

    fn encode_new(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
    ) -> Result<Encoded, FormatError> {
        self.current().encode_new(slate, context, sending)
    }

    fn encode_reply(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
        from: &SenderFacts,
    ) -> Result<Encoded, FormatError> {
        self.current().encode_reply(slate, context, sending, from)
    }

    fn notice_lengths(&self) -> &'static [usize] {
        self.current().notice_lengths()
    }

    fn notice_lengths_for(&self, sending: &Sending) -> &'static [usize] {
        self.current().notice_lengths_for(sending)
    }

    fn peer_key(&self, network: Network, address: &str) -> Result<String, TransportError> {
        self.current().peer_key(network, address)
    }

    fn delivery_is_permanent(&self, error: &TransportError) -> bool {
        self.current().delivery_is_permanent(error)
    }

    fn same_payee(&self, network: Network, to: &Destination, allowed: &str) -> bool {
        self.current().same_payee(network, to, allowed)
    }
}

impl Outbound for EpicboxSlot {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            let transport = self.current();
            Outbound::deliver(&transport, to, wire).await
        })
    }
}

impl Session {
    /// Moves the open wallet to the node and relay `config` names, as described in the
    /// module docs, cancelling a running scan. The data directory and chain must be the
    /// wallet's own. Fails with `InvalidArgument`, changing nothing, for a node URL or relay
    /// that is not one, for another directory or chain, and for a relay given to a wallet
    /// opened without one or none given to a wallet opened with one, or another `offline` than
    /// the wallet's; with `Locked` on a locked wallet.
    pub(crate) async fn set_servers(
        &self,
        config: &WalletConfig,
        node_secret: &NodeSecret,
    ) -> Result<(), WalletError> {
        // A switch that would be refused is refused before anything waits or is cut off.
        self.check_servers(config)?;
        let transport = self.engine.ports().node.transport();
        transport.cut_after(NODE_CUT_GRACE);
        let switched = self.switch_servers(config, node_secret).await;
        if switched.is_err() {
            transport.keep();
        }
        switched
    }

    /// The checks of [`Session::set_servers`] that need no gate.
    fn check_servers(&self, config: &WalletConfig) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        if config.chain.network() != self.network
            || !same_directory(&config.data_dir, &self.data_dir)
        {
            return Err(invalid("servers are switched for the open wallet only"));
        }
        self.ensure_same_offline(config)?;
        lepic_wallet::NodeEndpoint::parse(&config.node_url)
            .map_err(|_| invalid("node url is not an http or https url with a host"))?;
        Ok(())
    }

    async fn switch_servers(
        &self,
        config: &WalletConfig,
        node_secret: &NodeSecret,
    ) -> Result<(), WalletError> {
        let switch = self.servers.write();
        tokio::pin!(switch);
        // The pinned future keeps its place in the lock's queue across the timeouts.
        let _switch = loop {
            self.cancel_scan();
            if let Ok(guard) = timeout(SCAN_CANCEL_EVERY, &mut switch).await {
                break guard;
            }
        };
        // Again under the gate: the wallet may have been locked meanwhile.
        self.check_servers(config)?;
        let node = self.runtime.nodes.backend(
            (config, &self.tuning),
            node_secret,
            &self.node_tor,
            &self.onion_routes,
        )?;
        let relay = self.next_relay(config)?;
        if let Some((slot, transport)) = &relay {
            // Before anything changes, so a refusal leaves the old relay in place.
            transport.attach_wallet(&self.engine)?;
            self.move_listener().await;
            slot.replace(transport.clone()).detach();
            info!(relay = %transport.settings().endpoint.domain(), "epicbox relay switched");
        }
        self.engine.ports().node.transport().replace(node);
        info!(node = %node_host(&config.node_url), "node switched");
        Ok(())
    }

    /// The slot and the transport for the relay `config` names, or `None` when the relay is
    /// the one in use.
    fn next_relay(
        &self,
        config: &WalletConfig,
    ) -> Result<Option<(&EpicboxSlot, Epicbox)>, WalletError> {
        match (&self.epicbox, config.epicbox_domain.is_empty()) {
            (None, true) => Ok(None),
            (None, false) | (Some(_), true) => Err(invalid(
                "epicbox is turned on or off by opening the wallet again",
            )),
            (Some(slot), false) => {
                let endpoint = relay_endpoint(config)?;
                if slot.current().settings().endpoint == endpoint {
                    return Ok(None);
                }
                let transport = epicbox_transport(
                    &self.runtime,
                    (config, &self.tuning),
                    self.network,
                    &self.relay_tor,
                    &self.onion_routes,
                )?
                .ok_or_else(|| invalid("epicbox domain is empty"))?;
                Ok(Some((slot, transport)))
            }
        }
    }

    /// Ends the running listener once no message is in hand, at most [`LISTENER_GRACE`]
    /// later, and leaves the handle it continues with after the switch.
    async fn move_listener(&self) {
        let next = ListenHandle::new();
        let previous = {
            // Under the slot's lock, as a listener that ends reads both under it: it either
            // sees the handle to continue with, or marks its own stopped before this looks.
            let mut slot = lock(&self.listener);
            let running = slot.as_ref().is_some_and(|running| !running.is_stopped());
            if !running {
                return;
            }
            *lock(&self.relisten) = Some(next.clone());
            slot.replace(next)
        };
        let Some(previous) = previous else {
            return;
        };
        previous.finish();
        if timeout(LISTENER_GRACE, self.listen_run.lock())
            .await
            .is_err()
        {
            warn!("epicbox listener did not settle in time, abandoning its message");
            previous.stop();
            drop(self.listen_run.lock().await);
        }
    }

    /// The handle a listener continues with after a switch moved it.
    pub(crate) fn take_relisten(&self) -> Option<ListenHandle> {
        lock(&self.relisten).take()
    }
}

fn same_directory(given: &str, open: &std::path::Path) -> bool {
    std::fs::canonicalize(given).is_ok_and(|given| given == open)
}

/// The host of a node URL, for the log.
fn node_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use lepic_epicbox::mock_relay::MockRelay;
    use lepic_epicbox::testing::client_settings;
    use lepic_epicbox::{ClientError, Domain, Network as RelayNetwork, RelayEndpoint, Security};
    use lepic_transport::marker::v3::carries_lepic_marker;

    use lepic_methods::registry::Methods;

    use lepic_wallet::slate::MediaType;

    use super::*;

    fn epicbox() -> Epicbox {
        let endpoint =
            RelayEndpoint::new(Domain::parse("relay.test").unwrap(), None, Security::Plain);
        Epicbox::new(
            client_settings(endpoint),
            RelayNetwork::Floonet,
            MockRelay::new(RelayNetwork::Floonet).connector(),
        )
    }

    /// The method the engine reaches for `epicbox`, registered as a session registers it.
    fn registered(slot: &EpicboxSlot) -> Arc<dyn Method> {
        let mut methods = Methods::new();
        methods.register(Arc::new(slot.clone())).unwrap();
        Arc::clone(methods.get(TRANSPORT_ID).unwrap())
    }

    fn first_slate(method: &dyn Method) -> Slate {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/vectors/slates/send_file_plain_input_s1_v2.json");
        let vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let json = vector["expected"]["json"].as_str().unwrap().to_owned();
        method
            .decode(Network::Floonet, &WireSlate::text(MediaType::JSON, json))
            .unwrap()
    }

    #[test]
    fn a_send_through_the_registered_method_carries_the_lepic_marker() {
        let slot = EpicboxSlot::new(epicbox());
        let method = registered(&slot);
        let slate = first_slate(&*method);
        let sending = Sending::new(Network::Floonet, 0x0f, None);
        let context = EncodeContext {
            block_header_version: 1,
        };
        let encoded = method.encode_new(&slate, &context, &sending).unwrap();
        assert!(carries_lepic_marker(&encoded.wire));
        assert!(method.sender_facts(&encoded.wire).marked);
        let direct = epicbox().encode_new(&slate, &context, &sending).unwrap();
        assert_eq!(encoded.wire.as_text(), direct.wire.as_text());
    }

    #[test]
    fn the_slot_answers_as_the_epicbox_does() {
        let slot = EpicboxSlot::new(epicbox());
        let epicbox = epicbox();
        let valid = "zzRMBr82zhzvz6hAxJMecEchV4ohxJkrNtDKLqwJMq7EQ4y2ibhQ@epicbox.example:443";
        for address in [valid, "not an address", ""] {
            let from_slot = slot.peer_key(Network::Floonet, address);
            let direct = epicbox.peer_key(Network::Floonet, address);
            assert_eq!(from_slot.is_ok(), direct.is_ok(), "{address}");
            if let (Ok(a), Ok(b)) = (from_slot, direct) {
                assert_eq!(a, b);
            }
        }
        assert!(slot.peer_key(Network::Floonet, valid).is_ok());
        assert!(slot.peer_key(Network::Floonet, "not an address").is_err());
        let errors = [
            TransportError::from(ClientError::BinarySlate),
            TransportError::from(ClientError::Relay {
                kind: lepic_epicbox::RelayErrorKind::InvalidRequest,
            }),
            TransportError::from(ClientError::Relay {
                kind: lepic_epicbox::RelayErrorKind::UnknownError,
            }),
        ];
        for error in &errors {
            assert_eq!(
                slot.delivery_is_permanent(error),
                epicbox.delivery_is_permanent(error)
            );
        }
        assert!(slot.delivery_is_permanent(&errors[0]));
        assert!(!slot.delivery_is_permanent(&errors[2]));
    }
}
