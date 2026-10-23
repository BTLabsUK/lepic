//! Moving an open wallet to another node or Epicbox relay without locking it.
//!
//! A switch takes the session's server gate for writing: the wallet calls running when it
//! starts end first, and calls made after it wait until it is done (`tokio`'s lock is fair, so
//! a stream of new calls cannot hold the switch off). A running listener moves to a new relay
//! once no message is in hand, so no receive or acknowledgement is cut.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use lepic_epicbox::TRANSPORT_ID;
use lepic_epicbox::transport::{EpicboxPolicy, EpicboxTransport};
use lepic_transport::error::TransportError;
use lepic_transport::policy::FormatPolicy;
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport, TransportId};
use lepic_wallet::inbox::ListenHandle;
use lepic_wallet::slate::WireSlate;
use tokio::time::timeout;
use tracing::{info, warn};

use super::{Session, epicbox_transport, invalid, lock, relay_endpoint};
use crate::api::error::WalletError;
use crate::api::types::WalletConfig;
use crate::node::NodeSecret;

/// How long a listener moving to a new relay may take to settle the message in hand before
/// it is abandoned; an abandoned message stays on the old relay.
const LISTENER_GRACE: Duration = Duration::from_secs(30);

/// The Epicbox transport registered in the engine, whose relay a switch replaces. Clones share
/// it; a delivery goes through the relay set when it starts.
#[derive(Clone)]
pub(crate) struct EpicboxSlot {
    current: Arc<RwLock<EpicboxTransport>>,
    policy: EpicboxPolicy,
}

impl EpicboxSlot {
    pub(crate) fn new(transport: EpicboxTransport) -> Self {
        Self {
            current: Arc::new(RwLock::new(transport)),
            policy: EpicboxPolicy,
        }
    }

    pub(crate) fn current(&self) -> EpicboxTransport {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn replace(&self, transport: EpicboxTransport) -> EpicboxTransport {
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
    /// module docs. The data directory and chain must be the wallet's own. Fails with
    /// `InvalidArgument`, changing nothing, for a node URL or relay that is not one, for
    /// another directory or chain, and for a relay given to a wallet opened without one or
    /// none given to a wallet opened with one; with `Locked` on a locked wallet.
    pub(crate) async fn set_servers(
        &self,
        config: &WalletConfig,
        node_secret: &NodeSecret,
    ) -> Result<(), WalletError> {
        let _switch = self.servers.write().await;
        self.ensure_unlocked()?;
        if config.chain.network() != self.network
            || !same_directory(&config.data_dir, &self.data_dir)
        {
            return Err(invalid("servers are switched for the open wallet only"));
        }
        lepic_wallet::NodeEndpoint::parse(&config.node_url)
            .map_err(|_| invalid("node url is not an http or https url with a host"))?;
        let node = self.runtime.nodes.backend(config, node_secret)?;
        let relay = self.next_relay(config)?;
        if let Some((slot, transport)) = &relay {
            // Before anything changes, so a refusal leaves the old relay in place.
            self.engine.epicbox_attach(transport)?;
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
    ) -> Result<Option<(&EpicboxSlot, EpicboxTransport)>, WalletError> {
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
                let transport =
                    epicbox_transport(&self.runtime, config, self.network, &self.relay_tor)?
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
