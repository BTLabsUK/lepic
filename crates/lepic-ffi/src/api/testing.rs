//! Test support for the Dart package tests: an in-process scripted node and Epicbox relay. It
//! works only in a library built with the `mock` feature, which app builds never enable;
//! elsewhere every call fails with `Unsupported`.

use flutter_rust_bridge::frb;

use crate::api::diagnostics::LogLevel;
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::types::Chain;
use crate::boundary::{guard, guard_or};

/// A scripted chain that stands in for the node of every wallet of the runtimes it creates.
#[frb(opaque)]
pub struct MockChain {
    #[cfg(feature = "mock")]
    backend: crate::mock::MockBackend,
}

#[cfg(not(feature = "mock"))]
fn unsupported() -> WalletError {
    WalletError::new(
        WalletErrorKind::Unsupported,
        "this library was built without the mock feature",
    )
}

impl MockChain {
    /// An empty chain whose tip is at `height`.
    #[frb(sync)]
    pub fn new(height: u64) -> Result<MockChain, WalletError> {
        guard("mock_chain", || {
            #[cfg(feature = "mock")]
            {
                Ok(Self {
                    backend: crate::mock::MockBackend::new(height)?,
                })
            }
            #[cfg(not(feature = "mock"))]
            {
                let _ = height;
                Err(unsupported())
            }
        })
    }

    /// A runtime whose wallets all talk to this chain, whatever node they are configured
    /// with, and seal vaults with the cheapest Argon2 setting so tests stay fast.
    #[frb(sync)]
    pub fn runtime(&self, log_level: LogLevel) -> Result<LepicRuntime, WalletError> {
        guard("mock_chain_runtime", || {
            #[cfg(feature = "mock")]
            {
                let kdf = lepic_keychain::KdfParams::new(8, 1, 1)
                    .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
                LepicRuntime::start(
                    log_level,
                    crate::node::NodeFactory::Mock(self.backend.clone()),
                    kdf,
                    crate::pin::PinPolicy::DEFAULT,
                )
            }
            #[cfg(not(feature = "mock"))]
            {
                let _ = log_level;
                Err(unsupported())
            }
        })
    }

    #[cfg(all(test, feature = "mock"))]
    pub(crate) fn backend(&self) -> &crate::mock::MockBackend {
        &self.backend
    }

    /// [`MockChain::runtime`] whose wallets also reach `relay` for every Epicbox connection,
    /// whatever relay they are configured with.
    #[frb(sync)]
    pub fn runtime_with_relay(
        &self,
        log_level: LogLevel,
        relay: &MockRelay,
    ) -> Result<LepicRuntime, WalletError> {
        #[cfg(feature = "mock")]
        {
            let mut runtime = self.runtime(log_level)?;
            guard("mock_chain_runtime_with_relay", || {
                let inner = std::sync::Arc::get_mut(&mut runtime.inner).ok_or_else(|| {
                    WalletError::new(WalletErrorKind::Other, "runtime is shared already")
                })?;
                inner.relay = Some(relay.relay.connector());
                Ok(())
            })?;
            Ok(runtime)
        }
        #[cfg(not(feature = "mock"))]
        {
            let _ = relay;
            self.runtime(log_level)
        }
    }

    #[frb(sync)]
    pub fn height(&self) -> u64 {
        guard_or("mock_chain_height", 0, || {
            #[cfg(feature = "mock")]
            {
                self.backend.height()
            }
            #[cfg(not(feature = "mock"))]
            {
                0
            }
        })
    }

    #[frb(sync)]
    pub fn set_height(&self, height: u64) {
        guard_or("mock_chain_set_height", (), || {
            #[cfg(feature = "mock")]
            self.backend.set_height(height);
            #[cfg(not(feature = "mock"))]
            let _ = height;
        });
    }

    /// Mines a plain output of `amount` for key `m/0/0/<child>` of the wallet with `mnemonic`
    /// into the tip block. The phrase is a test wallet's; never pass a real one.
    #[frb(sync)]
    pub fn fund(
        &self,
        mnemonic: String,
        chain: Chain,
        amount: u64,
        child: u32,
    ) -> Result<(), WalletError> {
        let mnemonic = zeroize::Zeroizing::new(mnemonic);
        guard("mock_chain_fund", || {
            #[cfg(feature = "mock")]
            {
                self.backend.fund(
                    &crate::session::normalize_phrase(&mnemonic),
                    chain.network(),
                    amount,
                    child,
                )
            }
            #[cfg(not(feature = "mock"))]
            {
                let _ = (mnemonic, chain, amount, child);
                Err(unsupported())
            }
        })
    }

    /// How many transactions wallets have posted to this chain.
    #[frb(sync)]
    pub fn pushed_count(&self) -> u32 {
        guard_or("mock_chain_pushed_count", 0, || {
            #[cfg(feature = "mock")]
            {
                u32::try_from(self.backend.pushed_count()).unwrap_or(u32::MAX)
            }
            #[cfg(not(feature = "mock"))]
            {
                0
            }
        })
    }

    /// Mines every posted transaction into the tip block.
    #[frb(sync)]
    pub fn mine_pushed(&self) {
        guard_or("mock_chain_mine_pushed", (), || {
            #[cfg(feature = "mock")]
            self.backend.mine_pushed();
        });
    }

    /// Lists every posted transaction in the node's transaction pool, until the next call.
    #[frb(sync)]
    pub fn pool_pushed(&self) {
        guard_or("mock_chain_pool_pushed", (), || {
            #[cfg(feature = "mock")]
            self.backend.pool_pushed();
        });
    }

    /// Makes the next node request panic inside the engine operation that sends it.
    #[frb(sync)]
    pub fn panic_on_next_node_call(&self) {
        guard_or("mock_chain_panic_on_next_node_call", (), || {
            #[cfg(feature = "mock")]
            self.backend.panic_on_next_call();
        });
    }

    /// The next transaction a wallet posts reaches this chain's pool, but the wallet gets a
    /// connection error instead of the node's answer, as when a connection drops after the
    /// node took the transaction.
    #[frb(sync)]
    pub fn lose_next_post_reply(&self) {
        guard_or("mock_chain_lose_next_post_reply", (), || {
            #[cfg(feature = "mock")]
            self.backend.lose_next_post_reply();
        });
    }

    /// What the node answers to `ready_for_txs`; `None` answers as a node before 4.1.0, which
    /// does not know the method, as the chain does until this is called.
    #[frb(sync)]
    pub fn set_node_ready_for_txs(&self, ready: Option<bool>) {
        guard_or("mock_chain_set_node_ready_for_txs", (), || {
            #[cfg(feature = "mock")]
            self.backend.set_ready_for_txs(ready);
            #[cfg(not(feature = "mock"))]
            let _ = ready;
        });
    }

    /// While `stalled`, every node request waits without an answer, as a node that hangs.
    /// Requests that waited get their answer once it is cleared.
    #[frb(sync)]
    pub fn set_node_stalled(&self, stalled: bool) {
        guard_or("mock_chain_set_node_stalled", (), || {
            #[cfg(feature = "mock")]
            self.backend.set_stalled(stalled);
            #[cfg(not(feature = "mock"))]
            let _ = stalled;
        });
    }

    /// Node requests that waited on a stalled node so far.
    #[frb(sync)]
    pub fn stalled_node_calls(&self) -> u64 {
        guard_or("mock_chain_stalled_node_calls", 0, || {
            #[cfg(feature = "mock")]
            {
                self.backend.stalled_calls()
            }
            #[cfg(not(feature = "mock"))]
            {
                0
            }
        })
    }

    /// While `unreachable`, every node request fails as if the node refused the connection.
    #[frb(sync)]
    pub fn set_node_unreachable(&self, unreachable: bool) {
        guard_or("mock_chain_set_node_unreachable", (), || {
            #[cfg(feature = "mock")]
            self.backend.set_unreachable(unreachable);
            #[cfg(not(feature = "mock"))]
            let _ = unreachable;
        });
    }
}

/// An in-process Epicbox relay with the public relay's semantics, for the wallets of
/// [`MockChain::runtime_with_relay`].
#[frb(opaque)]
pub struct MockRelay {
    #[cfg(feature = "mock")]
    relay: lepic_epicbox::mock_relay::MockRelay,
    #[cfg(feature = "mock")]
    chain: Chain,
}

impl MockRelay {
    /// An empty relay for the addresses of `chain`.
    #[frb(sync)]
    pub fn new(chain: Chain) -> Result<MockRelay, WalletError> {
        guard("mock_relay", || {
            #[cfg(feature = "mock")]
            {
                Ok(Self {
                    relay: lepic_epicbox::mock_relay::MockRelay::new(
                        crate::session::relay_network(chain.network()),
                    ),
                    chain,
                })
            }
            #[cfg(not(feature = "mock"))]
            {
                let _ = chain;
                Err(unsupported())
            }
        })
    }

    /// Messages for `address` that no wallet acknowledged yet. Fails with `InvalidArgument`
    /// for an address that does not parse on the relay's chain.
    #[frb(sync)]
    pub fn pending(&self, address: String) -> Result<u32, WalletError> {
        guard("mock_relay_pending", || {
            #[cfg(feature = "mock")]
            {
                let address = lepic_epicbox::EpicboxAddress::parse(
                    &address,
                    crate::session::relay_network(self.chain.network()),
                )
                .map_err(|_| {
                    WalletError::new(WalletErrorKind::InvalidArgument, "not an epicbox address")
                })?;
                Ok(u32::try_from(self.relay.pending(&address)).unwrap_or(u32::MAX))
            }
            #[cfg(not(feature = "mock"))]
            {
                let _ = address;
                Err(unsupported())
            }
        })
    }

    /// While `refusing`, new connections fail as with an unreachable relay.
    #[frb(sync)]
    pub fn set_refusing(&self, refusing: bool) {
        guard_or("mock_relay_set_refusing", (), || {
            #[cfg(feature = "mock")]
            self.relay.set_refusing(refusing);
            #[cfg(not(feature = "mock"))]
            let _ = refusing;
        });
    }
}

/// A peer on a [`MockRelay`] that behaves as a stock `epic-wallet` listener does with an
/// invoice: it sends every message back to its sender as it arrived, unpaid.
#[frb(opaque)]
pub struct MockStockPeer {
    #[cfg(feature = "mock")]
    client: lepic_epicbox::EpicboxClient,
    #[cfg(feature = "mock")]
    chain: Chain,
}

impl MockStockPeer {
    /// A peer at `<key>@epicbox.example` on `relay`, its key derived from `seed`. The seed
    /// is a test value; never pass a real one.
    #[frb(sync)]
    pub fn new(relay: &MockRelay, seed: Vec<u8>) -> Result<MockStockPeer, WalletError> {
        guard("mock_stock_peer", || {
            #[cfg(feature = "mock")]
            {
                mock_peer::new(relay, &seed)
            }
            #[cfg(not(feature = "mock"))]
            {
                let _ = (relay, seed);
                Err(unsupported())
            }
        })
    }

    #[frb(sync)]
    pub fn address(&self) -> String {
        guard_or("mock_stock_peer_address", String::new(), || {
            #[cfg(feature = "mock")]
            {
                self.client.address().to_string()
            }
            #[cfg(not(feature = "mock"))]
            {
                String::new()
            }
        })
    }

    /// Posts `text` to `address` as this peer, on the threads of `runtime`. Fails with
    /// `InvalidArgument` for an address that does not parse on the relay's chain.
    pub async fn send(
        &self,
        runtime: &LepicRuntime,
        to: String,
        text: String,
    ) -> Result<(), WalletError> {
        #[cfg(feature = "mock")]
        {
            let client = self.client.clone();
            let network = crate::session::relay_network(self.chain.network());
            runtime
                .inner
                .boundary
                .run("mock_stock_peer_send", async move {
                    mock_peer::send(&client, network, &to, &text).await
                })
                .await
        }
        #[cfg(not(feature = "mock"))]
        {
            let _ = (runtime, to, text);
            Err(unsupported())
        }
    }

    /// Reads every message waiting for the peer, sends each back to its sender unchanged and
    /// acknowledges it, on the threads of `runtime`. Returns how many it sent back.
    pub async fn return_messages(&self, runtime: &LepicRuntime) -> Result<u32, WalletError> {
        #[cfg(feature = "mock")]
        {
            let client = self.client.clone();
            let network = crate::session::relay_network(self.chain.network());
            runtime
                .inner
                .boundary
                .run("mock_stock_peer_return_messages", async move {
                    mock_peer::return_messages(&client, network).await
                })
                .await
        }
        #[cfg(not(feature = "mock"))]
        {
            let _ = runtime;
            Err(unsupported())
        }
    }
}

#[cfg(feature = "mock")]
mod mock_peer {
    use lepic_epicbox::{
        ClientSettings, Domain, EpicboxAddress, EpicboxClient, Identity, Network, RelayEndpoint,
        Security,
    };
    use lepic_keychain::ExtendedPrivKey;
    use lepic_transport::transport::Inbound as _;

    use super::{MockRelay, MockStockPeer};
    use crate::api::error::{WalletError, WalletErrorKind};

    const DOMAIN: &str = "epicbox.example";
    const PORT: u16 = 443;

    fn failed(error: &(dyn std::error::Error + 'static)) -> WalletError {
        WalletError::new(
            WalletErrorKind::TransportFailed,
            lepic_telemetry::ErrorChain(error).to_string(),
        )
    }

    pub(super) fn new(relay: &MockRelay, seed: &[u8]) -> Result<MockStockPeer, WalletError> {
        let key = ExtendedPrivKey::new_master(seed).map_err(|error| failed(&error))?;
        let public = key.public_key().map_err(|error| failed(&error))?;
        let domain = Domain::parse(DOMAIN).map_err(|error| failed(&error))?;
        let network = crate::session::relay_network(relay.chain.network());
        let address = EpicboxAddress::new(public, network, domain.clone(), Some(PORT));
        let identity =
            Identity::new(key.secret_key().clone(), address).map_err(|error| failed(&error))?;
        let settings = ClientSettings::new(RelayEndpoint::new(domain, Some(PORT), Security::Tls));
        Ok(MockStockPeer {
            client: EpicboxClient::new(settings, identity, relay.relay.connector()),
            chain: relay.chain,
        })
    }

    pub(super) async fn send(
        client: &EpicboxClient,
        network: Network,
        to: &str,
        text: &str,
    ) -> Result<(), WalletError> {
        let to = EpicboxAddress::parse(to, network).map_err(|_| {
            WalletError::new(WalletErrorKind::InvalidArgument, "not an epicbox address")
        })?;
        client.post(&to, text).await.map_err(|error| failed(&error))
    }

    pub(super) async fn return_messages(
        client: &EpicboxClient,
        network: Network,
    ) -> Result<u32, WalletError> {
        let subscription = client.drain().map_err(|error| failed(&error))?;
        let mut returned = 0u32;
        while let Some(envelope) = subscription
            .next_envelope()
            .await
            .map_err(|error| failed(&error))?
        {
            let sender = envelope
                .reply_to()
                .and_then(|to| EpicboxAddress::parse(to.as_str(), network).ok());
            if let (Some(sender), Some(text)) = (sender, envelope.wire().as_text()) {
                client
                    .post(&sender, text)
                    .await
                    .map_err(|error| failed(&error))?;
                returned = returned.saturating_add(1);
            }
            subscription
                .acknowledge(envelope.ack_token())
                .await
                .map_err(|error| failed(&error))?;
        }
        subscription.stop().await.map_err(|error| failed(&error))?;
        Ok(returned)
    }
}
