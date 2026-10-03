//! Two wallets on one mock relay, shared by the inbox tests and the inbox log test.

// Each test binary uses a different subset of these helpers, and test helpers may unwrap and
// panic (docs/rules.md).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::time::Duration;

use crate::send_support::{ACCOUNT, Sender, context_key};
use crate::support::{Harness, MemoryStores, TestVault, TestWallet, password};
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{
    Backoff, ClientSettings, Domain, EpicboxAddress, Network as RelayNetwork, Nonce, RelayEndpoint,
    Salt, Security, SignedMessage, TRANSPORT_ID,
};
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, InboxEntry, MemoryStore, StoreError, TxState, WalletStore};
use lepic_transport::transport::Destination;
use lepic_wallet::event::{TransportState, TransportStatus};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Event, Ports, Wallet};
use tokio::sync::broadcast;

pub const AMOUNT: u64 = 100_000_000;

pub const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

pub const RECEIVER_PASSWORD: &str = "receiver";

/// Generous for a loaded machine; every wait ends as soon as its condition holds.
pub const PATIENCE: Duration = Duration::from_secs(20);

pub fn settings() -> ClientSettings {
    let mut settings = ClientSettings::new(RelayEndpoint::new(
        Domain::parse("relay.test").unwrap(),
        None,
        Security::Plain,
    ));
    settings.connect_timeout = Duration::from_secs(5);
    settings.response_timeout = Duration::from_secs(5);
    settings.ping_interval = Duration::from_secs(5);
    settings.backoff = Backoff {
        initial: Duration::from_millis(20),
        max: Duration::from_millis(100),
    };
    settings
}

pub fn request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

pub async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, future)
        .await
        .expect("timed out")
}

pub async fn until(condition: impl Fn() -> bool) {
    within(async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

pub async fn transport_reaches(events: &mut broadcast::Receiver<Event>, wanted: TransportState) {
    within(async {
        loop {
            if let Event::Transport(TransportStatus { state, .. }) = events.recv().await.unwrap()
                && state == wanted
            {
                return;
            }
        }
    })
    .await;
}

pub fn transport_states(events: &mut broadcast::Receiver<Event>) -> Vec<TransportState> {
    let mut states = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transport(TransportStatus { transport, state }) = event {
            assert_eq!(transport, TRANSPORT_ID);
            states.push(state);
        }
    }
    states
}

/// A receiving wallet. Handles built from one `Receiver` share the
/// database and the secret storage, as an app does across restarts.
pub struct Receiver {
    pub harness: Harness,
    pub vault: TestVault,
}

impl Receiver {
    pub fn new() -> Self {
        Self {
            harness: Harness::new(),
            vault: TestVault::default(),
        }
    }

    /// The wallet's database under its own context key; the wallet must exist.
    pub fn store(&self) -> MemoryStore {
        let seed = lepic_keychain::Seed::from_mnemonic(RECEIVER_MNEMONIC).unwrap();
        assert!(!self.harness.stores.is_empty(&self.harness.data_dir));
        lepic_wallet::StoreOpener::open(
            &self.harness.stores,
            &self.harness.data_dir,
            context_key(&seed),
        )
        .unwrap()
    }

    /// A new wallet handle with its own Epicbox transport, as after an app start.
    pub fn wallet(
        &self,
        relay: &MockRelay,
        runtime: tokio::runtime::Handle,
    ) -> (TestWallet, EpicboxTransport) {
        let epicbox = EpicboxTransport::new(settings(), RelayNetwork::Floonet, relay.connector());
        let mut transports = lepic_transport::registry::TransportRegistry::new();
        transports.register(Box::new(epicbox.clone())).unwrap();
        let mut config = self.harness.config(Network::Floonet);
        config.transports = vec![TRANSPORT_ID];
        let ports: Ports<_, MemoryStores, TestVault> = Ports {
            transports,
            runtime,
            ..self.harness.ports(self.vault.clone())
        };
        (Wallet::new(config, ports).unwrap(), epicbox)
    }

    pub fn transactions(&self) -> usize {
        self.store()
            .read(|repos| Ok::<_, StoreError>(repos.transactions(AccountIndex(0))?.len()))
            .unwrap()
    }

    pub fn inbox(&self, msg_id: &str) -> Option<InboxEntry> {
        self.store().read(|repos| repos.inbox(msg_id)).unwrap()
    }
}

/// A funded sender and a receiver, each with an Epicbox transport, on one mock relay.
pub struct World {
    /// Drives the relay, both subscriptions and both wallets; the harness runtimes have no
    /// timers.
    pub runtime: tokio::runtime::Runtime,
    pub relay: MockRelay,
    pub sender: Sender,
    pub sender_epicbox: EpicboxTransport,
    pub sender_address: EpicboxAddress,
    pub receiver: Receiver,
    pub receiver_wallet: TestWallet,
    pub receiver_epicbox: EpicboxTransport,
    pub receiver_address: EpicboxAddress,
}

impl World {
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let relay = MockRelay::new(RelayNetwork::Floonet);
        let sender_epicbox =
            EpicboxTransport::new(settings(), RelayNetwork::Floonet, relay.connector());
        let sender = Sender::with_transports(vec![Box::new(sender_epicbox.clone())]);
        let sender_address = sender.wallet.epicbox_attach(&sender_epicbox).unwrap();
        let receiver = Receiver::new();
        let (receiver_wallet, receiver_epicbox) = receiver.wallet(&relay, runtime.handle().clone());
        runtime
            .block_on(receiver_wallet.restore(password(RECEIVER_PASSWORD), RECEIVER_MNEMONIC))
            .unwrap();
        let receiver_address = receiver_wallet.epicbox_attach(&receiver_epicbox).unwrap();
        Self {
            runtime,
            relay,
            sender,
            sender_epicbox,
            sender_address,
            receiver,
            receiver_wallet,
            receiver_epicbox,
            receiver_address,
        }
    }

    pub fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }

    pub async fn send(&self) {
        self.sender
            .wallet
            .send(
                request(),
                Delivery::Deliver {
                    transport: TRANSPORT_ID,
                    to: Destination::new(self.receiver_address.to_string()),
                },
            )
            .await
            .unwrap();
    }

    pub fn sender_state(&self) -> TxState {
        self.sender.transactions()[0].entry.state
    }

    /// The receiver after an app restart: a new handle on the same database and secrets.
    pub fn restart_receiver(&self) -> (TestWallet, EpicboxTransport) {
        let (wallet, epicbox) = self
            .receiver
            .wallet(&self.relay, self.runtime.handle().clone());
        self.block_on(wallet.open(password(RECEIVER_PASSWORD)))
            .unwrap();
        (wallet, epicbox)
    }

    /// Stores a message for the receiver as if `from` had posted it, signed by `signer`.
    pub fn post_to_receiver(&self, from: u8, signer: u8, plaintext: &str) -> String {
        let key = |byte: u8| SecretKey::from_array([byte; 32]).unwrap();
        let from = EpicboxAddress::new(
            PublicKey::from_secret_key(&key(from)).unwrap(),
            RelayNetwork::Floonet,
            Domain::parse("relay.test").unwrap(),
            Some(80),
        );
        let message = SignedMessage::seal(
            plaintext,
            &self.receiver_address,
            &key(signer),
            Salt::from([4; 8]),
            Nonce::from([5; 12]),
        )
        .unwrap();
        self.relay.store(&from, &self.receiver_address, &message)
    }
}
