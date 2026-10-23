//! An issuer and a funded payer on one mock relay and one mock node, each with an Epicbox
//! transport, a clock the test moves and a store that counts its write transactions.

// Test helpers may unwrap, panic and use plain arithmetic (docs/rules.md).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use jiff::Timestamp;
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{
    Backoff, ClientSettings, Domain, EpicboxAddress, EpicboxClient, Identity,
    Network as RelayNetwork, Nonce, RelayEndpoint, Salt, Security, SignedMessage, TRANSPORT_ID,
};
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{NodeClient, NodeVersion, Tip};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_slate::codec::WireSlate;
use lepic_store::{
    AccountIndex, ContextKey, KeyId, MemoryStore, OutputRecord, OutputStatus, Repositories,
    StoreError, WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::policy::FormatPolicy;
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport, TransportId};
use lepic_wallet::invoice::{InvoiceRequest, IssuedInvoice, PayRequest};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::Delivery;
use lepic_wallet::{
    Clock, NodeEndpoint, Ports, SharedRng, StoreOpener, Wallet, WalletConfig, WalletName,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::support::{TestVault, complete_restore_scan, fixed_time, password};

pub const ISSUER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal \
    winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

pub const PAYER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

pub const ACCOUNT: AccountIndex = AccountIndex(0);
pub const AMOUNT: u64 = 300_000_000;
pub const FUNDING: u64 = 1_457_920_000;
pub const TIP: u64 = 4;

const PATIENCE: Duration = Duration::from_secs(20);
const CLIENT_TIMERS: Duration = Duration::from_secs(60);

pub type PartyWallet = Wallet<NodeClient<MockNode>, CountingStores, TestVault>;

/// A clock the test moves forward.
#[derive(Clone)]
pub struct TestClock(Arc<Mutex<Timestamp>>);

impl TestClock {
    pub fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *now = now.checked_add(by).unwrap();
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A memory store that counts the write transactions the engine runs on it, and fails one when
/// a test asks.
pub struct CountingStore {
    inner: MemoryStore,
    writes: Arc<AtomicUsize>,
    failing: Arc<Mutex<Option<usize>>>,
}

impl WalletStore for CountingStore {
    fn read<R, E>(&self, operation: impl FnOnce(&dyn Repositories) -> Result<R, E>) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        self.inner.read(operation)
    }

    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>,
    {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let fail = {
            let mut failing = self.failing.lock().unwrap_or_else(PoisonError::into_inner);
            match *failing {
                Some(0) => {
                    *failing = None;
                    true
                }
                Some(left) => {
                    *failing = Some(left - 1);
                    false
                }
                None => false,
            }
        };
        if fail {
            return Err(StoreError::Poisoned.into());
        }
        self.inner.write(operation)
    }
}

#[derive(Clone, Default)]
pub struct CountingStores {
    stores: Arc<Mutex<BTreeMap<PathBuf, MemoryStore>>>,
    writes: Arc<AtomicUsize>,
    failing: Arc<Mutex<Option<usize>>>,
}

impl StoreOpener for CountingStores {
    type Store = CountingStore;

    fn open(&self, data_dir: &Path, key: ContextKey) -> Result<CountingStore, StoreError> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        let store = stores
            .entry(data_dir.to_owned())
            .or_insert_with(|| MemoryStore::new(ContextKey::from_bytes([0; 32])));
        Ok(CountingStore {
            inner: store.reopen(key),
            writes: Arc::clone(&self.writes),
            failing: Arc::clone(&self.failing),
        })
    }
}

/// The Epicbox transport as the wallet's registry holds it, recording where each delivery went,
/// and failing every delivery while a test asks.
struct RecordingEpicbox {
    inner: EpicboxTransport,
    delivered_to: Arc<Mutex<Vec<String>>>,
    failing: Arc<AtomicBool>,
}

impl Transport for RecordingEpicbox {
    fn id(&self) -> TransportId {
        self.inner.id()
    }

    fn policy(&self) -> &dyn FormatPolicy {
        self.inner.policy()
    }

    fn outbound(&self) -> Option<&dyn Outbound> {
        Some(self)
    }
}

impl Outbound for RecordingEpicbox {
    fn deliver<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        self.delivered_to
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(to.as_str().to_owned());
        if self.failing.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(TransportError::Backend {
                    transport: TRANSPORT_ID,
                    source: Box::new(std::io::Error::from(std::io::ErrorKind::TimedOut)),
                })
            });
        }
        self.inner.deliver(to, wire)
    }
}

pub fn settings() -> ClientSettings {
    let mut settings = ClientSettings::new(RelayEndpoint::new(
        Domain::parse("relay.test").unwrap(),
        None,
        Security::Plain,
    ));
    settings.connect_timeout = CLIENT_TIMERS;
    settings.response_timeout = CLIENT_TIMERS;
    settings.ping_interval = CLIENT_TIMERS;
    settings.backoff = Backoff {
        initial: Duration::from_millis(20),
        max: Duration::from_millis(100),
    };
    settings
}

pub fn pay_request() -> PayRequest {
    PayRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..PayRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

fn context_key(seed: &Seed) -> ContextKey {
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).unwrap();
    mac.update(b"lepic-wallet private context key v1");
    ContextKey::from_bytes(mac.finalize_fixed().into())
}

pub struct Party {
    pub wallet: PartyWallet,
    pub epicbox: EpicboxTransport,
    /// The payments address, index 0, attached to `epicbox`.
    pub address: EpicboxAddress,
    pub clock: TestClock,
    delivered_to: Arc<Mutex<Vec<String>>>,
    deliveries_failing: Arc<AtomicBool>,
    stores: CountingStores,
    seed: Seed,
    data_dir: PathBuf,
}

impl Party {
    fn new(
        mnemonic: &str,
        name: &str,
        seed_rng: u64,
        node: &MockNode,
        relay: &MockRelay,
        runtime: &tokio::runtime::Runtime,
    ) -> Self {
        let epicbox = EpicboxTransport::new(settings(), RelayNetwork::Floonet, relay.connector());
        let delivered_to = Arc::default();
        let deliveries_failing = Arc::default();
        let mut transports = TransportRegistry::new();
        transports
            .register(Box::new(RecordingEpicbox {
                inner: epicbox.clone(),
                delivered_to: Arc::clone(&delivered_to),
                failing: Arc::clone(&deliveries_failing),
            }))
            .unwrap();
        let stores = CountingStores::default();
        let clock = TestClock(Arc::new(Mutex::new(fixed_time())));
        let data_dir = PathBuf::from(format!("/{name}"));
        let ports = Ports {
            node: node.client(),
            stores: stores.clone(),
            secrets: TestVault::default(),
            transports,
            clock: Arc::new(clock.clone()),
            rng: SharedRng::new(StdRng::seed_from_u64(seed_rng)),
            runtime: runtime.handle().clone(),
        };
        let config = WalletConfig {
            name: WalletName::new(name).unwrap(),
            network: Network::Floonet,
            data_dir: data_dir.clone(),
            node: NodeEndpoint::parse("http://127.0.0.1:13413").unwrap(),
            transports: vec![TRANSPORT_ID],
        };
        let wallet = Wallet::new(config, ports).unwrap();
        runtime
            .block_on(wallet.restore(password(name), mnemonic))
            .unwrap();
        complete_restore_scan(runtime, &wallet);
        let address = wallet.epicbox_attach(&epicbox).unwrap();
        Self {
            wallet,
            epicbox,
            address,
            clock,
            delivered_to,
            deliveries_failing,
            stores,
            seed: Seed::from_mnemonic(mnemonic).unwrap(),
            data_dir,
        }
    }

    /// The wallet's database under its own context key.
    pub fn store(&self) -> MemoryStore {
        self.stores
            .open(&self.data_dir, context_key(&self.seed))
            .unwrap()
            .inner
    }

    pub fn read<T>(&self, read: impl FnOnce(&dyn Repositories) -> Result<T, StoreError>) -> T {
        self.store().read(read).unwrap()
    }

    /// Write transactions run so far through the wallet's store opener.
    pub fn writes(&self) -> usize {
        self.stores.writes.load(Ordering::SeqCst)
    }

    /// The destinations the wallet handed its registered Epicbox transport, oldest first.
    pub fn delivered_to(&self) -> Vec<String> {
        self.delivered_to
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Makes every delivery through the registered transport fail as an unreachable relay
    /// does, or succeed again. Connections the wallet opens itself are not affected.
    pub fn set_deliveries_failing(&self, failing: bool) {
        self.deliveries_failing.store(failing, Ordering::SeqCst);
    }

    /// Lets `succeeding` more write transactions through, then fails the one after.
    pub fn fail_write_after(&self, succeeding: usize) {
        *self
            .stores
            .failing
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(succeeding);
    }

    pub fn invoice_address(&self) -> EpicboxAddress {
        self.wallet.invoice_address(&self.epicbox).unwrap()
    }

    /// Adds an unspent coinbase output of `value` at child `child`, mined at height 1, and moves
    /// the key counter past it.
    pub fn fund(&self, child: u32, value: u64) {
        let keychain = Keychain::from_seed(&self.seed, Network::Floonet).unwrap();
        let id = Identifier::new(3, [0, 0, child, 0]).unwrap();
        let output = OutputRecord {
            id: OutputIdentifier::new(
                OutputFeatures::Coinbase,
                keychain
                    .commit(value, &id, SwitchCommitment::Regular)
                    .unwrap(),
            ),
            key_id: KeyId(id.to_bytes()),
            account: ACCOUNT,
            amount: Amount::new(value),
            status: OutputStatus::Unspent,
            height: Height::new(1),
            lock_height: Height::ZERO,
            mmr_index: None,
            tx: None,
        };
        self.store()
            .write(|repos| {
                repos.put_output(&output)?;
                let mut account = repos.account(ACCOUNT)?.unwrap();
                account.next_child = child + 1;
                repos.put_account(&account)
            })
            .unwrap();
    }
}

pub struct World {
    pub runtime: tokio::runtime::Runtime,
    pub relay: MockRelay,
    pub node: MockNode,
    pub issuer: Party,
    pub payer: Party,
}

impl World {
    /// The payer allows the issuer's payments address on its invoice address.
    pub fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let relay = MockRelay::new(RelayNetwork::Floonet);
        let node = MockNode::from_chain(ChainState::new(
            NodeVersion {
                node_version: "4.0.4".to_owned(),
                block_header_version: 6,
            },
            Tip {
                height: Height::new(TIP),
                last_block_pushed: Hash::from_slice(&[0; 32]).unwrap(),
            },
        ));
        let issuer = Party::new(ISSUER_MNEMONIC, "issuer", 1, &node, &relay, &runtime);
        let payer = Party::new(PAYER_MNEMONIC, "payer", 2, &node, &relay, &runtime);
        payer.fund(0, FUNDING);
        payer
            .wallet
            .allow_invoice_sender(&issuer.address.to_string(), "shop")
            .unwrap();
        Self {
            runtime,
            relay,
            node,
            issuer,
            payer,
        }
    }

    pub fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }

    /// A second install of the issuer's wallet: the same phrase, so the same payments
    /// address, with a store of its own that knows none of the issuer's slates.
    pub fn issuer_twin(&self) -> Party {
        Party::new(
            ISSUER_MNEMONIC,
            "issuer-twin",
            3,
            &self.node,
            &self.relay,
            &self.runtime,
        )
    }

    /// A second install of the payer's wallet, as [`World::issuer_twin`] is of the issuer's.
    pub fn payer_twin(&self) -> Party {
        Party::new(
            PAYER_MNEMONIC,
            "payer-twin",
            4,
            &self.node,
            &self.relay,
            &self.runtime,
        )
    }

    /// The issuer invoices the payer's invoice address over Epicbox.
    pub fn issue(&self, message: Option<&str>) -> IssuedInvoice {
        let to = self.payer.invoice_address();
        self.issue_to(&to, message)
    }

    pub fn issue_to(&self, to: &EpicboxAddress, message: Option<&str>) -> IssuedInvoice {
        self.block_on(self.issuer.wallet.issue_invoice(
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: message.map(str::to_owned),
            },
            Delivery::Deliver {
                transport: TRANSPORT_ID,
                to: Destination::new(to.to_string()),
            },
        ))
        .unwrap()
    }

    pub async fn within<T>(&self, future: impl Future<Output = T>) -> T {
        tokio::time::timeout(PATIENCE, future)
            .await
            .expect("timed out")
    }

    /// The address of the key whose bytes all equal `byte`.
    pub fn address_of(byte: u8) -> EpicboxAddress {
        EpicboxAddress::new(
            PublicKey::from_secret_key(&key(byte)).unwrap(),
            RelayNetwork::Floonet,
            Domain::parse("relay.test").unwrap(),
            Some(80),
        )
    }

    /// Stores `plaintext` for `to`, as if the key whose bytes all equal `from` had posted it,
    /// `copies` times, and returns the message ids.
    pub fn post(
        &self,
        from: u8,
        to: &EpicboxAddress,
        plaintext: &str,
        copies: usize,
    ) -> Vec<String> {
        let message = SignedMessage::seal(
            plaintext,
            to,
            &key(from),
            Salt::from([4; 8]),
            Nonce::from([5; 12]),
        )
        .unwrap();
        let sender = Self::address_of(from);
        (0..copies)
            .map(|_| self.relay.store(&sender, to, &message))
            .collect()
    }

    /// A client speaking for the key whose bytes all equal `byte`, as a peer wallet.
    pub fn peer_client(&self, byte: u8) -> EpicboxClient {
        EpicboxClient::new(
            settings(),
            Identity::new(key(byte), Self::address_of(byte)).unwrap(),
            self.relay.connector(),
        )
    }
}

pub fn key(byte: u8) -> SecretKey {
    SecretKey::from_array([byte; 32]).unwrap()
}
