// SPDX-License-Identifier: Apache-2.0
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

use jiff::Timestamp;
use lepic_crypto::{PublicKey, SecretKey};
use lepic_epicbox::Connector;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::sessions::PushedConfig;
use lepic_epicbox::{
    Backoff, ClientSettings, Domain, EpicboxAddress, EpicboxClient, Identity, MuxOptions,
    Network as RelayNetwork, Nonce, RelayEndpoint, Salt, Security, SignedMessage,
};
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_methods::epicbox::Epicbox;
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{NodeClient, NodeVersion, Tip};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::hash::Hash;
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, WireSlate};
use lepic_slate::error::DecodeError;
use lepic_slate::model::Slate;
use lepic_store::{
    AccountIndex, KeyId, MemoryStore, OutputRecord, OutputStatus, PendingInvoice,
    PendingInvoiceStatus, Repositories, StoreError, StoreKeys, WalletStore,
};
use lepic_transport::error::{FormatError, TransportError};
use lepic_transport::method::{EncodeContext, Encoded, Method, Sending};
use lepic_transport::policy::FormatPolicy;
use lepic_transport::transport::{
    BoxFuture, Destination, Outbound, RelayCancel, RelayTxId, Transport, TransportId,
};
use lepic_wallet::invoice::PayRequest;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::{
    Clock, NodeEndpoint, Ports, SharedRng, StoreOpener, Wallet, WalletConfig, WalletName,
    WalletPolicy,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use uuid::Uuid;

use crate::support::{
    TestVault, complete_restore_scan, fixed_time, password, put_on_chain, registry,
};

pub const ISSUER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal \
    winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

pub const PAYER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

/// A third phrase, for a wallet that shares neither side's seed.
pub const STRANGER_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
    zoo zoo zoo zoo zoo zoo zoo zoo vote";

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

    fn open(
        &self,
        data_dir: &Path,
        key: StoreKeys,
        _: &lepic_store::StoreKey,
    ) -> Result<CountingStore, StoreError> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        let store = stores
            .entry(data_dir.to_owned())
            .or_insert_with(|| MemoryStore::new(StoreKeys::from_bytes([0; 32], [0; 32])));
        Ok(CountingStore {
            inner: store.reopen(key),
            writes: Arc::clone(&self.writes),
            failing: Arc::clone(&self.failing),
        })
    }

    fn start_over(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &lepic_store::StoreKey,
    ) -> Result<(CountingStore, Option<lepic_store::AtRestReport>), StoreError> {
        self.open_reporting(data_dir, keys, store_key)
    }
}

/// The Epicbox transport as the wallet's registry holds it, recording where each delivery went.
struct RecordingEpicbox {
    inner: Epicbox,
    delivered_to: Arc<Mutex<Vec<String>>>,
    /// Whether posts go under relay transaction ids and the relay can cancel, as the Epicbox
    /// method itself does; off, the method acts as one without them.
    relay_ids: Arc<AtomicBool>,
}

impl RecordingEpicbox {
    fn relay_ids(&self) -> bool {
        self.relay_ids.load(Ordering::SeqCst)
    }
}

/// What a party's ports hold as [`Ports::methods`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortsMethods {
    /// A registry of the party's recording Epicbox method.
    Recording,
    /// A registry with no method in it.
    Empty,
    /// No registry.
    Absent,
}

/// A second recording instance of a party's Epicbox method, with the same id as the one its
/// ports hold, for a test to hand the engine as the method a message arrived over.
pub struct Recorder {
    pub method: Arc<dyn Method>,
    delivered_to: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    /// The destinations the engine handed this instance, oldest first.
    pub fn delivered_to(&self) -> Vec<String> {
        self.delivered_to
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
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

    fn relay_cancel(&self) -> Option<&dyn RelayCancel> {
        if self.relay_ids() {
            self.inner.relay_cancel()
        } else {
            None
        }
    }
}

impl Method for RecordingEpicbox {
    fn decode(&self, network: Network, wire: &WireSlate) -> Result<Slate, DecodeError> {
        self.inner.decode(network, wire)
    }

    fn encode_new(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
    ) -> Result<Encoded, FormatError> {
        self.inner.encode_new(slate, context, sending)
    }

    fn encode_reply(
        &self,
        slate: &Slate,
        context: &EncodeContext,
        sending: &Sending,
    ) -> Result<Encoded, FormatError> {
        self.inner.encode_reply(slate, context, sending)
    }

    fn peer_key(&self, network: Network, address: &str) -> Result<String, TransportError> {
        self.inner.peer_key(network, address)
    }

    fn same_payee(&self, network: Network, to: &Destination, allowed: &str) -> bool {
        self.inner.same_payee(network, to, allowed)
    }

    fn delivery_cancelled_on_relay(&self, error: &TransportError) -> bool {
        self.inner.delivery_cancelled_on_relay(error)
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
        self.inner.deliver(to, wire)
    }

    fn new_relay_txid(&self) -> Result<Option<RelayTxId>, TransportError> {
        if self.relay_ids() {
            self.inner.new_relay_txid()
        } else {
            Ok(None)
        }
    }

    fn deliver_tx<'a>(
        &'a self,
        to: &'a Destination,
        wire: &'a WireSlate,
        txid: Option<&'a RelayTxId>,
    ) -> BoxFuture<'a, Result<(), TransportError>> {
        if !self.relay_ids() {
            return self.deliver(to, wire);
        }
        self.delivered_to
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(to.as_str().to_owned());
        self.inner.deliver_tx(to, wire, txid)
    }
}

/// Lets the contacts' mux/1 sessions ask `Waiting` as often as a test collects. The budget runs
/// on real time, and a test that collects across simulated days does so within a few seconds.
/// A test of the budget sets its own.
fn unpaced(epicbox: &Epicbox) {
    epicbox.pushed().set_contacts(Some(PushedConfig {
        group: "contacts".to_owned(),
        options: MuxOptions::default().with_waiting_budget(1_000, Duration::from_millis(1)),
    }));
}

pub fn settings() -> ClientSettings {
    let mut settings = lepic_epicbox::testing::client_settings(RelayEndpoint::new(
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

/// The keys the engine opens the wallet's database with.
fn context_key(seed: &Seed) -> StoreKeys {
    lepic_wallet::lifecycle::store_keys(seed).unwrap()
}

pub struct Party {
    pub wallet: PartyWallet,
    pub epicbox: Epicbox,
    /// `epicbox` as the engine's method, recording where each delivery went.
    pub method: Arc<dyn Method>,
    /// The payments address, index 0, attached to `epicbox`.
    pub address: EpicboxAddress,
    pub clock: TestClock,
    delivered_to: Arc<Mutex<Vec<String>>>,
    relay_ids: Arc<AtomicBool>,
    stores: CountingStores,
    seed: Seed,
    data_dir: PathBuf,
    relay_connector: Arc<dyn Connector>,
    config: WalletConfig,
    secrets: TestVault,
    seed_rng: u64,
    /// The node the party's wallet talks to, so funding reaches its chain.
    node: MockNode,
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
        Self::with_profile(mnemonic, name, seed_rng, 0, node, relay, runtime)
    }

    fn with_profile(
        mnemonic: &str,
        name: &str,
        seed_rng: u64,
        profile: u16,
        node: &MockNode,
        relay: &MockRelay,
        runtime: &tokio::runtime::Runtime,
    ) -> Self {
        Self::with_domain(
            mnemonic,
            name,
            seed_rng,
            profile,
            None,
            WalletPolicy::default(),
            PortsMethods::Recording,
            node,
            relay,
            runtime,
        )
    }

    /// As [`Self::with_profile`], the wallet claiming `domain` in the cards it sends,
    /// configured with `policy` and with `methods` in its ports.
    #[allow(clippy::too_many_arguments)]
    fn with_domain(
        mnemonic: &str,
        name: &str,
        seed_rng: u64,
        profile: u16,
        domain: Option<&str>,
        policy: WalletPolicy,
        methods: PortsMethods,
        node: &MockNode,
        relay: &MockRelay,
        runtime: &tokio::runtime::Runtime,
    ) -> Self {
        let epicbox = Epicbox::new(settings(), RelayNetwork::Floonet, relay.connector());
        unpaced(&epicbox);
        let delivered_to = Arc::default();
        let relay_ids: Arc<AtomicBool> = Arc::default();
        let method: Arc<dyn Method> = Arc::new(RecordingEpicbox {
            inner: epicbox.clone(),
            delivered_to: Arc::clone(&delivered_to),
            relay_ids: Arc::clone(&relay_ids),
        });
        let methods = match methods {
            PortsMethods::Recording => Some(registry([Arc::clone(&method)])),
            PortsMethods::Empty => Some(registry([])),
            PortsMethods::Absent => None,
        };
        let stores = CountingStores::default();
        let clock = TestClock(Arc::new(Mutex::new(fixed_time())));
        let data_dir = PathBuf::from(format!("/{name}"));
        let secrets = TestVault::default();
        let ports = Ports {
            node: node.client(),
            stores: stores.clone(),
            secrets: secrets.clone(),
            clock: Arc::new(clock.clone()),
            rng: SharedRng::new(StdRng::seed_from_u64(seed_rng)),
            runtime: runtime.handle().clone(),
            methods,
        };
        let config = WalletConfig {
            name: WalletName::new(name).unwrap(),
            network: Network::Floonet,
            data_dir: data_dir.clone(),
            node: NodeEndpoint::parse("http://127.0.0.1:13413").unwrap(),
            policy,
            offline: false,
            host_features: 0,
            profile,
            domain: domain.map(str::to_owned),
        };
        let wallet = Wallet::new(config.clone(), ports).unwrap();
        lepic_wallet_contacts::install(&wallet);
        runtime
            .block_on(wallet.restore(password(name), mnemonic))
            .unwrap();
        complete_restore_scan(runtime, &wallet);
        let address = epicbox.attach_wallet(&wallet).unwrap();
        Self {
            wallet,
            epicbox,
            method,
            address,
            clock,
            delivered_to,
            relay_ids,
            stores,
            seed: Seed::from_mnemonic(mnemonic).unwrap(),
            data_dir,
            relay_connector: relay.connector(),
            config,
            secrets,
            seed_rng,
            node: node.clone(),
        }
    }

    /// The same wallet opened again on its stores and vault, as after the app was stopped and
    /// started: a new Epicbox with no sessions, its own ports recording deliveries. The old
    /// handle is left to the caller to close.
    pub fn reopened(
        &self,
        node: &MockNode,
        relay: &MockRelay,
        runtime: &tokio::runtime::Runtime,
    ) -> Self {
        self.reopened_with(settings(), node, relay, runtime)
    }

    /// As [`Self::reopened`], the new Epicbox built with `settings`.
    pub fn reopened_with(
        &self,
        settings: ClientSettings,
        node: &MockNode,
        relay: &MockRelay,
        runtime: &tokio::runtime::Runtime,
    ) -> Self {
        let epicbox = Epicbox::new(settings, RelayNetwork::Floonet, relay.connector());
        unpaced(&epicbox);
        let delivered_to = Arc::default();
        let relay_ids: Arc<AtomicBool> = Arc::default();
        let method: Arc<dyn Method> = Arc::new(RecordingEpicbox {
            inner: epicbox.clone(),
            delivered_to: Arc::clone(&delivered_to),
            relay_ids: Arc::clone(&relay_ids),
        });
        let ports = Ports {
            node: node.client(),
            stores: self.stores.clone(),
            secrets: self.secrets.clone(),
            clock: Arc::new(self.clock.clone()),
            rng: SharedRng::new(StdRng::seed_from_u64(self.seed_rng)),
            runtime: runtime.handle().clone(),
            methods: Some(registry([Arc::clone(&method)])),
        };
        let wallet = Wallet::new(self.config.clone(), ports).unwrap();
        lepic_wallet_contacts::install(&wallet);
        runtime
            .block_on(wallet.open(password(self.config.name.as_str())))
            .unwrap();
        let address = epicbox.attach_wallet(&wallet).unwrap();
        Self {
            wallet,
            epicbox,
            method,
            address,
            clock: self.clock.clone(),
            delivered_to,
            relay_ids,
            stores: self.stores.clone(),
            seed: self.seed.clone(),
            data_dir: self.data_dir.clone(),
            relay_connector: relay.connector(),
            config: self.config.clone(),
            secrets: self.secrets.clone(),
            seed_rng: self.seed_rng,
            node: node.clone(),
        }
    }

    /// The wallet's seed.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// The wallet's database under its own context key.
    pub fn store(&self) -> MemoryStore {
        self.stores
            .open(
                &self.data_dir,
                context_key(&self.seed),
                &lepic_wallet::store_key(&self.seed).unwrap(),
            )
            .unwrap()
            .inner
    }

    pub fn read<T>(&self, read: impl FnOnce(&dyn Repositories) -> Result<T, StoreError>) -> T {
        self.store().read(read).unwrap()
    }

    pub fn write<T>(
        &self,
        write: impl FnOnce(&mut dyn Repositories) -> Result<T, StoreError>,
    ) -> T {
        self.store().write(write).unwrap()
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

    /// A second recording instance of the wallet's Epicbox method, apart from the one its ports
    /// hold.
    pub fn recorder(&self) -> Recorder {
        let delivered_to = Arc::default();
        Recorder {
            method: Arc::new(RecordingEpicbox {
                inner: self.epicbox.clone(),
                delivered_to: Arc::clone(&delivered_to),
                relay_ids: Arc::clone(&self.relay_ids),
            }),
            delivered_to,
        }
    }

    /// Makes the registered transport post under relay transaction ids and cancel on the relay
    /// as the Epicbox method does, or act as a method without them again (the default).
    pub fn set_relay_ids(&self, on: bool) {
        self.relay_ids.store(on, Ordering::SeqCst);
    }

    /// Lets `succeeding` more write transactions through, then fails the one after.
    pub fn fail_write_after(&self, succeeding: usize) {
        *self
            .stores
            .failing
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(succeeding);
    }

    /// The wallet's keychain, rebuilt from its phrase.
    pub fn keychain(&self) -> Keychain {
        Keychain::from_seed(&self.seed, Network::Floonet).unwrap()
    }

    /// A client speaking for the wallet's payments address, as the wallet itself would.
    pub fn client(&self) -> EpicboxClient {
        let keychain = Keychain::from_seed(&self.seed, Network::Floonet).unwrap();
        let parent = Identifier::new(2, [0, 0, 0, 0]).unwrap();
        let secret = keychain.address_key(&parent, 0).unwrap();
        EpicboxClient::new(
            settings(),
            Identity::new(secret, self.address.clone()).unwrap(),
            self.relay_connector.clone(),
        )
    }

    /// Parks `i1`, an invoice from `sender`, as it is parked once it arrived.
    pub fn park(&self, sender: &EpicboxAddress, i1: &WireSlate) {
        let slate = V3JsonCodec::new(Network::Floonet.params().default_base_fee())
            .decode(i1)
            .unwrap();
        let now = self.clock.now();
        let invoice = PendingInvoice {
            slate_id: Uuid::from_bytes(*slate.id().as_bytes()),
            sender_key: sender.key_text(),
            sender_address: sender.to_string(),
            received_at: now,
            status: PendingInvoiceStatus::Parked,
            codec: "v3".to_owned(),
            bytes: i1.as_bytes().to_vec(),
        };
        self.store()
            .write(|repos| repos.park_invoice(&invoice))
            .unwrap();
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
        put_on_chain(&self.node, &output.id, output.height);
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
    pub fn new() -> Self {
        Self::with_profiles(0, 0)
    }

    /// As [`Self::new`], the issuer's wallet configured with profile `issuer` and the payer's
    /// with `payer`.
    pub fn with_profiles(issuer: u16, payer: u16) -> Self {
        Self::with_parties(
            (issuer, None),
            (payer, None),
            WalletPolicy::default(),
            WalletPolicy::default(),
            PortsMethods::Recording,
        )
    }

    /// As [`Self::new`], the issuer's wallet configured with `policy`.
    pub fn with_issuer_policy(policy: WalletPolicy) -> Self {
        Self::with_parties(
            (0, None),
            (0, None),
            policy,
            WalletPolicy::default(),
            PortsMethods::Recording,
        )
    }

    /// As [`Self::new`], the payer's wallet configured with `policy`.
    pub fn with_payer_policy(policy: WalletPolicy) -> Self {
        Self::with_parties(
            (0, None),
            (0, None),
            WalletPolicy::default(),
            policy,
            PortsMethods::Recording,
        )
    }

    /// As [`Self::new`], the issuer's wallet claiming the domain `issuer` and the payer's the
    /// domain `payer`, where one is given.
    pub fn with_domains(issuer: Option<&str>, payer: Option<&str>) -> Self {
        Self::with_parties(
            (0, issuer),
            (0, payer),
            WalletPolicy::default(),
            WalletPolicy::default(),
            PortsMethods::Recording,
        )
    }

    /// As [`Self::new`], the issuer's ports holding `methods`.
    pub fn with_issuer_methods(methods: PortsMethods) -> Self {
        Self::with_parties(
            (0, None),
            (0, None),
            WalletPolicy::default(),
            WalletPolicy::default(),
            methods,
        )
    }

    fn with_parties(
        issuer: (u16, Option<&str>),
        payer: (u16, Option<&str>),
        issuer_policy: WalletPolicy,
        payer_policy: WalletPolicy,
        issuer_methods: PortsMethods,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let relay = MockRelay::new(RelayNetwork::Floonet);
        // The contacts read their mailboxes by push only.
        relay.offer_mux(true);
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
        let issuer = Party::with_domain(
            ISSUER_MNEMONIC,
            "issuer",
            1,
            issuer.0,
            issuer.1,
            issuer_policy,
            issuer_methods,
            &node,
            &relay,
            &runtime,
        );
        let payer = Party::with_domain(
            PAYER_MNEMONIC,
            "payer",
            2,
            payer.0,
            payer.1,
            payer_policy,
            PortsMethods::Recording,
            &node,
            &relay,
            &runtime,
        );
        payer.fund(0, FUNDING);
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

    /// Puts both parties' unspent and locked outputs on the node's chain, once each, then refreshes each
    /// party until it has confirmed the tip, as a wallet that has refreshed after its restore
    /// scan has: a later post of a payment waits for a confirmed tip. Call it once.
    pub fn confirm_tips(&self) {
        for party in [&self.issuer, &self.payer] {
            for status in [OutputStatus::Unspent, OutputStatus::Locked] {
                for output in party.read(|repos| repos.outputs(ACCOUNT, Some(status))) {
                    put_on_chain(&self.node, &output.id, output.height);
                }
            }
        }
        for party in [&self.issuer, &self.payer] {
            for _ in 0..2 {
                if party.wallet.confirmed_tip().unwrap().is_some() {
                    break;
                }
                self.block_on(party.wallet.refresh()).unwrap();
            }
            assert!(party.wallet.confirmed_tip().unwrap().is_some());
        }
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

    /// A wallet on a seed of its own, unfunded.
    pub fn stranger(&self) -> Party {
        Party::new(
            STRANGER_MNEMONIC,
            "stranger",
            5,
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
