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
use lepic_epicbox::marker::v3::carries_lepic_marker;
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
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{Codec, WireSlate};
use lepic_slate::stage::Stage;
use lepic_store::{
    AccountIndex, KeyId, MemoryStore, OutputRecord, OutputStatus, PeerCompat, PendingInvoice,
    PendingInvoiceStatus, Repositories, StoreError, StoreKeys, WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::policy::FormatPolicy;
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{
    BoxFuture, Destination, Inbound, Outbound, Transport, TransportId,
};
use lepic_wallet::inbox::InboxSummary;
use lepic_wallet::invoice::{InvoiceRequest, IssuedInvoice, PayRequest};
use lepic_wallet::peer_compat::{PeerFacts, PeerKind};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::Delivery;
use lepic_wallet::{
    Clock, NodeEndpoint, Ports, SharedRng, StoreOpener, Wallet, WalletConfig, WalletName,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use uuid::Uuid;

use crate::support::{TestVault, complete_restore_scan, fixed_time, password};

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
    pub epicbox: EpicboxTransport,
    /// The payments address, index 0, attached to `epicbox`.
    pub address: EpicboxAddress,
    pub clock: TestClock,
    delivered_to: Arc<Mutex<Vec<String>>>,
    deliveries_failing: Arc<AtomicBool>,
    stores: CountingStores,
    seed: Seed,
    data_dir: PathBuf,
    relay_connector: Arc<dyn Connector>,
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
        transports
            .register(Box::new(lepic_transport::file::FileTransport::new()))
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
            policy: Default::default(),
            offline: false,
            host_features: 0,
            profile,
        };
        let wallet = Wallet::new(config, ports).unwrap();
        lepic_wallet_contacts::install(&wallet);
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
            relay_connector: relay.connector(),
        }
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

    /// What the wallet keeps about the peer key `key`, if anything.
    pub fn peer_compat(&self, key: &str) -> Option<PeerCompat> {
        self.read(|repos| repos.peer_compat(key))
    }

    /// What the wallet derives about the peer key `key` now, when it keeps anything about it.
    pub fn peer_kind(&self, key: &str) -> Option<PeerKind> {
        self.peer_compat(key)
            .map(|compat| PeerFacts::derive(Some(compat), self.clock.now()).kind)
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

    /// Parks `i1`, an invoice from `sender`, as it is parked once it arrived: the store gains
    /// the invoice and, for a marked I1, the proof that its sender runs LEPIC.
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
        let marked = carries_lepic_marker(i1);
        self.store()
            .write(|repos| {
                if marked {
                    repos.put_peer_compat(
                        &sender.key_text(),
                        &PeerCompat {
                            last_marked_at: Some(now),
                            claimed: 1,
                            works: 1,
                            ..PeerCompat::default()
                        },
                    )?;
                }
                repos.park_invoice(&invoice)
            })
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
    }
}

pub struct World {
    pub runtime: tokio::runtime::Runtime,
    pub relay: MockRelay,
    pub node: MockNode,
    pub issuer: Party,
    pub payer: Party,
    /// What draining the payer's payments address did before an invoice reached it, for the
    /// test's next drain to report.
    carried: Mutex<InboxSummary>,
}

impl World {
    pub fn new() -> Self {
        Self::with_profiles(0, 0)
    }

    /// As [`Self::new`], the issuer's wallet configured with profile `issuer` and the payer's
    /// with `payer`.
    pub fn with_profiles(issuer: u16, payer: u16) -> Self {
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
        let issuer = Party::with_profile(
            ISSUER_MNEMONIC,
            "issuer",
            1,
            issuer,
            &node,
            &relay,
            &runtime,
        );
        let payer = Party::with_profile(PAYER_MNEMONIC, "payer", 2, payer, &node, &relay, &runtime);
        payer.fund(0, FUNDING);
        Self {
            runtime,
            relay,
            node,
            issuer,
            payer,
            carried: Mutex::default(),
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

    /// The issuer invoices the payer's payments address over Epicbox, and the payer parks it.
    /// Messages already waiting for the payer are handled first, so the invoice is at the head
    /// of its queue; [`World::take_carried`] reports what that did.
    pub fn issue(&self, message: Option<&str>) -> IssuedInvoice {
        if self.relay.pending(&self.payer.address) > 0 {
            let summary = self
                .block_on(self.payer.wallet.epicbox_drain(&self.payer.epicbox))
                .unwrap();
            let mut carried = self.carried.lock().unwrap_or_else(PoisonError::into_inner);
            *carried = add(*carried, summary);
        }
        let to = self.payer.address.clone();
        let issued = self.issue_to(&to, message);
        assert_eq!(self.deliver_invoices(), 1);
        issued
    }

    /// Takes the invoices at the head of the payer's payments address off the relay and parks
    /// each under the address it came from, as delivery to the payer parks them; the first
    /// message that is not an invoice stops it and stays. Returns how many were parked.
    pub fn deliver_invoices(&self) -> usize {
        let client = self.payer.client();
        let codec = V3JsonCodec::new(Network::Floonet.params().default_base_fee());
        self.block_on(async {
            let subscription = client.drain().unwrap();
            let mut parked = 0;
            while let Some(envelope) = self.within(subscription.next_envelope()).await.unwrap() {
                let is_i1 = codec
                    .decode(envelope.wire())
                    .is_ok_and(|slate| slate.stage() == Stage::I1);
                // The relay hands out the next message only once this one is acknowledged.
                if !is_i1 {
                    break;
                }
                let sender = EpicboxAddress::parse(
                    envelope.reply_to().unwrap().as_str(),
                    RelayNetwork::Floonet,
                )
                .unwrap();
                self.payer.park(&sender, envelope.wire());
                subscription
                    .acknowledge(envelope.ack_token())
                    .await
                    .unwrap();
                parked += 1;
            }
            subscription.stop().await.unwrap();
            parked
        })
    }

    /// What draining the payer before an invoice did since the last call.
    pub fn take_carried(&self) -> InboxSummary {
        std::mem::take(&mut *self.carried.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub fn issue_to(&self, to: &EpicboxAddress, message: Option<&str>) -> IssuedInvoice {
        self.block_on(self.issuer.wallet.issue_invoice(
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(AMOUNT),
                message: message.map(str::to_owned),
                ttl_blocks: None,
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

/// The two summaries counted together.
pub fn add(a: InboxSummary, b: InboxSummary) -> InboxSummary {
    InboxSummary {
        received: a.received + b.received,
        finalized: a.finalized + b.finalized,
        repeated: a.repeated + b.repeated,
        rejected: a.rejected + b.rejected,
        held: a.held + b.held,
        parked: a.parked + b.parked,
        bounced: a.bounced + b.bounced,
        dropped: a.dropped + b.dropped,
        notices: a.notices + b.notices,
        requeued: a.requeued + b.requeued,
    }
}

pub fn key(byte: u8) -> SecretKey {
    SecretKey::from_array([byte; 32]).unwrap()
}
