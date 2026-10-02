//! In-memory ports for engine integration tests: a store opener over `MemoryStore`, a secret
//! vault over the real `lepic-keychain` vault format, the mock node, a loopback transport, a
//! fixed clock and a seeded RNG. Later engine tasks build on these.

// Each test binary uses a different subset of these helpers, and test helpers may unwrap and
// panic (docs/rules.md).
#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use jiff::Timestamp;
use lepic_keychain::vault::BackendError;
use lepic_keychain::{KdfParams, Vault, VaultError, VaultStorage};
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{NodeClient, NodeVersion, Tip};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::params::Network;
use lepic_store::{ContextKey, MemoryStore, StoreError};
use lepic_transport::file::FilePolicy;
use lepic_transport::loopback::LoopbackTransport;
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, TransportId};
use lepic_wallet::{
    Clock, NodeEndpoint, Password, Ports, SecretVault, SecretVaultError, SharedRng, StoreOpener,
    Wallet, WalletConfig, WalletName,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::runtime::Runtime;

pub const LOOPBACK: TransportId = TransportId::new("loopback");

/// Golden vector `keys/wallet_seed_seed32`: a `wallet.seed` written by `epic-wallet`.
pub const WALLET_SEED_VECTOR: &str =
    include_str!("../../../../testdata/vectors/keys/wallet_seed_seed32.json");

pub type TestWallet = Wallet<NodeClient<MockNode>, MemoryStores, TestVault>;

/// The time the fixed clock always reports.
pub fn fixed_time() -> Timestamp {
    Timestamp::from_second(1_790_000_000).unwrap()
}

pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// Memory stores by data directory. Clones share the data, so a second wallet handle on the same
/// directory sees what the first one stored, as after an app restart.
#[derive(Clone, Default)]
pub struct MemoryStores {
    stores: Arc<Mutex<BTreeMap<PathBuf, MemoryStore>>>,
}

impl MemoryStores {
    pub fn is_empty(&self, data_dir: &Path) -> bool {
        !self
            .stores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(data_dir)
    }
}

impl StoreOpener for MemoryStores {
    type Store = MemoryStore;

    fn open(&self, data_dir: &Path, key: ContextKey) -> Result<MemoryStore, StoreError> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        let store = stores
            .entry(data_dir.to_owned())
            .or_insert_with(|| MemoryStore::new(ContextKey::from_bytes([0; 32])));
        Ok(store.reopen(key))
    }
}

/// Vault bytes shared between clones, standing in for the vault file.
#[derive(Clone, Default)]
pub struct SharedVaultStorage(Arc<Mutex<Option<Vec<u8>>>>);

impl VaultStorage for SharedVaultStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, BackendError> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }

    fn replace(&mut self, contents: &[u8]) -> Result<(), BackendError> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(contents.to_vec());
        Ok(())
    }
}

/// The desktop vault with the cheapest Argon2 setting, so tests stay fast.
#[derive(Clone, Default)]
pub struct TestVault {
    storage: SharedVaultStorage,
}

impl TestVault {
    pub fn is_created(&self) -> bool {
        self.storage.load().unwrap().is_some()
    }
}

fn vault_error(error: VaultError) -> SecretVaultError {
    match error {
        VaultError::NotFound => SecretVaultError::NotFound,
        VaultError::AlreadyExists => SecretVaultError::AlreadyExists,
        VaultError::Decryption => SecretVaultError::WrongPassword,
        other => SecretVaultError::Backend(Box::new(other)),
    }
}

impl SecretVault for TestVault {
    type Secrets = Vault<SharedVaultStorage, StdRng>;

    fn exists(&self) -> Result<bool, SecretVaultError> {
        Ok(self.is_created())
    }

    fn create(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError> {
        Vault::create(
            self.storage.clone(),
            StdRng::seed_from_u64(11),
            password.expose_bytes(),
            KdfParams::new(8, 1, 1).unwrap(),
        )
        .map_err(vault_error)
    }

    fn unlock(&self, password: &Password) -> Result<Self::Secrets, SecretVaultError> {
        Vault::open(
            self.storage.clone(),
            StdRng::seed_from_u64(12),
            password.expose_bytes(),
        )
        .map_err(vault_error)
    }
}

/// A node at height 10 with no outputs.
pub fn mock_node() -> MockNode {
    MockNode::from_chain(ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 7,
        },
        Tip {
            height: Height::new(10),
            last_block_pushed: Hash::from_slice(&[0; 32]).unwrap(),
        },
    ))
}

/// The shared side of a test: what survives between wallet handles, and the peer's end of the
/// loopback transport.
pub struct Harness {
    pub runtime: Runtime,
    pub node: MockNode,
    pub stores: MemoryStores,
    pub vault: TestVault,
    pub peer: Arc<Mutex<Option<LoopbackTransport>>>,
    pub data_dir: PathBuf,
}

impl Harness {
    pub fn new() -> Self {
        Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
            node: mock_node(),
            stores: MemoryStores::default(),
            vault: TestVault::default(),
            peer: Arc::default(),
            data_dir: PathBuf::from("/wallet-data"),
        }
    }

    pub fn config(&self, network: Network) -> WalletConfig {
        WalletConfig {
            name: WalletName::new("test").unwrap(),
            network,
            data_dir: self.data_dir.clone(),
            node: NodeEndpoint::parse("http://127.0.0.1:13413").unwrap(),
            transports: vec![LOOPBACK],
        }
    }

    /// A new handle on the harness's wallet, as after an app restart.
    pub fn wallet(&self) -> TestWallet {
        self.wallet_with(self.config(Network::Mainnet), self.vault.clone())
    }

    pub fn wallet_with(&self, config: WalletConfig, vault: TestVault) -> TestWallet {
        Wallet::new(config, self.ports(vault)).unwrap()
    }

    pub fn ports(&self, vault: TestVault) -> Ports<NodeClient<MockNode>, MemoryStores, TestVault> {
        Ports {
            node: self.node.client(),
            stores: self.stores.clone(),
            secrets: vault,
            transports: self.transports(),
            clock: Arc::new(FixedClock(fixed_time())),
            rng: SharedRng::new(StdRng::seed_from_u64(42)),
            runtime: self.runtime.handle().clone(),
        }
    }

    /// A registry holding one end of a fresh loopback pair; the other end replaces
    /// [`Harness::peer`].
    pub fn transports(&self) -> TransportRegistry {
        let (own, peer) = LoopbackTransport::pair(
            LOOPBACK,
            Arc::new(FilePolicy),
            Destination::new("wallet".to_owned()),
            Destination::new("peer".to_owned()),
        );
        *self.peer.lock().unwrap_or_else(PoisonError::into_inner) = Some(peer);
        let mut registry = TransportRegistry::new();
        registry.register(Box::new(own)).unwrap();
        registry
    }

    pub fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }
}

pub fn password(text: &str) -> Password {
    Password::new(text.to_owned())
}

/// A text field of a golden vector.
pub fn vector_text(vector: &serde_json::Value, pointer: &str) -> String {
    vector
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("vector has no text at {pointer}"))
        .to_owned()
}
