// SPDX-License-Identifier: Apache-2.0
//! A party to the invoice flow over in-memory ports: a wallet restored from a mnemonic, the
//! file transport on one end of a loopback pair, a mock node shared with the other party, and
//! an RNG that repeats the byte 1, which gives the nonces `epic-wallet`'s test-RNG mode uses.

// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_node::mock::MockNode;
use lepic_node::{NodeClient, Propagation};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_slate::codec::WireSlate;
use lepic_store::{
    AccountIndex, ContextKey, KeyId, MemoryStore, OutputRecord, OutputStatus, Repositories,
    StoreError, WalletStore,
};
use lepic_transport::file::{FILE, FilePolicy};
use lepic_transport::loopback::LoopbackTransport;
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::invoice::{InvoiceError, InvoiceRequest, IssuedInvoice, PaidInvoice, PayRequest};
use lepic_wallet::send::Delivery;
use lepic_wallet::{Finalized, NodeEndpoint, Ports, SharedRng, Wallet, WalletConfig, WalletName};
use rand_core::{TryCryptoRng, TryRng};
use tokio::runtime::Runtime;

use crate::support::{
    FixedClock, MemoryStores, TestVault, complete_restore_scan, fixed_time, password,
};

pub const ACCOUNT: AccountIndex = AccountIndex(0);

/// The issuer of the G-03 invoice cases.
pub const ISSUER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal \
    winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The payer of the G-03 invoice cases.
pub const PAYER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

/// The coinbase output every G-03 invoice case pays from: key `m/0/0/0`, mined at height 1.
pub const FUNDING: u64 = 1_457_920_000;

const DATA_DIR: &str = "/invoice-party";

/// Repeats one byte. With 1 it yields the secret nonces `[1; 32]` that upstream's test-RNG mode
/// uses for the partial signature and the message signature.
pub struct RepeatingRng(pub u8);

impl TryRng for RepeatingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

pub type PartyWallet = Wallet<NodeClient<MockNode>, MemoryStores, TestVault>;

pub struct Party {
    runtime: Runtime,
    stores: MemoryStores,
    seed: Seed,
    pub keychain: Keychain,
    pub wallet: PartyWallet,
    /// The other end of the wallet's file transport.
    pub peer: LoopbackTransport,
}

impl Party {
    /// The wallet restored and scanned, ready to issue and pay.
    pub fn new(mnemonic: &str, node: &MockNode) -> Self {
        let party = Self::restored_without_scan(mnemonic, node);
        complete_restore_scan(&party.runtime, &party.wallet);
        party
    }

    /// The wallet restored onto an empty database, before the scan it needs.
    pub fn restored_without_scan(mnemonic: &str, node: &MockNode) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let stores = MemoryStores::default();
        let (own, peer) = LoopbackTransport::pair(
            FILE,
            Arc::new(FilePolicy),
            Destination::new("own".to_owned()),
            Destination::new("peer".to_owned()),
        );
        let mut transports = TransportRegistry::new();
        transports.register(Box::new(own)).unwrap();
        let ports = Ports {
            node: node.client(),
            stores: stores.clone(),
            secrets: TestVault::default(),
            transports,
            clock: Arc::new(FixedClock(fixed_time())),
            rng: SharedRng::new(RepeatingRng(1)),
            runtime: runtime.handle().clone(),
        };
        let config = WalletConfig {
            name: WalletName::new("invoice").unwrap(),
            network: Network::Floonet,
            data_dir: PathBuf::from(DATA_DIR),
            node: NodeEndpoint::parse("http://127.0.0.1:13413").unwrap(),
            transports: vec![FILE],
        };
        let wallet = Wallet::new(config, ports).unwrap();
        runtime
            .block_on(wallet.restore(password("invoice party"), mnemonic))
            .unwrap();
        let seed = Seed::from_mnemonic(mnemonic).unwrap();
        Self {
            runtime,
            stores,
            keychain: Keychain::from_seed(&seed, Network::Floonet).unwrap(),
            seed,
            wallet,
            peer,
        }
    }

    pub fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }

    /// The wallet's database, opened with the key the engine seals contexts under.
    pub fn store(&self) -> MemoryStore {
        let mut mac =
            <Blake2bMac<U32> as KeyInit>::new_from_slice(self.seed.expose_bytes()).unwrap();
        mac.update(b"lepic-wallet private context key v1");
        let key = ContextKey::from_bytes(mac.finalize_fixed().into());
        lepic_wallet::StoreOpener::open(&self.stores, Path::new(DATA_DIR), key).unwrap()
    }

    pub fn read<T>(&self, read: impl FnOnce(&dyn Repositories) -> Result<T, StoreError>) -> T {
        self.store().read(read).unwrap()
    }

    /// Adds an unspent coinbase output of `value` at child `child`, mined at height 1.
    pub fn fund(&self, child: u32, value: u64) {
        let id = Identifier::new(3, [0, 0, child, 0]).unwrap();
        let output = OutputRecord {
            id: OutputIdentifier::new(
                OutputFeatures::Coinbase,
                self.keychain
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
            .write(|repos| repos.put_output(&output))
            .unwrap();
    }

    /// Moves the default account's key counter to `child`, the child the next output takes.
    pub fn set_next_child(&self, child: u32) {
        self.store()
            .write(|repos| {
                let mut account = repos.account(ACCOUNT)?.unwrap();
                account.next_child = child;
                repos.put_account(&account)
            })
            .unwrap();
    }

    pub fn issue(&self, amount: u64, message: Option<&str>) -> Result<IssuedInvoice, InvoiceError> {
        self.issue_with_ttl(amount, message, None)
    }

    pub fn issue_with_ttl(
        &self,
        amount: u64,
        message: Option<&str>,
        ttl_blocks: Option<u64>,
    ) -> Result<IssuedInvoice, InvoiceError> {
        self.block_on(self.wallet.issue_invoice(
            InvoiceRequest {
                account: ACCOUNT,
                amount: Amount::new(amount),
                message: message.map(str::to_owned),
                ttl_blocks,
            },
            Delivery::Deliver {
                transport: FILE,
                to: Destination::new("peer".to_owned()),
            },
        ))
    }

    pub fn pay(&self, wire: &WireSlate, request: PayRequest) -> Result<PaidInvoice, InvoiceError> {
        self.block_on(self.wallet.pay_invoice(FILE, wire, request))
    }

    pub fn finalize(&self, wire: &WireSlate) -> Result<Finalized, InvoiceError> {
        self.block_on(self.wallet.finalize_invoice(FILE, wire, Propagation::Stem))
    }

    /// The next slate the peer end of the file transport received.
    pub fn delivered(&self) -> Option<WireSlate> {
        self.block_on(self.peer.next_envelope())
            .unwrap()
            .map(|envelope| envelope.wire().clone())
    }
}
