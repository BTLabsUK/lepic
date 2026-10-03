//! A LEPIC party: the `lepic-wallet` engine on an in-memory store, reaching the test node through
//! `lepic-node`'s HTTP transport and exchanging slates through `lepic-transport`'s file method.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use jiff::Timestamp;
use lepic_keychain::vault::BackendError;
use lepic_keychain::{KdfParams, Vault, VaultError, VaultStorage};
use lepic_node::{
    CallPolicy, HttpSettings, HttpTransport, NodeClient, Propagation, RetryPolicy,
    webpki_tls_config,
};
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_slate::codec::WireSlate;
use lepic_slate::model::ProofAddress;
use lepic_store::{
    AccountIndex, CONTEXT_KEY_LEN, ContextKey, MemoryStore, StoreError, WalletStore,
};
use lepic_transport::file::{FILE, FileTransport};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::Location;
use lepic_wallet::event::Event;
use lepic_wallet::invoice::{InvoiceRequest, PayRequest};
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{
    Clock, NodeEndpoint, Password, Ports, ReceiveRequest, SecretVault, SecretVaultError, SharedRng,
    StoreOpener, Wallet, WalletConfig, WalletName,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::runtime::Runtime;

use super::view::{
    BalanceView, OutputView, PartyView, TxView, upstream_output_status, upstream_states,
};
use super::{Offer, Party, Pay};

/// The network LEPIC runs on against the upstream test chain. Below the first header version
/// change both floonet and the test chain behave alike for everything the file method uses.
const NETWORK: Network = Network::Floonet;
const ACCOUNT: AccountIndex = AccountIndex(0);
/// What the upstream CLI passes as `-c` in these tests.
const MINIMUM_CONFIRMATIONS: u64 = 1;

type Engine = Wallet<NodeClient<HttpTransport>, MemoryStores, TestVault>;

pub struct LepicParty {
    name: &'static str,
    runtime: Runtime,
    wallet: Engine,
    stores: MemoryStores,
    data_dir: PathBuf,
    mnemonic: String,
}

impl LepicParty {
    /// Restores the wallet from a mnemonic, as a user restoring from the recovery phrase does.
    pub fn restore(name: &'static str, mnemonic: &str, node_url: &str, seed: u64) -> LepicParty {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let stores = MemoryStores::default();
        let data_dir = PathBuf::from(format!("/lepic-{name}"));
        let mut transports = TransportRegistry::new();
        transports.register(Box::new(FileTransport::new())).unwrap();
        let node = NodeClient::new(
            HttpTransport::new(
                node_url,
                &HttpSettings::default(),
                webpki_tls_config().unwrap(),
            )
            .unwrap(),
            CallPolicy {
                retry: RetryPolicy::NONE,
                ..CallPolicy::default()
            },
        );
        let config = WalletConfig {
            name: WalletName::new(name).unwrap(),
            network: NETWORK,
            data_dir: data_dir.clone(),
            node: NodeEndpoint::parse(node_url).unwrap(),
            transports: vec![FILE],
        };
        let ports = Ports {
            node,
            stores: stores.clone(),
            secrets: TestVault::default(),
            transports,
            clock: Arc::new(FixedClock(Timestamp::from_second(1_790_000_000).unwrap())),
            rng: SharedRng::new(StdRng::seed_from_u64(seed)),
            runtime: runtime.handle().clone(),
        };
        let wallet = Wallet::new(config, ports).unwrap();
        runtime
            .block_on(wallet.restore(password(), mnemonic))
            .unwrap();
        runtime
            .block_on(wallet.scan(ScanOptions::restore(NETWORK), &ScanCancel::new()))
            .unwrap();
        LepicParty {
            name,
            runtime,
            wallet,
            stores,
            data_dir,
            mnemonic: mnemonic.to_owned(),
        }
    }

    fn import(&self, path: &Path) -> WireSlate {
        let exchange = self
            .wallet
            .ports()
            .transports
            .get(FILE)
            .unwrap()
            .exchange()
            .unwrap();
        self.runtime
            .block_on(exchange.import(&Location::File(path.to_path_buf())))
            .unwrap_or_else(|e| panic!("{}: lepic could not read {path:?}: {e}", self.name))
    }

    fn export(&self, wire: &WireSlate, path: &Path) {
        let exchange = self
            .wallet
            .ports()
            .transports
            .get(FILE)
            .unwrap()
            .exchange()
            .unwrap();
        self.runtime
            .block_on(exchange.export(wire, &Location::File(path.to_path_buf())))
            .unwrap();
    }

    fn store(&self) -> MemoryStore {
        self.stores.store(&self.data_dir)
    }
}

fn export_to(path: &Path) -> Delivery {
    Delivery::Export {
        transport: FILE,
        to: Location::File(path.to_path_buf()),
    }
}

impl Party for LepicParty {
    fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    fn send(&mut self, out: &Path, offer: &Offer) -> String {
        let mut request = SendRequest::new(ACCOUNT, Amount::new(offer.amount));
        request.minimum_confirmations = MINIMUM_CONFIRMATIONS;
        request.strategy = SelectionStrategy::Smallest;
        request.ttl_blocks = offer.ttl_blocks;
        request.message = offer.message.clone();
        request.payment_proof_recipient = offer
            .proof_to
            .map(|bytes| ProofAddress::from_bytes(bytes).unwrap());
        let sent = self
            .runtime
            .block_on(self.wallet.send(request, export_to(out)))
            .unwrap_or_else(|e| panic!("{}: lepic send failed: {e:?}", self.name));
        sent.slate_id.to_string()
    }

    fn receive(&mut self, input: &Path, out: &Path, message: Option<&str>) -> String {
        let wire = self.import(input);
        let request = ReceiveRequest {
            account: None,
            message: message.map(str::to_owned),
        };
        let received = self
            .runtime
            .block_on(self.wallet.receive(FILE, &wire, request))
            .unwrap_or_else(|e| panic!("{}: lepic receive failed: {e:?}", self.name));
        self.export(&received.reply, out);
        received.slate.id().to_string()
    }

    fn finalize_and_post(&mut self, input: &Path) {
        let wire = self.import(input);
        self.runtime
            .block_on(self.wallet.finalize(FILE, &wire, Propagation::Fluff))
            .unwrap_or_else(|e| panic!("{}: lepic finalize failed: {e:?}", self.name));
    }

    fn issue_invoice(&mut self, out: &Path, amount: u64, message: Option<&str>) -> String {
        let request = InvoiceRequest {
            account: ACCOUNT,
            amount: Amount::new(amount),
            message: message.map(str::to_owned),
        };
        let issued = self
            .runtime
            .block_on(self.wallet.issue_invoice(request, export_to(out)))
            .unwrap_or_else(|e| panic!("{}: lepic issue_invoice failed: {e:?}", self.name));
        issued.slate_id.to_string()
    }

    fn pay_invoice(&mut self, input: &Path, out: &Path, pay: &Pay) -> String {
        let wire = self.import(input);
        let mut request = PayRequest::new(ACCOUNT, Amount::new(pay.amount));
        request.minimum_confirmations = MINIMUM_CONFIRMATIONS;
        request.strategy = SelectionStrategy::Smallest;
        request.ttl_blocks = pay.ttl_blocks;
        request.message = pay.message.clone();
        let paid = self
            .runtime
            .block_on(self.wallet.pay_invoice(FILE, &wire, request))
            .unwrap_or_else(|e| panic!("{}: lepic pay_invoice failed: {e:?}", self.name));
        self.export(&paid.reply, out);
        paid.slate.id().to_string()
    }

    fn finalize_invoice_and_post(&mut self, input: &Path) {
        let wire = self.import(input);
        self.runtime
            .block_on(
                self.wallet
                    .finalize_invoice(FILE, &wire, Propagation::Fluff),
            )
            .unwrap_or_else(|e| panic!("{}: lepic finalize_invoice failed: {e:?}", self.name));
    }

    fn refresh(&mut self) {
        self.runtime
            .block_on(self.wallet.refresh())
            .unwrap_or_else(|e| panic!("{}: lepic refresh failed: {e:?}", self.name));
    }

    /// Refreshes once more to read the balance event, since the engine reports balances only
    /// through events. A second refresh right after the first changes nothing.
    fn view(&mut self, slate_id: Option<&str>) -> PartyView {
        let mut events = self.wallet.subscribe();
        self.refresh();
        let mut balance = None;
        while let Ok(event) = events.try_recv() {
            if let Event::Balance(b) = event
                && b.account == ACCOUNT
            {
                balance = Some(BalanceView {
                    total: b.total.value(),
                    spendable: b.spendable.value(),
                    awaiting_confirmation: b.awaiting_confirmation.value(),
                    awaiting_finalization: b.awaiting_finalization.value(),
                    immature: b.immature.value(),
                    locked: b.locked.value(),
                });
            }
        }
        let balance = balance.unwrap_or_else(|| panic!("{}: no balance event", self.name));
        let (outputs, tx) = self
            .store()
            .read(|repos| {
                let mut outputs: Vec<OutputView> = repos
                    .outputs(ACCOUNT, None)?
                    .iter()
                    .map(|o| OutputView {
                        commit: o.id.commitment.to_hex(),
                        value: o.amount.value(),
                        status: upstream_output_status(o.status),
                    })
                    .collect();
                outputs.sort();
                let tx = match slate_id {
                    Some(id) => repos
                        .transactions(ACCOUNT)?
                        .into_iter()
                        .find(|t| t.entry.slate_id.is_some_and(|s| s.to_string() == id))
                        .map(|t| tx_view(&t.entry)),
                    None => None,
                };
                Ok::<_, StoreError>((outputs, tx))
            })
            .unwrap();
        PartyView {
            balance,
            outputs,
            tx,
        }
    }
}

/// LEPIC records no TTL, stored transaction or messages on its entries, so those are not
/// compared for it.
fn tx_view(entry: &lepic_store::TransactionEntry) -> TxView {
    TxView {
        upstream_states: upstream_states(entry.direction, entry.state),
        amount_credited: entry.amount_credited.value(),
        amount_debited: entry.amount_debited.value(),
        fee: entry.fee.map(|f| f.value()),
        ttl_cutoff_height: None,
        stored_tx: None,
        messages: None,
        kernel_excess: None,
    }
}

fn password() -> Password {
    Password::new("differential".to_owned())
}

struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// Memory stores by data directory; clones share them, so the test reads what the engine wrote.
#[derive(Clone, Default)]
struct MemoryStores {
    stores: Arc<Mutex<std::collections::BTreeMap<PathBuf, MemoryStore>>>,
}

impl MemoryStores {
    fn store(&self, data_dir: &Path) -> MemoryStore {
        self.stores
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(data_dir)
            .unwrap()
            .reopen(ContextKey::from_bytes([0; CONTEXT_KEY_LEN]))
    }
}

impl StoreOpener for MemoryStores {
    type Store = MemoryStore;

    fn open(&self, data_dir: &Path, key: ContextKey) -> Result<MemoryStore, StoreError> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        let store = stores
            .entry(data_dir.to_owned())
            .or_insert_with(|| MemoryStore::new(ContextKey::from_bytes([0; CONTEXT_KEY_LEN])));
        Ok(store.reopen(key))
    }
}

#[derive(Clone, Default)]
struct SharedVaultStorage(Arc<Mutex<Option<Vec<u8>>>>);

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

/// The desktop vault with the cheapest Argon2 setting, so the tests stay fast.
#[derive(Clone, Default)]
struct TestVault {
    storage: SharedVaultStorage,
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
        Ok(self.storage.load().unwrap().is_some())
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
