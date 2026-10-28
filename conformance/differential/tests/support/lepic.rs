// SPDX-License-Identifier: Apache-2.0
//! A LEPIC party: the `lepic-wallet` engine on an in-memory store, reaching the test node through
//! `lepic-node`'s HTTP transport and exchanging slates through `lepic-transport`'s file method.

use std::num::NonZeroUsize;
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
    AccountIndex, CONTEXT_KEY_LEN, ContextKey, MemoryStore, StoreError, StoredTransaction,
    TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::file::{FILE, FileTransport};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::Location;
use lepic_wallet::event::Event;
use lepic_wallet::invoice::{InvoiceRequest, PayRequest};
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use lepic_wallet::{
    Clock, FinalizeError, NodeEndpoint, Password, Ports, ReceiveError, ReceiveRequest, SecretVault,
    SecretVaultError, SharedRng, StoreOpener, Wallet, WalletConfig, WalletName,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::runtime::Runtime;

use super::faults::{CrashPoint, Faults, FaultyStore};
use super::view::{
    BalanceView, OutputView, PartyView, TxView, upstream_output_status, upstream_states,
};
use super::{Offer, Party, Pay, Spend};

/// The network LEPIC runs on against the upstream test chain. Below the first header version
/// change both floonet and the test chain behave alike for everything the file method uses.
const NETWORK: Network = Network::Floonet;
const ACCOUNT: AccountIndex = AccountIndex(0);

type Engine = Wallet<NodeClient<HttpTransport>, MemoryStores, TestVault>;

/// How a step that LEPIC was stopped in ended, once LEPIC was reopened and the step tried
/// again the way a user retries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// The step made fewer writes than the crash point, so it was not stopped.
    NotStopped,
    /// The retry completed the step on the slate it started.
    Completed,
    /// The retry refused the slate, because the step had stored a reply the file method cannot
    /// write again. The receiver cancelled its transaction; the sender must start over.
    Refused,
}

/// What the user does after a send was stopped with its slate stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRetry {
    /// Delivers the stored slate again, as the engine documents.
    ResendWaiting,
    /// Sends again as if nothing was stored. Only the soak's self-test does this.
    SendAgain,
}

pub struct LepicParty {
    name: &'static str,
    runtime: Runtime,
    wallet: Engine,
    stores: MemoryStores,
    vault: TestVault,
    node_url: String,
    /// Seeds the random number generator of the next wallet handle.
    next_seed: u64,
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
        let vault = TestVault::default();
        let data_dir = PathBuf::from(format!("/lepic-{name}"));
        let wallet = engine(name, node_url, &data_dir, &stores, &vault, &runtime, seed);
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
            vault,
            node_url: node_url.to_owned(),
            next_seed: seed.wrapping_add(1),
            data_dir,
            mnemonic: mnemonic.to_owned(),
        }
    }

    /// Replaces the wallet handle with a new one on the same database and secret storage and
    /// opens it with the password, as an app does after the OS stopped it.
    pub fn reopen(&mut self) {
        let wallet = engine(
            self.name,
            &self.node_url,
            &self.data_dir,
            &self.stores,
            &self.vault,
            &self.runtime,
            self.next_seed,
        );
        self.next_seed = self.next_seed.wrapping_add(1);
        self.runtime
            .block_on(wallet.open(password()))
            .unwrap_or_else(|e| panic!("{}: lepic reopen failed: {e:?}", self.name));
        self.wallet = wallet;
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

    fn transactions(&self) -> Vec<StoredTransaction> {
        self.store()
            .read(|repos| repos.transactions(ACCOUNT))
            .unwrap()
    }

    fn try_send(&self, out: &Path, offer: &Offer) -> Result<String, SendError> {
        let mut request = SendRequest::new(ACCOUNT, Amount::new(offer.amount));
        request.minimum_confirmations = offer.spend.minimum_confirmations;
        request.strategy = strategy(&offer.spend);
        request.change_outputs = change_outputs(&offer.spend);
        request.ttl_blocks = offer.ttl_blocks;
        request.message = offer.message.clone();
        request.payment_proof_recipient = offer
            .proof_to
            .map(|bytes| ProofAddress::from_bytes(bytes).unwrap());
        let sent = self
            .runtime
            .block_on(self.wallet.send(request, export_to(out)))?;
        Ok(sent.slate_id.to_string())
    }

    fn try_receive(
        &self,
        input: &Path,
        out: &Path,
        message: Option<&str>,
    ) -> Result<String, ReceiveError> {
        let wire = self.import(input);
        let request = ReceiveRequest {
            account: None,
            message: message.map(str::to_owned),
        };
        let received = self
            .runtime
            .block_on(self.wallet.receive(FILE, &wire, request))?;
        self.export(&received.reply, out);
        Ok(received.slate.id().to_string())
    }

    fn try_finalize(&self, input: &Path) -> Result<(), FinalizeError> {
        let wire = self.import(input);
        self.runtime
            .block_on(self.wallet.finalize(FILE, &wire, Propagation::Fluff))?;
        Ok(())
    }

    /// Runs `step` with the store armed to stop at `point`. Returns the step's result and
    /// whether it was stopped; a stopped wallet is reopened.
    fn stopping<R>(&mut self, point: CrashPoint, step: impl FnOnce(&Self) -> R) -> (R, bool) {
        self.stores.faults.arm(point);
        let result = step(self);
        let stopped = self.stores.faults.disarm();
        if stopped {
            self.reopen();
        }
        (result, stopped)
    }

    /// Sends, stopped at `point`. After a stop the user finds the stored transaction waiting
    /// and delivers it again, or sends again when nothing was stored. Returns the slate id.
    pub fn send_stopped(
        &mut self,
        out: &Path,
        offer: &Offer,
        point: CrashPoint,
        retry: SendRetry,
    ) -> (String, Recovery) {
        let before: Vec<TxId> = self.transactions().iter().map(|t| t.id).collect();
        let (first, stopped) = self.stopping(point, |party| party.try_send(out, offer));
        if !stopped {
            let slate_id =
                first.unwrap_or_else(|e| panic!("{}: lepic send failed: {e:?}", self.name));
            return (slate_id, Recovery::NotStopped);
        }
        let waiting = self.transactions().into_iter().find(|t| {
            retry == SendRetry::ResendWaiting
                && !before.contains(&t.id)
                && t.entry.direction == TxDirection::Outgoing
                && t.entry.state == TxState::Sent
        });
        let slate_id = match waiting {
            Some(waiting) => {
                self.runtime
                    .block_on(self.wallet.resend(waiting.id, export_to(out)))
                    .unwrap_or_else(|e| panic!("{}: lepic resend failed: {e:?}", self.name));
                waiting.entry.slate_id.unwrap().to_string()
            }
            None => self
                .try_send(out, offer)
                .unwrap_or_else(|e| panic!("{}: lepic send again failed: {e:?}", self.name)),
        };
        (slate_id, Recovery::Completed)
    }

    /// Receives, stopped at `point`. After a stop the user receives the same file again.
    pub fn receive_stopped(
        &mut self,
        input: &Path,
        out: &Path,
        message: Option<&str>,
        point: CrashPoint,
    ) -> (Option<String>, Recovery) {
        let (first, stopped) = self.stopping(point, |party| party.try_receive(input, out, message));
        if !stopped {
            let slate_id =
                first.unwrap_or_else(|e| panic!("{}: lepic receive failed: {e:?}", self.name));
            return (Some(slate_id), Recovery::NotStopped);
        }
        match self.try_receive(input, out, message) {
            Ok(slate_id) => (Some(slate_id), Recovery::Completed),
            Err(ReceiveError::AlreadyReceived { tx_id, .. }) => {
                self.runtime
                    .block_on(self.wallet.cancel(tx_id))
                    .unwrap_or_else(|e| panic!("{}: lepic cancel failed: {e:?}", self.name));
                (None, Recovery::Refused)
            }
            Err(e) => panic!("{}: lepic receive again failed: {e:?}", self.name),
        }
    }

    /// Finalizes and posts, stopped at `point`. After a stop the user finalizes the same file
    /// again.
    pub fn finalize_stopped(&mut self, input: &Path, point: CrashPoint) -> Recovery {
        let (first, stopped) = self.stopping(point, |party| party.try_finalize(input));
        if !stopped {
            first.unwrap_or_else(|e| panic!("{}: lepic finalize failed: {e:?}", self.name));
            return Recovery::NotStopped;
        }
        self.try_finalize(input)
            .unwrap_or_else(|e| panic!("{}: lepic finalize again failed: {e:?}", self.name));
        Recovery::Completed
    }
}

fn engine(
    name: &str,
    node_url: &str,
    data_dir: &Path,
    stores: &MemoryStores,
    vault: &TestVault,
    runtime: &Runtime,
    seed: u64,
) -> Engine {
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
        data_dir: data_dir.to_path_buf(),
        node: NodeEndpoint::parse(node_url).unwrap(),
        transports: vec![FILE],
    };
    let ports = Ports {
        node,
        stores: stores.clone(),
        secrets: vault.clone(),
        transports,
        clock: Arc::new(FixedClock(Timestamp::from_second(1_790_000_000).unwrap())),
        rng: SharedRng::new(StdRng::seed_from_u64(seed)),
        runtime: runtime.handle().clone(),
    };
    Wallet::new(config, ports).unwrap()
}

fn strategy(spend: &Spend) -> SelectionStrategy {
    if spend.use_all {
        SelectionStrategy::All
    } else {
        SelectionStrategy::Smallest
    }
}

fn change_outputs(spend: &Spend) -> NonZeroUsize {
    NonZeroUsize::new(usize::try_from(spend.change_outputs).unwrap()).unwrap()
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
        self.try_send(out, offer)
            .unwrap_or_else(|e| panic!("{}: lepic send failed: {e:?}", self.name))
    }

    fn receive(&mut self, input: &Path, out: &Path, message: Option<&str>) -> String {
        self.try_receive(input, out, message)
            .unwrap_or_else(|e| panic!("{}: lepic receive failed: {e:?}", self.name))
    }

    fn finalize_and_post(&mut self, input: &Path) {
        self.try_finalize(input)
            .unwrap_or_else(|e| panic!("{}: lepic finalize failed: {e:?}", self.name));
    }

    fn issue_invoice(&mut self, out: &Path, amount: u64, message: Option<&str>) -> String {
        let request = InvoiceRequest {
            account: ACCOUNT,
            amount: Amount::new(amount),
            message: message.map(str::to_owned),
            ttl_blocks: None,
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
        request.minimum_confirmations = pay.spend.minimum_confirmations;
        request.strategy = strategy(&pay.spend);
        request.change_outputs = change_outputs(&pay.spend);
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

    fn cancel(&mut self, slate_id: &str) {
        let tx = self
            .transactions()
            .into_iter()
            .find(|t| t.entry.slate_id.is_some_and(|s| s.to_string() == slate_id))
            .unwrap_or_else(|| panic!("{}: no transaction for {slate_id}", self.name));
        self.runtime
            .block_on(self.wallet.cancel(tx.id))
            .unwrap_or_else(|e| panic!("{}: lepic cancel failed: {e:?}", self.name));
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
        let (outputs, entries, tx) = self
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
                let transactions = repos.transactions(ACCOUNT)?;
                let tx = slate_id.and_then(|id| {
                    transactions
                        .iter()
                        .find(|t| t.entry.slate_id.is_some_and(|s| s.to_string() == id))
                        .map(|t| tx_view(&t.entry))
                });
                Ok::<_, StoreError>((outputs, transactions.len(), tx))
            })
            .unwrap();
        PartyView {
            balance,
            outputs,
            entries,
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
/// The engine's handles obey the shared crash plan; the test's own handles do not.
#[derive(Clone, Default)]
struct MemoryStores {
    stores: Arc<Mutex<std::collections::BTreeMap<PathBuf, MemoryStore>>>,
    faults: Faults,
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
    type Store = FaultyStore;

    fn open(&self, data_dir: &Path, key: ContextKey) -> Result<FaultyStore, StoreError> {
        let mut stores = self.stores.lock().unwrap_or_else(PoisonError::into_inner);
        let store = stores
            .entry(data_dir.to_owned())
            .or_insert_with(|| MemoryStore::new(ContextKey::from_bytes([0; CONTEXT_KEY_LEN])));
        Ok(FaultyStore {
            inner: store.reopen(key),
            faults: self.faults.clone(),
        })
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
