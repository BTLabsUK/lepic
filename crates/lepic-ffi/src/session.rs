//! One open wallet: the engine over the binding's ports, and the glue between engine calls,
//! the app's secret store and Dart streams.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use jiff::Timestamp;
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{
    ClientSettings, Domain, EpicboxAddress, Network as RelayNetwork, RelayEndpoint, Security,
    TRANSPORT_ID, TcpConnector,
};
use lepic_keychain::vault::SecretName;
use lepic_keychain::{SecretStore as _, Seed, Vault};
use lepic_node::{NodeApi as _, Propagation, webpki_tls_config};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, TxId, TxState};
use lepic_transport::file::{FILE, FileTransport, response_path};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Exchange as _, Location};
use lepic_wallet::details::TransactionDetails as EngineTransactionDetails;
use lepic_wallet::event::{Balance, TransportState as EngineTransportState};
use lepic_wallet::inbox::ListenHandle;
use lepic_wallet::legacy_history::{
    ImportWorkDir, LegacyImportOutcome, LegacyImportStatus as EngineLegacyStatus,
    TxOrigin as EngineTxOrigin,
};
use lepic_wallet::refresh::{BALANCE_MINIMUM_CONFIRMATIONS, RefreshOutcome};
use lepic_wallet::scan::{ScanCancel, ScanOptions, ScanStart};
use lepic_wallet::selection::Selection;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::{
    Clock, DATABASE_FILE, Event, NodeEndpoint, Password, Ports, ReceiveRequest, SessionState,
    SharedRng, SqliteStores, Wallet, WalletName, WordCount,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::{DirClaim, RuntimeInner};
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    FeeEstimate, FinalizedTx, ImportedTx, InboxReport, LegacyImport, LegacyImportStatus,
    ListenerEvent, ListenerEventKind, NodeTip, ReceivedSlate, ScanProgress, SentTx, Slate,
    SlateMessage, TransactionDetails, TransportState, TxOrigin, TxStatus, WalletConfig,
    WalletEvent, WalletEventKind, WalletSummary,
};
use crate::frb_generated::StreamSink;
use crate::node::{Node, NodeSecret, node_error};
use crate::vault_port::{AppVault, SharedStorage, VAULT_KEY, VaultBytes, vault_error};

mod app_data;
mod http;
mod tor;

#[cfg(test)]
pub(crate) use http::HttpReport;
#[cfg(test)]
pub(crate) use tor::TorReport;
mod invoice;

type EngineWallet = Wallet<Node, SqliteStores, AppVault>;

/// Matches the name `lepic-wallet` stores the seed under in the wallet's vault.
const SEED_SECRET: &str = "wallet/seed";

/// The name of the wallet in logs. The binding opens one wallet per data directory.
const WALLET_NAME: &str = "default";

const DEFAULT_ACCOUNT: AccountIndex = AccountIndex(0);

/// The longest slate text the file method imports, checked before the text is written to a
/// scratch file.
const MAX_SLATE_TEXT_LEN: usize = lepic_transport::file::MAX_WIRE_SLATE_LEN;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// Where a new wallet's seed comes from.
pub(crate) enum SeedOrigin {
    Generate,
    /// A recovery phrase the user typed.
    Phrase(Zeroizing<String>),
    /// The text of an `epic-wallet` `wallet.seed` file and the password it was written with.
    SeedFile {
        text: String,
        password: Zeroizing<String>,
    },
}

impl SeedOrigin {
    pub(crate) fn phrase(mnemonic: Option<Zeroizing<String>>) -> Self {
        mnemonic.map_or(Self::Generate, Self::Phrase)
    }
}

pub(crate) struct Session {
    engine: EngineWallet,
    network: Network,
    data_dir: PathBuf,
    store: AppSecretStore,
    vault: VaultBytes,
    epicbox: Option<EpicboxTransport>,
    listener: Mutex<Option<ListenHandle>>,
    /// Holds the answers of HTTP sends until they are finalized.
    http: lepic_foreign::HttpTransport,
    http_listener: Mutex<http::HttpListener>,
    http_starts: AtomicU64,
    /// Holds the answers of Tor sends until they are finalized.
    tor: lepic_tor::TorTransport,
    tor_slot: Mutex<tor::TorSlot>,
    tor_starts: AtomicU64,
    #[cfg(test)]
    tor_timings: Mutex<Option<lepic_tor::TorTimings>>,
    scan: Mutex<Option<ScanCancel>>,
    balance: Mutex<Option<Balance>>,
    claim: DirClaim,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.lock();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn os_rng() -> Result<StdRng, WalletError> {
    StdRng::try_from_rng(&mut getrandom::SysRng)
        .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))
}

fn invalid(message: impl Into<String>) -> WalletError {
    WalletError::new(WalletErrorKind::InvalidArgument, message)
}

fn io(what: &str, error: &std::io::Error) -> WalletError {
    WalletError::new(WalletErrorKind::Io, format!("{what}: {error}"))
}

pub(crate) const fn relay_network(network: Network) -> RelayNetwork {
    match network {
        Network::Mainnet => RelayNetwork::Mainnet,
        Network::Floonet => RelayNetwork::Floonet,
    }
}

/// `address` as an Epicbox address of `network` that names its relay. A bare key is refused:
/// the engine would send it to a default relay the user never named.
pub(crate) fn relay_address(address: &str, network: Network) -> Option<EpicboxAddress> {
    if !address.contains('@') {
        return None;
    }
    EpicboxAddress::parse(address, relay_network(network)).ok()
}

/// Words separated by single spaces, lowercase, as the engine expects. Built in one buffer
/// large enough that it never moves, so no copy of the phrase is left unwiped.
pub(crate) fn normalize_phrase(phrase: &str) -> Zeroizing<String> {
    // Lowercasing at most doubles the length of any character.
    let mut normalized = Zeroizing::new(String::with_capacity(phrase.len().saturating_mul(2)));
    for word in phrase.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.extend(word.chars().flat_map(char::to_lowercase));
    }
    normalized
}

/// The engine's password type, taking over the buffer of `text` without a copy.
fn password(mut text: Zeroizing<String>) -> Password {
    Password::new(std::mem::take(&mut *text))
}

fn relay_endpoint(config: &WalletConfig) -> Result<RelayEndpoint, WalletError> {
    let domain = Domain::parse(&config.epicbox_domain)
        .map_err(|_| invalid("epicbox domain is not a host name"))?;
    let security = if domain.is_loopback() {
        Security::Plain
    } else {
        Security::Tls
    };
    Ok(RelayEndpoint::new(
        domain,
        Some(config.epicbox_port),
        security,
    ))
}

fn epicbox_transport(
    runtime: &RuntimeInner,
    config: &WalletConfig,
    network: Network,
) -> Result<Option<EpicboxTransport>, WalletError> {
    if config.epicbox_domain.is_empty() {
        return Ok(None);
    }
    let endpoint = relay_endpoint(config)?;
    #[cfg(feature = "mock")]
    if let Some(relay) = &runtime.relay {
        return Ok(Some(EpicboxTransport::new(
            ClientSettings::new(endpoint),
            relay_network(network),
            Arc::clone(relay),
        )));
    }
    #[cfg(not(feature = "mock"))]
    let _ = runtime;
    let tls = webpki_tls_config().map_err(|error| node_error(&error))?;
    Ok(Some(EpicboxTransport::new(
        ClientSettings::new(endpoint),
        relay_network(network),
        Arc::new(TcpConnector::new(tls)),
    )))
}

impl Session {
    /// A locked wallet on `config.data_dir`, which must exist and not be open anywhere.
    pub(crate) fn new(
        runtime: &Arc<RuntimeInner>,
        config: &WalletConfig,
        node_secret: &NodeSecret,
        store: AppSecretStore,
    ) -> Result<Self, WalletError> {
        let network = config.chain.network();
        let data_dir = PathBuf::from(&config.data_dir);
        let claim = runtime.claim(&data_dir)?;
        let node = runtime.nodes.client(config, node_secret)?;
        let epicbox = epicbox_transport(runtime, config, network)?;
        let mut transports = TransportRegistry::new();
        let mut ids = vec![FILE];
        transports
            .register(Box::new(FileTransport::new()))
            .map_err(|error| invalid(error.to_string()))?;
        if let Some(epicbox) = &epicbox {
            transports
                .register(Box::new(epicbox.clone()))
                .map_err(|error| invalid(error.to_string()))?;
            ids.push(TRANSPORT_ID);
        }
        let http = http::http_transport()?;
        transports
            .register(Box::new(http.clone()))
            .map_err(|error| invalid(error.to_string()))?;
        ids.push(lepic_foreign::TRANSPORT_ID);
        let tor = tor::tor_transport();
        transports
            .register(Box::new(tor.clone()))
            .map_err(|error| invalid(error.to_string()))?;
        ids.push(lepic_tor::TRANSPORT_ID);
        let engine_config = lepic_wallet::WalletConfig {
            name: WalletName::new(WALLET_NAME).map_err(|error| invalid(error.to_string()))?,
            network,
            data_dir: claim.dir.clone(),
            node: NodeEndpoint::parse(&config.node_url)
                .map_err(|_| invalid("node url is not an http or https url with a host"))?,
            transports: ids,
        };
        let vault = VaultBytes::default();
        let ports = Ports {
            node,
            stores: SqliteStores,
            secrets: AppVault::new(vault.clone(), runtime.kdf),
            transports,
            clock: Arc::new(SystemClock),
            rng: SharedRng::new(os_rng()?),
            runtime: runtime.boundary.handle.clone(),
        };
        let engine = Wallet::new(engine_config, ports)?;
        Ok(Self {
            engine,
            network,
            data_dir: claim.dir.clone(),
            store,
            vault,
            epicbox,
            listener: Mutex::default(),
            http,
            http_listener: Mutex::default(),
            http_starts: AtomicU64::new(0),
            tor,
            tor_slot: Mutex::default(),
            tor_starts: AtomicU64::new(0),
            #[cfg(test)]
            tor_timings: Mutex::default(),
            scan: Mutex::default(),
            balance: Mutex::default(),
            claim,
        })
    }

    pub(crate) fn runtime(&self) -> &Arc<RuntimeInner> {
        &self.claim.runtime
    }

    pub(crate) fn store(&self) -> &AppSecretStore {
        &self.store
    }

    /// Stops tor, the listeners and any scan, forgets the cached balance and the relay identity, and
    /// drops the root key. Operations already running finish with the keys they started with.
    pub(crate) fn lock(&self) {
        if let Some(listener) = lock(&self.listener).take() {
            listener.stop();
        }
        if let Some(scan) = lock(&self.scan).take() {
            scan.cancel();
        }
        lock(&self.balance).take();
        if let Some(epicbox) = &self.epicbox {
            epicbox.detach();
        }
        self.engine.lock();
        // After the engine locks, so a start that saw it unlocked is in its slot. Tor stops
        // before the listeners it forwards to.
        self.stop_tor();
        self.stop_http_listener();
    }

    pub(crate) fn ensure_unlocked(&self) -> Result<(), WalletError> {
        if self.engine.is_unlocked() {
            Ok(())
        } else {
            Err(WalletError::from(lepic_wallet::WalletError::Locked))
        }
    }

    /// Creates the wallet from `origin`'s seed. When it fails after making the database, the
    /// database files are removed again, so a later create on the directory starts afresh; a
    /// database that was there before is kept.
    pub(crate) async fn create(
        &self,
        origin: SeedOrigin,
        password: Zeroizing<String>,
    ) -> Result<(), WalletError> {
        let database = self.data_dir.join(DATABASE_FILE);
        let made_database = !tokio::fs::try_exists(&database)
            .await
            .map_err(|error| io("checking the wallet database", &error))?;
        if let Err(error) = self.create_with_vault(origin, password).await {
            if made_database {
                // Closes the database before its files are removed.
                self.engine.lock();
                if let Err(removal) = remove_database(&self.data_dir).await {
                    warn!(error = %removal, "wallet database not removed");
                }
            }
            return Err(error);
        }
        self.seed_node_tip()
    }

    /// Creates the wallet and stores its vault; the wallet is locked when that store fails.
    async fn create_with_vault(
        &self,
        origin: SeedOrigin,
        password: Zeroizing<String>,
    ) -> Result<(), WalletError> {
        self.vault.load(&self.store).await?;
        let password = self::password(password);
        match origin {
            SeedOrigin::Phrase(phrase) => {
                let phrase = normalize_phrase(&phrase);
                self.engine.restore(password, &phrase).await?;
            }
            SeedOrigin::SeedFile {
                text,
                password: file_password,
            } => {
                self.engine
                    .import_wallet_seed(password, &text, self::password(file_password))
                    .await?;
            }
            // The phrase is shown later through `recovery_phrase`, after the user set up a PIN.
            SeedOrigin::Generate => {
                drop(self.engine.create(password, WordCount::TwentyFour).await?);
            }
        }
        if let Err(error) = self.vault.flush(&self.store).await {
            self.engine.lock();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) async fn open(&self, password: Zeroizing<String>) -> Result<(), WalletError> {
        self.vault.load(&self.store).await?;
        self.engine.open(self::password(password)).await?;
        self.seed_node_tip()
    }

    /// Starts the node client from the tip the wallet confirmed last, so the first tip a node
    /// reports in this session is bounded by it rather than accepted as the new reference.
    fn seed_node_tip(&self) -> Result<(), WalletError> {
        let Some(confirmed) = self.engine.confirmed_tip()? else {
            return Ok(());
        };
        // A device clock behind the stored time counts as no time passed.
        let seen_ago =
            std::time::Duration::try_from(Timestamp::now().duration_since(confirmed.seen_at))
                .unwrap_or_default();
        // Clones of the client share what it has seen, so this seeds the engine's client.
        drop(
            self.engine
                .ports()
                .node
                .clone()
                .with_known_tip(confirmed.height, seen_ago),
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn node(&self) -> &Node {
        &self.engine.ports().node
    }

    #[cfg(test)]
    pub(crate) async fn scan_to_tip(&self) {
        self.engine
            .scan(ScanOptions::update(self.network), &ScanCancel::new())
            .await
            .unwrap();
    }

    /// The recovery phrase, after checking `password` against the stored vault.
    pub(crate) async fn recovery_phrase(
        &self,
        password: Zeroizing<String>,
    ) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let phrase = self
            .with_stored_vault(password, |vault| {
                let name =
                    SecretName::new(SEED_SECRET).map_err(|error| invalid(error.to_string()))?;
                let stored = vault
                    .get(&name)
                    .map_err(|error| WalletError::from(lepic_wallet::WalletError::from(error)))?
                    .ok_or_else(|| {
                        WalletError::new(WalletErrorKind::WalletNotFound, "no seed is stored")
                    })?;
                let seed = Seed::from_entropy(stored.expose_bytes()).map_err(|_| {
                    WalletError::new(WalletErrorKind::SecretStore, "stored seed is malformed")
                })?;
                let phrase = seed.to_mnemonic().map_err(|_| {
                    WalletError::new(WalletErrorKind::SecretStore, "stored seed is malformed")
                })?;
                Ok::<_, WalletError>(phrase)
            })
            .await?;
        // The binding encodes the returned text for Dart and drops it without wiping it, so it
        // gets this buffer rather than a second copy.
        let mut phrase = phrase;
        Ok(std::mem::take(&mut *phrase))
    }

    /// Checks `password` against the stored vault: `WrongPassword` when it does not open it.
    pub(crate) async fn check_password(
        &self,
        password: Zeroizing<String>,
    ) -> Result<(), WalletError> {
        self.with_stored_vault(password, |_| Ok(())).await
    }

    /// Opens the vault in the app's store with `password` on the blocking pool and hands it to
    /// `read`.
    async fn with_stored_vault<T: Send + 'static>(
        &self,
        password: Zeroizing<String>,
        read: impl FnOnce(&Vault<SharedStorage, StdRng>) -> Result<T, WalletError> + Send + 'static,
    ) -> Result<T, WalletError> {
        let bytes = VaultBytes::default();
        bytes.load(&self.store).await?;
        let password = self::password(password);
        tokio::task::spawn_blocking(move || {
            let vault = Vault::open(
                SharedStorage::new(bytes),
                os_rng()?,
                password.expose_bytes(),
            )
            .map_err(|error| {
                WalletError::from(lepic_wallet::WalletError::from(vault_error(error)))
            })?;
            read(&vault)
        })
        .await
        .map_err(|_| WalletError::new(WalletErrorKind::Panic, "vault failed inside lepic"))?
    }

    /// Refreshes against the node and returns the default account's balance.
    pub(crate) async fn refresh(&self) -> Result<WalletSummary, WalletError> {
        let mut events = self.engine.subscribe();
        match self.engine.refresh().await? {
            RefreshOutcome::Refreshed(_) => {
                let mut latest = None;
                loop {
                    match events.try_recv() {
                        Ok(Event::Balance(balance)) if balance.account == DEFAULT_ACCOUNT => {
                            latest = Some(balance);
                        }
                        Ok(_) | Err(TryRecvError::Lagged(_)) => {}
                        Err(TryRecvError::Empty | TryRecvError::Closed) => break,
                    }
                }
                match latest {
                    Some(balance) => {
                        *lock(&self.balance) = Some(balance);
                        Ok(summary(&balance, true))
                    }
                    None => self.cached().ok_or_else(|| {
                        WalletError::new(WalletErrorKind::Other, "refresh reported no balance")
                    }),
                }
            }
            RefreshOutcome::NodeBehind { .. } => self.cached().ok_or_else(|| {
                WalletError::new(
                    WalletErrorKind::NodeUnreachable,
                    "node is behind the wallet; try again once it has synced",
                )
            }),
        }
    }

    /// The balance of the last refresh in this session.
    pub(crate) fn cached(&self) -> Option<WalletSummary> {
        if !self.engine.is_unlocked() {
            return None;
        }
        lock(&self.balance)
            .as_ref()
            .map(|balance| summary(balance, false))
    }

    /// The default account's balance from the store, at the tip the wallet confirmed last,
    /// without asking the node.
    pub(crate) fn stored_summary(&self) -> Result<WalletSummary, WalletError> {
        Ok(summary(&self.engine.balance(DEFAULT_ACCOUNT)?, false))
    }

    pub(crate) async fn transactions(&self) -> Result<Vec<TransactionDetails>, WalletError> {
        let stored = self.engine.transactions(DEFAULT_ACCOUNT).await?;
        Ok(stored.iter().map(transaction_details).collect())
    }

    pub(crate) async fn import_legacy_history(
        &self,
        source_dir: &str,
    ) -> Result<LegacyImport, WalletError> {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
        let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
        let work = ImportWorkDir::create(&self.data_dir, &suffix)
            .map_err(|error| io("creating the import folder", &error))?;
        let outcome = self
            .engine
            .import_legacy_history(Path::new(source_dir), work.path())
            .await?;
        Ok(legacy_import(&outcome))
    }

    pub(crate) async fn transaction(&self, tx_id: u32) -> Result<TransactionDetails, WalletError> {
        let stored = self.engine.transaction_details(TxId(tx_id)).await?;
        if stored.transaction.entry.account != DEFAULT_ACCOUNT {
            return Err(WalletError::from(
                lepic_wallet::WalletError::UnknownTransaction(TxId(tx_id)),
            ));
        }
        Ok(transaction_details(&stored))
    }

    pub(crate) async fn estimate_fee(
        &self,
        amount: u64,
        minimum_confirmations: u64,
    ) -> Result<FeeEstimate, WalletError> {
        let options = Self::send_request(amount, minimum_confirmations, None).selection_options();
        let selection = self
            .engine
            .estimate_fee(Amount::new(amount), options)
            .await?;
        fee_estimate(&selection)
    }

    pub(crate) async fn estimate_max(
        &self,
        minimum_confirmations: u64,
    ) -> Result<FeeEstimate, WalletError> {
        let options = Self::send_request(0, minimum_confirmations, None).selection_options();
        let selection = self.engine.estimate_max(options).await?;
        fee_estimate(&selection)
    }

    pub(crate) async fn scan(
        &self,
        start_height: Option<u64>,
        progress: &StreamSink<ScanProgress>,
    ) -> Result<(), WalletError> {
        let cancel = ScanCancel::new();
        *lock(&self.scan) = Some(cancel.clone());
        let options = match start_height {
            Some(height) => ScanOptions {
                start: ScanStart::Height(Height::new(height)),
                ..ScanOptions::update(self.network)
            },
            None => ScanOptions::update(self.network),
        };
        let mut events = self.engine.subscribe();
        let scan = self.engine.scan(options, &cancel);
        tokio::pin!(scan);
        let result = loop {
            tokio::select! {
                result = &mut scan => break result,
                event = events.recv() => match event {
                    Ok(Event::Sync(sync)) => {
                        let _ = progress.add(scan_progress(sync.height.value(), sync.target.value(), false));
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break (&mut scan).await,
                },
            }
        };
        lock(&self.scan).take();
        let summary = result?;
        info!(height = %summary.end_height, "scan reported");
        // A closed stream only means nobody is listening.
        let _ = progress.add(scan_progress(
            summary.end_height.value(),
            summary.end_height.value(),
            true,
        ));
        Ok(())
    }

    pub(crate) fn cancel_scan(&self) {
        if let Some(scan) = lock(&self.scan).as_ref() {
            scan.cancel();
        }
    }

    fn send_request(
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
    ) -> SendRequest {
        SendRequest {
            minimum_confirmations,
            message,
            ..SendRequest::new(DEFAULT_ACCOUNT, Amount::new(amount))
        }
    }

    pub(crate) async fn send_file(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        path: PathBuf,
        message: Option<String>,
    ) -> Result<SentTx, WalletError> {
        let sent = self
            .engine
            .send(
                Self::send_request(amount, minimum_confirmations, message),
                Delivery::Export {
                    transport: FILE,
                    to: Location::File(path),
                },
            )
            .await?;
        Ok(sent_tx(&sent))
    }

    pub(crate) async fn create_send_slate(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
    ) -> Result<Slate, WalletError> {
        let scratch = ScratchFile::new(&self.data_dir)?;
        let sent = self
            .send_file(amount, minimum_confirmations, scratch.path.clone(), message)
            .await?;
        let json = scratch.read().await?;
        Ok(Slate {
            tx_id: sent.tx_id,
            slate_id: sent.slate_id,
            json,
        })
    }

    /// Signs the S1 in the file at `path`. Returns the reply, also written next to the file as
    /// `epic-wallet` names it, when `write_response` is set. A repeated S1 gets the reply stored
    /// the first time, written again.
    pub(crate) async fn receive_file(
        &self,
        path: &Path,
        write_response: bool,
    ) -> Result<ReceivedSlate, WalletError> {
        let file = FileTransport::new();
        let wire = file
            .import(&Location::File(path.to_owned()))
            .await
            .map_err(|error| transport_error(&error))?;
        let received = self
            .engine
            .receive(FILE, &wire, ReceiveRequest::default())
            .await?;
        if write_response {
            file.export(&received.reply, &Location::File(response_path(path)))
                .await
                .map_err(|error| transport_error(&error))?;
        }
        let json = String::from_utf8(received.reply.as_bytes().to_vec())
            .map_err(|_| WalletError::new(WalletErrorKind::InvalidSlate, "reply is not text"))?;
        Ok(ReceivedSlate {
            tx_id: received.tx_id.0,
            slate_id: received.slate.id().to_string(),
            json,
            repeated: received.repeated,
        })
    }

    pub(crate) async fn receive_slate(&self, json: String) -> Result<ReceivedSlate, WalletError> {
        let scratch = ScratchFile::with_contents(&self.data_dir, json).await?;
        self.receive_file(&scratch.path, false).await
    }

    pub(crate) async fn finalize_file(&self, path: &Path) -> Result<FinalizedTx, WalletError> {
        let wire = FileTransport::new()
            .import(&Location::File(path.to_owned()))
            .await
            .map_err(|error| transport_error(&error))?;
        let finalized = self
            .engine
            .finalize(FILE, &wire, Propagation::Fluff)
            .await?;
        Ok(FinalizedTx {
            tx_id: finalized.tx_id.0,
            slate_id: finalized.slate.id().to_string(),
        })
    }

    pub(crate) async fn finalize_slate(&self, json: String) -> Result<FinalizedTx, WalletError> {
        let scratch = ScratchFile::with_contents(&self.data_dir, json).await?;
        self.finalize_file(&scratch.path).await
    }

    pub(crate) async fn repost(&self, tx_id: u32) -> Result<(), WalletError> {
        self.engine.post(TxId(tx_id), Propagation::Fluff).await?;
        Ok(())
    }

    pub(crate) async fn cancel(&self, tx_id: u32) -> Result<(), WalletError> {
        self.attach_for_notices()?;
        Ok(self.engine.cancel(TxId(tx_id)).await?)
    }

    /// Attaches the payments identity when a relay is configured, so the `withdrawn` notice
    /// a cancel of an issued invoice sends leaves from the address the invoice came from.
    fn attach_for_notices(&self) -> Result<(), WalletError> {
        if let Some(epicbox) = &self.epicbox {
            self.engine.epicbox_attach(epicbox)?;
        }
        Ok(())
    }

    pub(crate) async fn release(&self, tx_id: u32) -> Result<(), WalletError> {
        Ok(self.engine.release(TxId(tx_id)).await?)
    }

    fn epicbox(&self) -> Result<&EpicboxTransport, WalletError> {
        self.epicbox.as_ref().ok_or_else(|| {
            WalletError::new(
                WalletErrorKind::Unsupported,
                "epicbox is not configured for this wallet",
            )
        })
    }

    pub(crate) fn epicbox_address(&self) -> Result<String, WalletError> {
        Ok(self.engine.epicbox_attach(self.epicbox()?)?.to_string())
    }

    pub(crate) async fn send_epicbox(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        address: String,
        message: Option<String>,
    ) -> Result<SentTx, WalletError> {
        let epicbox = self.epicbox()?;
        relay_address(&address, self.network)
            .ok_or_else(|| invalid("not an epicbox address with a relay on this network"))?;
        self.engine.epicbox_attach(epicbox)?;
        let sent = self
            .engine
            .send(
                Self::send_request(amount, minimum_confirmations, message),
                Delivery::Deliver {
                    transport: TRANSPORT_ID,
                    to: Destination::new(address),
                },
            )
            .await?;
        Ok(sent_tx(&sent))
    }

    pub(crate) async fn drain_epicbox(&self) -> Result<InboxReport, WalletError> {
        let summary = self.engine.epicbox_drain(self.epicbox()?).await?;
        Ok(InboxReport {
            received: summary.received,
            finalized: summary.finalized,
            repeated: summary.repeated,
            rejected: summary.rejected,
            held: summary.held,
            notices: summary.notices,
            bounced: summary.bounced,
            dropped: summary.dropped,
        })
    }

    /// Starts listening unless a listener runs. Returns the handle to stop it with, or `None`
    /// when one was running already.
    pub(crate) fn claim_listener(&self) -> Result<Option<ListenHandle>, WalletError> {
        self.epicbox()?;
        let mut slot = lock(&self.listener);
        if slot.as_ref().is_some_and(|handle| !handle.is_stopped()) {
            return Ok(None);
        }
        let handle = ListenHandle::new();
        *slot = Some(handle.clone());
        Ok(Some(handle))
    }

    /// Runs the listener until `handle` is stopped, handing what it does to `report`.
    pub(crate) async fn listen(
        &self,
        handle: &ListenHandle,
        report: impl Fn(ListenerEvent),
    ) -> Result<(), WalletError> {
        let epicbox = self.epicbox()?;
        let mut events = self.engine.subscribe();
        let listen = self.engine.epicbox_listen(epicbox, handle);
        tokio::pin!(listen);
        let result = loop {
            tokio::select! {
                result = &mut listen => break result,
                event = events.recv() => match event {
                    Ok(event) => {
                        if let Some(event) = listener_event(&event) {
                            report(event);
                        }
                    }
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break (&mut listen).await,
                },
            }
        };
        let summary = result?;
        debug!(
            received = summary.received,
            finalized = summary.finalized,
            "listener ended"
        );
        Ok(())
    }

    pub(crate) fn stop_listener(&self) {
        if let Some(handle) = lock(&self.listener).as_ref() {
            handle.stop();
        }
    }

    pub(crate) fn listener_running(&self) -> bool {
        lock(&self.listener)
            .as_ref()
            .is_some_and(|handle| !handle.is_stopped())
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.engine.subscribe()
    }
}

/// Forwards engine events to `sink` until the wallet closes or the app stops listening.
pub(crate) async fn forward_events(
    mut events: broadcast::Receiver<Event>,
    sink: StreamSink<WalletEvent>,
) {
    loop {
        let event = match events.recv().await {
            Ok(event) => match wallet_event(&event) {
                Some(event) => event,
                None => continue,
            },
            Err(RecvError::Lagged(count)) => WalletEvent {
                missed: Some(count),
                ..WalletEvent::of(WalletEventKind::Missed)
            },
            Err(RecvError::Closed) => break,
        };
        if sink.add(event).is_err() {
            break;
        }
    }
}

fn summary(balance: &Balance, validated_with_node: bool) -> WalletSummary {
    WalletSummary {
        last_confirmed_height: balance.height.value(),
        minimum_confirmations: BALANCE_MINIMUM_CONFIRMATIONS,
        total: balance.total.value(),
        spendable: balance.spendable.value(),
        awaiting_confirmation: balance.awaiting_confirmation.value(),
        awaiting_finalization: balance.awaiting_finalization.value(),
        immature: balance.immature.value(),
        locked: balance.locked.value(),
        validated_with_node,
    }
}

fn scan_progress(height: u64, target_height: u64, finished: bool) -> ScanProgress {
    let percent = height
        .checked_mul(100)
        .and_then(|scaled| scaled.checked_div(target_height))
        .map(|percent| percent.min(100))
        .and_then(|percent| u8::try_from(percent).ok());
    ScanProgress {
        percent: if finished { Some(100) } else { percent },
        height,
        target_height,
        message: if finished {
            "scan completed"
        } else {
            "scanning"
        }
        .to_owned(),
        finished,
    }
}

fn sent_tx(sent: &SentSlate) -> SentTx {
    SentTx {
        tx_id: sent.tx_id.0,
        slate_id: sent.slate_id.to_string(),
        amount: sent.amount.value(),
        fee: sent.fee.value(),
    }
}

fn transaction_details(details: &EngineTransactionDetails) -> TransactionDetails {
    let stored = &details.transaction;
    let entry = &stored.entry;
    TransactionDetails {
        tx_id: stored.id.0,
        direction: entry.direction.into(),
        status: entry.state.into(),
        slate_id: entry.slate_id.map(|id| id.to_string()),
        transport: entry.transport.clone(),
        amount_credited: entry.amount_credited.value(),
        amount_debited: entry.amount_debited.value(),
        fee: entry.fee.map(Fee::value),
        created_at_ms: entry.created_at.as_millisecond(),
        confirmed_at_ms: details.confirmed_at.map(Timestamp::as_millisecond),
        confirmed_height: details.confirmed_height.map(Height::value),
        kernel_excess: details.kernel_excess.map(|excess| excess.to_hex()),
        counterparty: details
            .counterparty
            .as_ref()
            .map(|address| address.as_str().to_owned()),
        ttl_cutoff_height: details.ttl_cutoff_height.map(Height::value),
        releasable_from: details.releasable_from.map(Height::value),
        releasable: details.releasable,
        messages: details
            .messages
            .iter()
            .map(|message| SlateMessage {
                role: message.role.into(),
                text: message.text.clone(),
            })
            .collect(),
        flow: details.flow.into(),
        origin: match details.origin {
            EngineTxOrigin::Wallet => TxOrigin::Wallet,
            EngineTxOrigin::Imported => TxOrigin::Imported,
            EngineTxOrigin::FoundByScan => TxOrigin::FoundByScan,
        },
        imported: details.imported.as_ref().map(|imported| ImportedTx {
            source_id: imported.source_id,
            kind: imported.kind.into(),
            input_count: imported.input_count,
            output_count: imported.output_count,
            check: imported.check.into(),
        }),
    }
}

fn legacy_import(outcome: &LegacyImportOutcome) -> LegacyImport {
    LegacyImport {
        status: match outcome.status {
            EngineLegacyStatus::Imported => LegacyImportStatus::Imported,
            EngineLegacyStatus::AlreadyImported => LegacyImportStatus::AlreadyImported,
            EngineLegacyStatus::NoHistory => LegacyImportStatus::NoHistory,
            EngineLegacyStatus::OldFormat => LegacyImportStatus::OldFormat,
            EngineLegacyStatus::Unreadable => LegacyImportStatus::Unreadable,
            EngineLegacyStatus::SourceBusy => LegacyImportStatus::SourceBusy,
            EngineLegacyStatus::TooLarge => LegacyImportStatus::TooLarge,
            EngineLegacyStatus::OtherWallet => LegacyImportStatus::OtherWallet,
            EngineLegacyStatus::OtherHistory => LegacyImportStatus::OtherHistory,
        },
        transactions: outcome.transactions,
        outputs: outcome.outputs,
        accounts_named: outcome.accounts_named,
        linked: outcome.linked,
        skipped: outcome.skipped,
        confirmed_by_kernel: outcome.confirmed_by_kernel,
        dated: outcome.dated,
    }
}

fn fee_estimate(selection: &Selection) -> Result<FeeEstimate, WalletError> {
    let out_of_range = || WalletError::new(WalletErrorKind::Other, "fee estimate out of range");
    let change = selection
        .change
        .iter()
        .try_fold(0u64, |sum, change| sum.checked_add(change.value()))
        .ok_or_else(out_of_range)?;
    Ok(FeeEstimate {
        amount: selection.amount.value(),
        fee: selection.fee.value(),
        input_count: u32::try_from(selection.inputs.len()).map_err(|_| out_of_range())?,
        change,
    })
}

fn transport_error(error: &lepic_transport::error::TransportError) -> WalletError {
    WalletError::new(
        WalletErrorKind::TransportFailed,
        lepic_telemetry::ErrorChain(error).to_string(),
    )
}

const fn transport_state(state: EngineTransportState) -> TransportState {
    match state {
        EngineTransportState::Connecting => TransportState::Connecting,
        EngineTransportState::Connected => TransportState::Connected,
        EngineTransportState::Disconnected => TransportState::Disconnected,
        _ => TransportState::Stopped,
    }
}

fn wallet_event(event: &Event) -> Option<WalletEvent> {
    Some(match event {
        Event::Session(state) => WalletEvent {
            session: Some(match state {
                SessionState::Unlocked => crate::api::types::SessionState::Unlocked,
                SessionState::Locked => crate::api::types::SessionState::Locked,
                SessionState::Closed => crate::api::types::SessionState::Closed,
            }),
            ..WalletEvent::of(WalletEventKind::Session)
        },
        Event::Balance(balance) => WalletEvent {
            account: Some(balance.account.0),
            balance: Some(summary(balance, true)),
            ..WalletEvent::of(WalletEventKind::Balance)
        },
        Event::Transaction(change) => WalletEvent {
            tx_id: Some(change.tx_id.0),
            from: Some(change.from.into()),
            to: Some(change.to.into()),
            ..WalletEvent::of(WalletEventKind::Transaction)
        },
        Event::Received(received) => WalletEvent {
            tx_id: Some(received.tx_id.0),
            to: Some(TxStatus::Received),
            ..WalletEvent::of(WalletEventKind::Transaction)
        },
        Event::Sync(sync) => WalletEvent {
            height: Some(sync.height.value()),
            target_height: Some(sync.target.value()),
            ..WalletEvent::of(WalletEventKind::Sync)
        },
        Event::Transport(status) => WalletEvent {
            transport: Some(status.transport.as_str().to_owned()),
            transport_state: Some(transport_state(status.state)),
            ..WalletEvent::of(WalletEventKind::Transport)
        },
        Event::InvoiceParked(parked) => WalletEvent {
            slate_id: Some(parked.slate_id.to_string()),
            amount: Some(parked.amount.value()),
            ..WalletEvent::of(WalletEventKind::InvoiceReceived)
        },
        Event::InvoiceFinalized(finalized) => WalletEvent {
            tx_id: Some(finalized.tx_id.0),
            slate_id: Some(finalized.slate_id.to_string()),
            ..WalletEvent::of(WalletEventKind::InvoiceFinalized)
        },
        Event::InvoiceExpired(expired) => WalletEvent {
            tx_id: expired.tx_id.map(|tx_id| tx_id.0),
            slate_id: Some(expired.slate_id.to_string()),
            ..WalletEvent::of(WalletEventKind::InvoiceExpired)
        },
        Event::InvoicePosted(posted) => WalletEvent {
            tx_id: Some(posted.tx_id.0),
            slate_id: Some(posted.slate_id.to_string()),
            kernel_excess: Some(posted.excess.to_hex()),
            ..WalletEvent::of(WalletEventKind::InvoicePosted)
        },
        Event::InvoiceDeclined(declined) => WalletEvent {
            tx_id: Some(declined.tx_id.0),
            slate_id: Some(declined.slate_id.to_string()),
            ..WalletEvent::of(WalletEventKind::InvoiceDeclined)
        },
        Event::InvoiceWithdrawn(withdrawn) => WalletEvent {
            tx_id: withdrawn.tx_id.map(|tx_id| tx_id.0),
            slate_id: Some(withdrawn.slate_id.to_string()),
            ..WalletEvent::of(WalletEventKind::InvoiceWithdrawn)
        },
        Event::InvoiceBounced(bounced) => WalletEvent {
            tx_id: Some(bounced.tx_id.0),
            slate_id: Some(bounced.slate_id.to_string()),
            ..WalletEvent::of(WalletEventKind::InvoiceBounced)
        },
        _ => return None,
    })
}

fn listener_event(event: &Event) -> Option<ListenerEvent> {
    if let Event::InvoiceBounced(bounced) = event {
        return Some(ListenerEvent {
            kind: ListenerEventKind::InvoiceBounced,
            tx_id: Some(bounced.tx_id.0),
            slate_id: Some(bounced.slate_id.to_string()),
            message: String::new(),
        });
    }
    let (kind, tx_id) = match event {
        Event::Transport(status) if status.transport == TRANSPORT_ID => {
            match transport_state(status.state) {
                TransportState::Connected => (ListenerEventKind::Connected, None),
                TransportState::Disconnected => (ListenerEventKind::Disconnected, None),
                TransportState::Connecting | TransportState::Stopped => return None,
            }
        }
        Event::Received(received) => (ListenerEventKind::Received, Some(received.tx_id.0)),
        Event::AnsweredAgain(again) => (ListenerEventKind::Repeated, Some(again.tx_id.0)),
        Event::Transaction(change) if change.to == TxState::Finalized => {
            (ListenerEventKind::Finalized, Some(change.tx_id.0))
        }
        _ => return None,
    };
    Some(ListenerEvent {
        kind,
        tx_id,
        slate_id: None,
        message: String::new(),
    })
}

/// A slate file in the wallet's directory that exists only for one call, so text slates go
/// through the file method's checks. Removed when dropped.
struct ScratchFile {
    path: PathBuf,
}

impl ScratchFile {
    fn new(data_dir: &Path) -> Result<Self, WalletError> {
        let mut name = [0u8; 8];
        getrandom::fill(&mut name)
            .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
        let name: String = name.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            path: data_dir.join(format!(".lepic-{name}.slate")),
        })
    }

    async fn with_contents(data_dir: &Path, contents: String) -> Result<Self, WalletError> {
        if contents.len() > MAX_SLATE_TEXT_LEN {
            return Err(WalletError::new(
                WalletErrorKind::InvalidSlate,
                "slate text is longer than any slate",
            ));
        }
        let file = Self::new(data_dir)?;
        tokio::fs::write(&file.path, contents)
            .await
            .map_err(|error| io("writing a slate file", &error))?;
        Ok(file)
    }

    async fn read(&self) -> Result<String, WalletError> {
        tokio::fs::read_to_string(&self.path)
            .await
            .map_err(|error| io("reading a slate file", &error))
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(error = %error, "slate file not removed"),
        }
    }
}

/// The tip and version of the node `config` names, without opening a wallet.
pub(crate) async fn node_tip(
    runtime: &Arc<RuntimeInner>,
    config: &WalletConfig,
    node_secret: &NodeSecret,
) -> Result<NodeTip, WalletError> {
    let node = runtime.nodes.client(config, node_secret)?;
    let tip = node.get_tip().await.map_err(|error| node_error(&error))?;
    let version = node
        .get_version()
        .await
        .map_err(|error| node_error(&error))?;
    Ok(NodeTip {
        height: tip.height.value(),
        node_version: version.node_version,
    })
}

/// Whether the app's store holds a wallet vault.
pub(crate) async fn wallet_exists(store: &AppSecretStore) -> Result<bool, WalletError> {
    Ok(store.read(VAULT_KEY).await?.is_some())
}

/// Removes the wallet database in `data_dir` with its journal files, if there are any.
async fn remove_database(data_dir: &Path) -> Result<(), WalletError> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = data_dir.join(format!("{DATABASE_FILE}{suffix}"));
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io("deleting the wallet database", &error)),
        }
    }
    Ok(())
}

/// Deletes the wallet database in `config.data_dir` and the vault in `store`.
pub(crate) async fn delete_wallet(
    runtime: &Arc<RuntimeInner>,
    config: &WalletConfig,
    store: &AppSecretStore,
) -> Result<(), WalletError> {
    let claim = runtime.claim(Path::new(&config.data_dir))?;
    remove_database(&claim.dir).await?;
    store.delete(VAULT_KEY).await?;
    crate::pin::forget(store).await?;
    info!("wallet deleted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use lepic_wallet::event::{ReceivedTransaction, TransactionState};

    use super::*;

    fn received() -> Event {
        Event::Received(ReceivedTransaction {
            tx_id: TxId(3),
            account: DEFAULT_ACCOUNT,
            amount: Amount::new(100_000_000),
            transport: TRANSPORT_ID,
        })
    }

    fn relay_config(domain: &str) -> WalletConfig {
        WalletConfig {
            data_dir: String::new(),
            chain: crate::api::types::Chain::Mainnet,
            node_url: String::new(),
            node_api_secret: None,
            epicbox_domain: domain.to_owned(),
            epicbox_port: 3423,
        }
    }

    #[test]
    fn a_loopback_relay_is_reached_without_tls_and_any_other_with_tls() {
        for domain in ["localhost", "LocalHost", "127.0.0.1", "127.1.2.3"] {
            let endpoint = relay_endpoint(&relay_config(domain)).unwrap();
            assert_eq!(endpoint.security(), Security::Plain, "{domain}");
            assert_eq!(endpoint.port(), 3423, "{domain}");
        }
        for domain in [
            "epicbox.epiccash.com",
            "localhost.example",
            "128.0.0.1",
            "10.0.0.1",
        ] {
            let endpoint = relay_endpoint(&relay_config(domain)).unwrap();
            assert_eq!(endpoint.security(), Security::Tls, "{domain}");
        }
    }

    #[test]
    fn every_engine_detail_reaches_the_binding_type() {
        use lepic_keychain::{Identifier, Keychain, SwitchCommitment};
        use lepic_store::{StoredTransaction, TransactionEntry, TxDirection};
        use lepic_transport::transport::Destination;

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        let keychain = Keychain::from_mnemonic(phrase, Network::Floonet).unwrap();
        let id = Identifier::new(3, [0, 0, 7, 0]).unwrap();
        let excess = keychain.commit(5, &id, SwitchCommitment::Regular).unwrap();
        let created = Timestamp::from_millisecond(1_790_000_000_123).unwrap();
        let confirmed = Timestamp::from_millisecond(1_790_000_600_456).unwrap();
        let slate_id = "0436430c-2b02-624c-2032-570501212b0e";
        let address = "zzRMBr82zhzvz6hAxJMecEchV4ohxJkrNtDKLqwJMq7EQ4y2ibhQ@epicbox.example:443";
        let details = EngineTransactionDetails {
            transaction: StoredTransaction {
                id: TxId(12),
                entry: TransactionEntry {
                    account: DEFAULT_ACCOUNT,
                    direction: TxDirection::Outgoing,
                    state: TxState::Confirmed,
                    slate_id: Some(slate_id.parse().unwrap()),
                    transport: Some("epicbox".to_owned()),
                    amount_credited: Amount::new(400),
                    amount_debited: Amount::new(1_500),
                    fee: Some(Fee::new(100)),
                    created_at: created,
                    updated_at: confirmed,
                },
            },
            kernel_excess: Some(excess),
            confirmed_height: Some(Height::new(321)),
            counterparty: Some(Destination::new(address.to_owned())),
            ttl_cutoff_height: Some(Height::new(360)),
            confirmed_at: Some(confirmed),
            releasable_from: Some(Height::new(1_444)),
            releasable: true,
            messages: vec![lepic_wallet::details::SlateMessage {
                role: lepic_wallet::slate::Role::Receiver,
                text: "got it".to_owned(),
            }],
            flow: lepic_wallet::details::TxFlow::Invoice,
            origin: EngineTxOrigin::Imported,
            imported: Some(lepic_wallet::details::ImportedDetails {
                source_id: 31,
                kind: lepic_store::ImportedKind::SentCancelled,
                input_count: 2,
                output_count: 1,
                check: lepic_store::ChainCheck::CancelledButOnChain,
            }),
        };

        assert_eq!(
            transaction_details(&details),
            TransactionDetails {
                tx_id: 12,
                direction: crate::api::types::TxDirection::Outgoing,
                status: TxStatus::Confirmed,
                slate_id: Some(slate_id.to_owned()),
                transport: Some("epicbox".to_owned()),
                amount_credited: 400,
                amount_debited: 1_500,
                fee: Some(100),
                created_at_ms: 1_790_000_000_123,
                confirmed_at_ms: Some(1_790_000_600_456),
                confirmed_height: Some(321),
                kernel_excess: Some(excess.to_hex()),
                counterparty: Some(address.to_owned()),
                ttl_cutoff_height: Some(360),
                releasable_from: Some(1_444),
                releasable: true,
                messages: vec![SlateMessage {
                    role: crate::api::types::SlateRole::Receiver,
                    text: "got it".to_owned(),
                }],
                flow: crate::api::types::TxFlow::Invoice,
                origin: TxOrigin::Imported,
                imported: Some(ImportedTx {
                    source_id: 31,
                    kind: crate::api::types::ImportedTxKind::SentCancelled,
                    input_count: 2,
                    output_count: 1,
                    check: crate::api::types::ChainCheck::CancelledButOnChain,
                }),
            }
        );
        let hex = excess.to_hex();
        assert_eq!(hex.len(), 66);
        assert!(
            hex.bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
    }

    #[test]
    fn invoice_events_reach_the_event_stream_with_their_slate() {
        use lepic_wallet::event::{
            DeclinedInvoice, ExpiredInvoice, FinalizedInvoice, ParkedInvoice, SlateId,
            WithdrawnInvoice,
        };
        let slate_id = SlateId::from_bytes([9; 16]);
        let parked = wallet_event(&Event::InvoiceParked(ParkedInvoice {
            slate_id,
            amount: Amount::new(300),
        }))
        .unwrap();
        assert_eq!(parked.kind, WalletEventKind::InvoiceReceived);
        assert_eq!(parked.slate_id, Some(slate_id.to_string()));
        assert_eq!(parked.amount, Some(300));
        let finalized = wallet_event(&Event::InvoiceFinalized(FinalizedInvoice {
            tx_id: TxId(4),
            slate_id,
        }))
        .unwrap();
        assert_eq!(finalized.kind, WalletEventKind::InvoiceFinalized);
        assert_eq!(finalized.tx_id, Some(4));
        let expired = wallet_event(&Event::InvoiceExpired(ExpiredInvoice {
            slate_id,
            tx_id: None,
        }))
        .unwrap();
        assert_eq!(expired.kind, WalletEventKind::InvoiceExpired);
        assert_eq!(expired.tx_id, None);
        assert_eq!(expired.slate_id, Some(slate_id.to_string()));
        let declined = wallet_event(&Event::InvoiceDeclined(DeclinedInvoice {
            tx_id: TxId(6),
            slate_id,
        }))
        .unwrap();
        assert_eq!(declined.kind, WalletEventKind::InvoiceDeclined);
        assert_eq!(declined.tx_id, Some(6));
        let withdrawn = wallet_event(&Event::InvoiceWithdrawn(WithdrawnInvoice {
            slate_id,
            tx_id: Some(TxId(7)),
        }))
        .unwrap();
        assert_eq!(withdrawn.kind, WalletEventKind::InvoiceWithdrawn);
        assert_eq!(withdrawn.tx_id, Some(7));
        assert_eq!(withdrawn.slate_id, Some(slate_id.to_string()));
    }

    #[test]
    fn a_bounced_invoice_reaches_the_events_and_the_listener_with_its_ids() {
        use lepic_wallet::event::{BouncedInvoice, SlateId};
        let slate_id = SlateId::from_bytes([9; 16]);
        let bounced = Event::InvoiceBounced(BouncedInvoice {
            tx_id: TxId(8),
            slate_id,
            peer: lepic_epicbox::EpicboxAddress::parse(
                "esWpjSHdScqVnFSkbM8mPEpzAGBWWSFg4Pu3sKHnqCsKgjzU4YD6@epicbox.epiccash.com",
                lepic_epicbox::Network::Mainnet,
            )
            .unwrap(),
        });
        let event = wallet_event(&bounced).unwrap();
        assert_eq!(event.kind, WalletEventKind::InvoiceBounced);
        assert_eq!(event.tx_id, Some(8));
        assert_eq!(event.slate_id, Some(slate_id.to_string()));
        let heard = listener_event(&bounced).unwrap();
        assert_eq!(heard.kind, ListenerEventKind::InvoiceBounced);
        assert_eq!(heard.tx_id, Some(8));
        assert_eq!(heard.slate_id, Some(slate_id.to_string()));
    }

    #[test]
    fn a_received_slate_reaches_the_listener_as_received() {
        let event = listener_event(&received()).unwrap();
        assert_eq!(event.kind, ListenerEventKind::Received);
        assert_eq!(event.tx_id, Some(3));
    }

    #[test]
    fn a_received_slate_reaches_the_event_stream_as_a_new_transaction() {
        let event = wallet_event(&received()).unwrap();
        assert_eq!(event.kind, WalletEventKind::Transaction);
        assert_eq!(event.tx_id, Some(3));
        assert_eq!(event.from, None);
        assert_eq!(event.to, Some(TxStatus::Received));
    }

    #[test]
    fn only_finalized_state_changes_reach_the_listener() {
        let change = |to| {
            Event::Transaction(TransactionState {
                tx_id: TxId(5),
                from: TxState::Sent,
                to,
            })
        };
        let finalized = listener_event(&change(TxState::Finalized)).unwrap();
        assert_eq!(finalized.kind, ListenerEventKind::Finalized);
        assert_eq!(finalized.tx_id, Some(5));
        assert!(listener_event(&change(TxState::Cancelled)).is_none());
    }

    /// The sender posts the same S1 twice, as a sender that sent it again does. The receiver's
    /// listener reports the first as a payment and the second only as answered again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_slate_delivered_twice_reaches_the_listener_as_received_then_repeated() {
        use lepic_epicbox::mock_relay::MockRelay;
        use lepic_transport::transport::Transport as _;
        use lepic_wallet::slate::{MediaType, WireSlate};

        let relay = MockRelay::new(RelayNetwork::Floonet);
        let chain = crate::api::testing::MockChain::new(1).unwrap();
        let mut runtime = chain
            .runtime(crate::api::diagnostics::LogLevel::Warn)
            .unwrap();
        Arc::get_mut(&mut runtime.inner).unwrap().relay = Some(relay.connector());
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let mut sessions = Vec::new();
        for dir in &dirs {
            let mut config = WalletConfig {
                data_dir: dir.path().to_string_lossy().into_owned(),
                chain: crate::api::types::Chain::Floonet,
                node_url: "http://127.0.0.1:1".to_owned(),
                node_api_secret: None,
                epicbox_domain: "epicbox.example".to_owned(),
                epicbox_port: 443,
            };
            let secret = NodeSecret::take(&mut config);
            let session = Session::new(
                &runtime.inner,
                &config,
                &secret,
                AppSecretStore::in_memory(),
            )
            .unwrap();
            session
                .create(SeedOrigin::Generate, Zeroizing::new("password".to_owned()))
                .await
                .unwrap();
            sessions.push(Arc::new(session));
        }
        let (sender, receiver) = (&sessions[0], &sessions[1]);
        sender.epicbox_address().unwrap();
        let to = Destination::new(receiver.epicbox_address().unwrap());
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testdata/vectors/slates/send_epicbox_plain_s1_v3.json"
        ))
        .unwrap();
        let s1 = WireSlate::text(
            MediaType::JSON,
            vector["expected"]["json"].as_str().unwrap().to_owned(),
        );
        let outbound = sender.epicbox().unwrap().outbound().unwrap();
        outbound.deliver(&to, &s1).await.unwrap();
        outbound.deliver(&to, &s1).await.unwrap();

        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle = receiver.claim_listener().unwrap().unwrap();
        let listening = tokio::spawn({
            let receiver = Arc::clone(receiver);
            let seen = Arc::clone(&seen);
            let handle = handle.clone();
            async move {
                receiver
                    .listen(&handle, |event| {
                        if matches!(
                            event.kind,
                            ListenerEventKind::Received | ListenerEventKind::Repeated
                        ) {
                            lock(&seen).push((event.kind, event.tx_id));
                        }
                    })
                    .await
            }
        });
        for _ in 0..2000 {
            if lock(&seen).len() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        handle.stop();
        tokio::time::timeout(std::time::Duration::from_secs(20), listening)
            .await
            .expect("the listener ended")
            .unwrap()
            .unwrap();

        let seen = lock(&seen).clone();
        let [(ListenerEventKind::Received, Some(first)), (kind, again)] = seen.as_slice() else {
            panic!("{seen:?}");
        };
        assert_eq!(*kind, ListenerEventKind::Repeated, "{seen:?}");
        assert_eq!(*again, Some(*first));
    }
}
