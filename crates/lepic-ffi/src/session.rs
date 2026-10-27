//! One open wallet: the engine over the binding's ports, and the glue between engine calls,
//! the app's secret store and Dart streams.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
#[cfg(feature = "tor")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use jiff::Timestamp;
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::tunnel::OnionRoutes;
use lepic_epicbox::{
    ClientSettings, Domain, EpicboxAddress, Network as RelayNetwork, RelayEndpoint, Security,
    TRANSPORT_ID,
};
use lepic_keychain::vault::SecretName;
use lepic_keychain::{SecretStore as _, Seed, Vault};
use lepic_node::{NodeApi as _, Propagation, webpki_tls_config};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, OutputStatus as EngineOutputStatus, TxId, TxState};
use lepic_transport::file::{FILE, FileTransport, response_path};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Exchange as _, Location};
use lepic_wallet::details::TransactionDetails as EngineTransactionDetails;
use lepic_wallet::event::{Balance, Connection, TransportState as EngineTransportState};
use lepic_wallet::inbox::ListenHandle;
use lepic_wallet::legacy_history::{
    ImportWorkDir, LegacyImportOutcome, LegacyImportStatus as EngineLegacyStatus,
    TxOrigin as EngineTxOrigin,
};
use lepic_wallet::lifecycle::PhraseCheck;
use lepic_wallet::refresh::{
    BALANCE_MINIMUM_CONFIRMATIONS, BalanceCategory, OutputDetails, RefreshOutcome,
};
use lepic_wallet::scan::{
    FoundDuring as EngineFoundDuring, ScanCancel, ScanOptions, ScanStart, ScanSummary,
};
use lepic_wallet::selection::Commitment;
use lepic_wallet::selection::{
    Selection, SelectionOptions, SelectionStrategy as EngineStrategy, SelfSendShape,
};
use lepic_wallet::self_send::SelfSent;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use lepic_wallet::slate::WireSlate;
use lepic_wallet::{
    Clock, DATABASE_FILE, Event, NodeEndpoint, Password, Ports, ReceiveRequest, SessionState,
    SharedRng, Wallet, WalletName, WordCount,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::{ClaimHolder, ClaimedStores, RuntimeInner};
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    FeeEstimate, FinalizedTx, FoundDuring, ImportedTx, InboxReport, LegacyImport,
    LegacyImportStatus, ListenerEvent, ListenerEventKind, NodeTip, OutputCategory, OutputStatus,
    PushSignature, ReceivedSlate, ScanFound, ScanProgress, ScanResult, SelectionStrategy,
    SelfSentTx, SendOptions, SentTx, Slate, SlateMessage, SlateStage, TransactionDetails,
    TransportConnection, TransportState, TxOrigin, TxStatus, WalletConfig, WalletEvent,
    WalletEventKind, WalletOutput, WalletSummary,
};
use crate::boundary::InFlight;
use crate::frb_generated::StreamSink;
use crate::node::{BackendCache, BackendKey, Node, NodeBackend, NodeSecret, RelayTor, node_error};
use crate::vault_port::{
    AppVault, SharedStorage, VAULT_KEY, VAULT_NEXT_KEY, VaultBytes, decode, vault_error,
};
use crate::{password as password_change, pin};

mod app_data;
mod contact;
mod http;
#[cfg(not(feature = "tor"))]
mod no_tor;
#[cfg(feature = "tor")]
mod tor;

#[cfg(test)]
pub(crate) use http::HttpReport;
#[cfg(test)]
#[cfg(feature = "tor")]
pub(crate) use tor::TorReport;
mod invoice;
mod servers;

use servers::EpicboxSlot;

type EngineWallet = Wallet<Node, ClaimedStores, AppVault>;

/// Matches the name `lepic-wallet` stores the seed under in the wallet's vault.
const SEED_SECRET: &str = "wallet/seed";

/// The name of the wallet in logs. The binding opens one wallet per data directory.
const WALLET_NAME: &str = "default";

const DEFAULT_ACCOUNT: AccountIndex = AccountIndex(0);

/// The strategy of a send given no options, as `epic-wallet send` and the Epic GUI wallet
/// choose; the engine's own default, `All`, is that of `epic-wallet`'s owner API.
const DEFAULT_STRATEGY: EngineStrategy = EngineStrategy::Smallest;

/// Blocks, a day of them, after which this wallet neither finalizes nor posts an app send and
/// expires it if unanswered. File slates carry it as their TTL too, so the receiver refuses to
/// sign past it. An invoice the app issues carries it as its TTL, so a payer refuses a request
/// a day old and the payment of one that is never finalized is released.
const APP_TTL_BLOCKS: u64 = lepic_wallet::invoice::INVOICE_TTL_BLOCKS;

/// The most change outputs a send may ask for; each one costs a range proof.
const MAX_CHANGE_OUTPUTS: usize = 10;

/// The longest slate text the file method imports, checked before the text is written to a
/// scratch file.
const MAX_SLATE_TEXT_LEN: usize = lepic_transport::file::MAX_WIRE_SLATE_LEN;

/// The running scan's cancel signal in the session's slot, cleared when the scan ends, also
/// when its future is dropped.
struct ScanSlot<'a> {
    slot: &'a Mutex<Option<ScanCancel>>,
    cancel: ScanCancel,
}

impl<'a> ScanSlot<'a> {
    /// Fails with `WalletBusy` while another scan of the session runs, so `cancel_scan` always
    /// reaches the one running.
    fn claim(slot: &'a Mutex<Option<ScanCancel>>, cancel: ScanCancel) -> Result<Self, WalletError> {
        let mut running = lock(slot);
        if running.is_some() {
            return Err(WalletError::new(
                WalletErrorKind::WalletBusy,
                "a scan of this wallet is running",
            ));
        }
        *running = Some(cancel.clone());
        Ok(Self { slot, cancel })
    }
}

impl Drop for ScanSlot<'_> {
    /// Clears the slot only while it holds this scan's signal, never a later scan's.
    fn drop(&mut self) {
        let mut running = lock(self.slot);
        if running
            .as_ref()
            .is_some_and(|cancel| cancel.is_same(&self.cancel))
        {
            running.take();
        }
    }
}

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
    epicbox: Option<EpicboxSlot>,
    listener: Mutex<Option<ListenHandle>>,
    /// The handle a listener that a server switch ended continues with.
    relisten: Mutex<Option<ListenHandle>>,
    /// Held by a listener while it is subscribed, so a server switch can wait for its end.
    listen_run: tokio::sync::Mutex<()>,
    /// Held for reading by every wallet call and for writing by a server switch.
    pub(crate) servers: tokio::sync::RwLock<()>,
    /// Holds the answers of HTTP sends until they are finalized.
    http: lepic_foreign::HttpTransport,
    http_listener: Mutex<http::HttpListener>,
    http_starts: AtomicU64,
    /// Holds the answers of Tor sends until they are finalized.
    #[cfg(feature = "tor")]
    tor: lepic_tor::TorTransport,
    #[cfg(feature = "tor")]
    tor_slot: Mutex<tor::TorSlot>,
    #[cfg(feature = "tor")]
    tor_starts: AtomicU64,
    /// Takes the relay connection through the wallet's tor while it runs (ADR 0021); never
    /// in a build without Tor.
    relay_tor: Arc<RelayTor>,
    /// The same for node requests; it follows the wallet's tor like `relay_tor`, with a
    /// setting of its own.
    node_tor: Arc<RelayTor>,
    /// `expect_tor` was called and no start followed yet: a stop keeps the relay waiting.
    #[cfg(feature = "tor")]
    tor_expected: AtomicBool,
    /// Hosts reached at an onion through tor, with TLS for the host: the built-in table until
    /// the app sets its own. Shared by every connection of the session that goes through tor.
    pub(crate) onion_routes: Arc<OnionRoutes>,
    /// The backend [`Session::node_tip_for`] asked last.
    node_tips: BackendCache<NodeBackend>,
    #[cfg(all(test, feature = "tor"))]
    tor_timings: Mutex<Option<lepic_tor::TorTimings>>,
    /// Makes the next listen fail before it subscribes.
    #[cfg(test)]
    pub(crate) fail_next_listen: std::sync::atomic::AtomicBool,
    /// Outputs per page of [`Session::scan`], in place of the engine's default.
    #[cfg(test)]
    pub(crate) scan_page_size: Mutex<Option<std::num::NonZeroU64>>,
    scan: Mutex<Option<ScanCancel>>,
    balance: Mutex<Option<Balance>>,
    runtime: Arc<RuntimeInner>,
    claim: Arc<ClaimHolder>,
    /// The calls running on the handle, ended by [`Session::lock`].
    pub(crate) in_flight: Arc<InFlight>,
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
    relay_tor: &Arc<RelayTor>,
    onion_routes: &Arc<OnionRoutes>,
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
    #[cfg(feature = "tor")]
    let connector = Arc::new(lepic_epicbox::tunnel::TunnelConnector::with_routes(
        tls,
        Arc::new(tor::RelayTunnel(Arc::clone(relay_tor))),
        Arc::clone(onion_routes),
    ));
    // No tor to go through: the relay is always reached directly.
    #[cfg(not(feature = "tor"))]
    let connector = {
        let _ = (relay_tor, onion_routes);
        Arc::new(lepic_epicbox::TcpConnector::new(tls))
    };
    Ok(Some(EpicboxTransport::new(
        ClientSettings::new(endpoint),
        relay_network(network),
        connector,
    )))
}

impl Session {
    /// A locked wallet on `config.data_dir`, which must exist and not be open anywhere.
    pub(crate) async fn new(
        runtime: &Arc<RuntimeInner>,
        config: &WalletConfig,
        node_secret: &NodeSecret,
        store: AppSecretStore,
    ) -> Result<Self, WalletError> {
        let network = config.chain.network();
        let data_dir = PathBuf::from(&config.data_dir);
        let claim = runtime.claim(&data_dir).await?;
        let data_dir = claim.dir.clone();
        let claim = ClaimHolder::new(claim);
        let node_tor = Arc::new(RelayTor::new(true));
        let relay_tor = Arc::new(RelayTor::new(true));
        let onion_routes = Arc::new(OnionRoutes::default());
        let node = runtime
            .nodes
            .client(config, node_secret, &node_tor, &onion_routes)?;
        let epicbox = epicbox_transport(runtime, config, network, &relay_tor, &onion_routes)?
            .map(EpicboxSlot::new);
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
        #[cfg(feature = "tor")]
        let tor = tor::tor_transport();
        #[cfg(feature = "tor")]
        {
            transports
                .register(Box::new(tor.clone()))
                .map_err(|error| invalid(error.to_string()))?;
            ids.push(lepic_tor::TRANSPORT_ID);
        }
        let engine_config = lepic_wallet::WalletConfig {
            name: WalletName::new(WALLET_NAME).map_err(|error| invalid(error.to_string()))?,
            network,
            data_dir: data_dir.clone(),
            node: NodeEndpoint::parse(&config.node_url)
                .map_err(|_| invalid("node url is not an http or https url with a host"))?,
            transports: ids,
        };
        let vault = VaultBytes::default();
        let ports = Ports {
            node,
            stores: ClaimedStores(Arc::clone(&claim)),
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
            data_dir,
            store,
            vault,
            epicbox,
            listener: Mutex::default(),
            relisten: Mutex::default(),
            listen_run: tokio::sync::Mutex::default(),
            servers: tokio::sync::RwLock::default(),
            http,
            http_listener: Mutex::default(),
            http_starts: AtomicU64::new(0),
            #[cfg(feature = "tor")]
            tor,
            #[cfg(feature = "tor")]
            tor_slot: Mutex::default(),
            #[cfg(feature = "tor")]
            tor_starts: AtomicU64::new(0),
            relay_tor,
            node_tor,
            #[cfg(feature = "tor")]
            tor_expected: AtomicBool::new(false),
            onion_routes,
            node_tips: BackendCache::default(),
            #[cfg(all(test, feature = "tor"))]
            tor_timings: Mutex::default(),
            #[cfg(test)]
            fail_next_listen: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            scan_page_size: Mutex::default(),
            scan: Mutex::default(),
            balance: Mutex::default(),
            runtime: Arc::clone(runtime),
            claim,
            in_flight: Arc::default(),
        })
    }

    pub(crate) fn runtime(&self) -> &Arc<RuntimeInner> {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn holds_directory(&self) -> bool {
        self.claim.is_held()
    }

    #[cfg(test)]
    pub(crate) fn directory_claim(&self) -> &Arc<ClaimHolder> {
        &self.claim
    }

    pub(crate) fn store(&self) -> &AppSecretStore {
        &self.store
    }

    /// Stops tor, the listeners and any scan, forgets the cached balance and the relay
    /// identity, drops the root key and ends the calls still running, which fail with
    /// `Cancelled` at their next await; a store write under way runs to its end. The
    /// directory is released as soon as the database closes: now, or when the last such call
    /// has ended.
    pub(crate) fn lock(&self) {
        #[cfg(feature = "tor")]
        self.tor_expected.store(false, Ordering::Relaxed);
        if let Some(listener) = lock(&self.listener).take() {
            listener.stop();
        }
        if let Some(listener) = self.take_relisten() {
            listener.stop();
        }
        if let Some(scan) = lock(&self.scan).take() {
            scan.cancel();
        }
        lock(&self.balance).take();
        if let Some(epicbox) = &self.epicbox {
            epicbox.current().detach();
        }
        // Before the engine locks, so a database that closes at the lock releases the
        // directory.
        self.claim.release_when_closed();
        self.engine.lock();
        // After the engine locks, so a start that saw it unlocked is in its slot. Tor stops
        // before the listeners it forwards to.
        self.stop_tor();
        self.stop_http_listener();
        self.in_flight.abort_all();
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
        match self.store.read(VAULT_NEXT_KEY).await? {
            None => self.engine.open(self::password(password)).await?,
            Some(next) => self.open_settling_change(password, &next).await?,
        }
        self.seed_node_tip()
    }

    /// Opens while `next` holds the vault of a password change that stopped before it ended. A
    /// password that opens the stored vault drops the change; one that opens only `next`
    /// finishes it, making `next` the stored vault.
    async fn open_settling_change(
        &self,
        password: Zeroizing<String>,
        next: &str,
    ) -> Result<(), WalletError> {
        let stored = self
            .engine
            .open(self::password(password.clone()))
            .await
            .map_err(WalletError::from);
        let error = match stored {
            Ok(()) => {
                password_change::discard_next(&self.store).await;
                info!("unfinished password change dropped");
                return Ok(());
            }
            Err(error)
                if matches!(
                    error.kind,
                    WalletErrorKind::WrongPassword
                        | WalletErrorKind::SecretStore
                        | WalletErrorKind::WalletNotFound
                ) =>
            {
                error
            }
            Err(error) => return Err(error),
        };
        let Ok(bytes) = decode(next) else {
            return Err(error);
        };
        self.vault.set(bytes);
        if let Err(next_error) = self.engine.open(self::password(password)).await {
            let next_error = WalletError::from(next_error);
            return Err(if next_error.kind == WalletErrorKind::WrongPassword {
                next_error
            } else {
                error
            });
        }
        if let Err(error) = self.store.write(VAULT_KEY, next.to_owned()).await {
            self.engine.lock();
            return Err(error);
        }
        password_change::discard_next(&self.store).await;
        info!("unfinished password change finished");
        Ok(())
    }

    /// Re-encrypts the vault under `new` once `current` opened it, as [`password_change`]
    /// describes. Refused with `Unsupported` for a PIN wallet, whose password the user never
    /// sees, before any attempt is counted.
    pub(crate) async fn change_password(
        &self,
        current: Zeroizing<String>,
        new: Zeroizing<String>,
    ) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        if pin::is_pin_wallet(&self.store).await? {
            return Err(WalletError::new(
                WalletErrorKind::Unsupported,
                "a pin wallet changes its pin, not its password",
            ));
        }
        let runtime = self.runtime();
        pin::after_password_attempt(
            &runtime.pin,
            &self.store,
            || password_change::open_stored(&self.store, current),
            |vault| password_change::replace(&self.store, vault, new, runtime.kdf),
        )
        .await?;
        info!("wallet password changed");
        Ok(())
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
    /// Refreshes, then runs the short update scan that finds what another wallet on the phrase
    /// received and the change of its spends; a scan that fails is logged and the next refresh
    /// tries again.
    pub(crate) async fn refresh(&self) -> Result<WalletSummary, WalletError> {
        let mut events = self.engine.subscribe();
        let refreshed = self.engine.refresh().await?;
        if matches!(refreshed, RefreshOutcome::Refreshed(_))
            && let Err(error) = self.engine.refresh_scan().await
        {
            warn!(error = %error, "update scan after a refresh failed");
        }
        match refreshed {
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
                // The update scan may have stored the change of a spend elsewhere since.
                if latest.is_some()
                    && let Ok(balance) = self.engine.balance(DEFAULT_ACCOUNT)
                {
                    latest = Some(balance);
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

    pub(crate) fn outputs(&self) -> Result<Vec<WalletOutput>, WalletError> {
        let outputs = self.engine.outputs(DEFAULT_ACCOUNT)?;
        Ok(outputs.iter().map(wallet_output).collect())
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
        options: Option<SendOptions>,
    ) -> Result<FeeEstimate, WalletError> {
        let options = Self::send_request_with(amount, minimum_confirmations, None, options)?
            .selection_options();
        let selection = self
            .engine
            .estimate_fee(Amount::new(amount), options)
            .await?;
        fee_estimate(&selection)
    }

    pub(crate) async fn estimate_max(
        &self,
        minimum_confirmations: u64,
        options: Option<SendOptions>,
    ) -> Result<FeeEstimate, WalletError> {
        let options =
            Self::send_request_with(0, minimum_confirmations, None, options)?.selection_options();
        let selection = self.engine.estimate_max(options).await?;
        fee_estimate(&selection)
    }

    fn self_send_options(minimum_confirmations: u64) -> SelectionOptions {
        Self::send_request(0, minimum_confirmations, None).selection_options()
    }

    pub(crate) async fn estimate_self_send(
        &self,
        shape: SelfSendShape,
        minimum_confirmations: u64,
    ) -> Result<FeeEstimate, WalletError> {
        let selection = self
            .engine
            .estimate_self_send(Self::self_send_options(minimum_confirmations), shape)
            .await?;
        fee_estimate(&selection)
    }

    pub(crate) async fn self_send(
        &self,
        shape: SelfSendShape,
        minimum_confirmations: u64,
    ) -> Result<SelfSentTx, WalletError> {
        let sent = self
            .engine
            .self_send(
                Self::self_send_options(minimum_confirmations),
                shape,
                Propagation::Fluff,
            )
            .await?;
        self_sent_tx(&sent)
    }

    pub(crate) async fn spend_outputs_to_self(
        &self,
        commitments: Vec<String>,
        minimum_confirmations: u64,
    ) -> Result<SelfSentTx, WalletError> {
        // Matched against the stored outputs, so an unknown commitment is refused here and
        // the engine checks that each one found may be spent.
        let outputs = self.engine.outputs(DEFAULT_ACCOUNT)?;
        let commitments = commitments
            .iter()
            .enumerate()
            .map(|(position, hex)| {
                let hex = hex.trim().to_ascii_lowercase();
                outputs
                    .iter()
                    .find(|details| details.output.id.commitment.to_hex() == hex)
                    .map(|details| details.output.id.commitment)
                    .ok_or_else(|| {
                        invalid(format!(
                            "commitment {position} is not an output of this wallet"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sent = self
            .engine
            .spend_outputs_to_self(
                Self::self_send_options(minimum_confirmations),
                commitments,
                Propagation::Fluff,
            )
            .await?;
        self_sent_tx(&sent)
    }

    pub(crate) async fn scan(
        &self,
        start_height: Option<u64>,
        delete_unconfirmed: bool,
        progress: impl Fn(ScanProgress),
    ) -> Result<(), WalletError> {
        if delete_unconfirmed && start_height.is_some() {
            return Err(invalid(
                "a scan with delete_unconfirmed starts from the beginning of the chain",
            ));
        }
        let cancel = ScanCancel::new();
        let _running = ScanSlot::claim(&self.scan, cancel.clone())?;
        // Only a scan from genesis completes a restore scan, so while one is pending a scan
        // without a start begins there, where a stopped one resumes, as `lepic wallet scan`
        // does.
        let start = match start_height {
            Some(0) => ScanStart::Genesis,
            Some(height) => ScanStart::Height(Height::new(height)),
            None if self.engine.restore_scan_required()? => ScanStart::Genesis,
            None => ScanStart::LastScanned,
        };
        #[allow(unused_mut)]
        let mut options = ScanOptions {
            start,
            delete_unconfirmed,
            ..ScanOptions::update(self.network)
        };
        #[cfg(test)]
        if let Some(size) = *lock(&self.scan_page_size) {
            options.page_size = size;
        }
        let mut events = self.engine.subscribe();
        let scan = self.engine.scan(options, &cancel);
        tokio::pin!(scan);
        let result = loop {
            tokio::select! {
                result = &mut scan => break result,
                event = events.recv() => match event {
                    Ok(Event::Sync(sync)) => {
                        progress(scan_progress(sync.height.value(), sync.target.value(), false));
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break (&mut scan).await,
                },
            }
        };
        let summary = result?;
        info!(height = %summary.end_height, "scan reported");
        let mut last = scan_progress(summary.end_height.value(), summary.end_height.value(), true);
        // The engine skips a start above the tip without scanning or storing anything.
        if summary.start_height > summary.end_height {
            last.message = "scan skipped: the start height is above the chain tip".to_owned();
        }
        progress(ScanProgress {
            result: Some(scan_result(&summary)),
            ..last
        });
        Ok(())
    }

    pub(crate) fn restore_scan_required(&self) -> Result<bool, WalletError> {
        Ok(self.engine.restore_scan_required()?)
    }

    pub(crate) fn fingerprint(&self) -> Result<String, WalletError> {
        Ok(self.engine.fingerprint()?)
    }

    pub(crate) fn cancel_scan(&self) {
        if let Some(scan) = lock(&self.scan).as_ref() {
            scan.cancel();
        }
    }

    /// A send with the binding's default selection, as [`Session::send_request_with`] without
    /// options makes it.
    fn send_request(
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
    ) -> SendRequest {
        SendRequest {
            minimum_confirmations,
            message,
            strategy: DEFAULT_STRATEGY,
            local_ttl_blocks: Some(APP_TTL_BLOCKS),
            ..SendRequest::new(DEFAULT_ACCOUNT, Amount::new(amount))
        }
    }

    /// Fails with `InvalidArgument` for change outputs outside 1..=[`MAX_CHANGE_OUTPUTS`].
    fn send_request_with(
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SendRequest, WalletError> {
        let request = Self::send_request(amount, minimum_confirmations, message);
        let Some(options) = options else {
            return Ok(request);
        };
        let (strategy, change_outputs, exclude_outputs) = selection_choice(&options)?;
        Ok(SendRequest {
            strategy,
            change_outputs,
            exclude_outputs,
            ..request
        })
    }

    /// [`Session::send_request_with`] for the file method, whose slate carries the limit as its
    /// TTL.
    fn file_send_request(
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SendRequest, WalletError> {
        Ok(SendRequest {
            ttl_blocks: Some(APP_TTL_BLOCKS),
            ..Self::send_request_with(amount, minimum_confirmations, message, options)?
        })
    }

    pub(crate) async fn send_file(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        path: PathBuf,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SentTx, WalletError> {
        let sent = self
            .engine
            .send(
                Self::file_send_request(amount, minimum_confirmations, message, options)?,
                Delivery::Export {
                    transport: FILE,
                    to: Location::File(path),
                },
            )
            .await?;
        Ok(sent_tx(&sent))
    }

    #[cfg(test)]
    pub(crate) async fn create_send_slate(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
    ) -> Result<Slate, WalletError> {
        self.create_send_slate_with(amount, minimum_confirmations, message, None)
            .await
    }

    pub(crate) async fn create_send_slate_with(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<Slate, WalletError> {
        let scratch = ScratchFile::new(&self.data_dir)?;
        let sent = self
            .send_file(
                amount,
                minimum_confirmations,
                scratch.path.clone(),
                message,
                options,
            )
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

    /// Finalizes the S2 of a send, or the I2 of an invoice this wallet issued, in the file at
    /// `path`. The engine checks either against what this wallet stored for its slate id.
    pub(crate) async fn finalize_file(&self, path: &Path) -> Result<FinalizedTx, WalletError> {
        let wire = FileTransport::new()
            .import(&Location::File(path.to_owned()))
            .await
            .map_err(|error| transport_error(&error))?;
        let finalized = if self.is_invoice_payment(&wire) {
            self.engine
                .finalize_invoice(FILE, &wire, Propagation::Fluff)
                .await?
        } else {
            self.engine
                .finalize(FILE, &wire, Propagation::Fluff)
                .await?
        };
        Ok(FinalizedTx {
            tx_id: finalized.tx_id.0,
            slate_id: finalized.slate.id().to_string(),
        })
    }

    /// Whether `wire` reads as an I2. Anything else goes to the finalize of a send, which
    /// names what is wrong with it.
    fn is_invoice_payment(&self, wire: &WireSlate) -> bool {
        std::str::from_utf8(wire.as_bytes())
            .ok()
            .and_then(|text| crate::inspect::inspect(text.to_owned(), self.network).ok())
            .is_some_and(|info| info.stage == SlateStage::I2)
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
            self.engine.epicbox_attach(&epicbox.current())?;
        }
        Ok(())
    }

    pub(crate) async fn release(&self, tx_id: u32) -> Result<(), WalletError> {
        Ok(self.engine.release(TxId(tx_id)).await?)
    }

    /// The transport of the relay in use.
    pub(crate) fn epicbox(&self) -> Result<EpicboxTransport, WalletError> {
        self.epicbox
            .as_ref()
            .map(EpicboxSlot::current)
            .ok_or_else(|| {
                WalletError::new(
                    WalletErrorKind::Unsupported,
                    "epicbox is not configured for this wallet",
                )
            })
    }

    pub(crate) fn epicbox_address(&self) -> Result<String, WalletError> {
        Ok(self.engine.epicbox_attach(&self.epicbox()?)?.to_string())
    }

    /// Never logs the token, the text or the signature.
    pub(crate) fn push_signature(
        &self,
        action: &str,
        token: &str,
        timestamp: u64,
    ) -> Result<PushSignature, WalletError> {
        let action =
            lepic_epicbox::PushAction::parse(action).map_err(|e| invalid(e.to_string()))?;
        let request = lepic_epicbox::PushRequest::new(action, token, timestamp)
            .map_err(|e| invalid(e.to_string()))?;
        let (address, signature) = self
            .engine
            .epicbox_push_signature(&self.epicbox()?, &request)?;
        Ok(PushSignature {
            address: address.to_string(),
            signature: signature.to_der_hex(),
        })
    }

    pub(crate) async fn send_epicbox(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        address: String,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SentTx, WalletError> {
        let request = Self::send_request_with(amount, minimum_confirmations, message, options)?;
        let epicbox = self.epicbox()?;
        relay_address(&address, self.network)
            .ok_or_else(|| invalid("not an epicbox address with a relay on this network"))?;
        self.engine.epicbox_attach(&epicbox)?;
        let sent = self
            .engine
            .send(
                request,
                Delivery::Deliver {
                    transport: TRANSPORT_ID,
                    to: Destination::new(address),
                },
            )
            .await?;
        Ok(sent_tx(&sent))
    }

    pub(crate) async fn resend_epicbox(&self, tx_id: u32) -> Result<(), WalletError> {
        let epicbox = self.epicbox()?;
        let details = self.engine.transaction_details(TxId(tx_id)).await?;
        let to = details
            .counterparty
            .filter(|_| {
                details.transaction.entry.transport.as_deref() == Some(TRANSPORT_ID.as_str())
            })
            .ok_or_else(|| invalid("transaction is not a send over epicbox"))?;
        self.engine.epicbox_attach(&epicbox)?;
        Ok(self
            .engine
            .resend(
                TxId(tx_id),
                Delivery::Deliver {
                    transport: TRANSPORT_ID,
                    to,
                },
            )
            .await?)
    }

    pub(crate) async fn drain_epicbox(&self) -> Result<InboxReport, WalletError> {
        let epicbox = self.epicbox()?;
        // The listener subscribes the same address and gets every stored message itself; a
        // second connection beside it would only handle them twice.
        if self.listener_running() {
            return Ok(InboxReport::default());
        }
        let summary = self.engine.epicbox_drain(&epicbox).await?;
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

    /// Runs the listener until `handle` is stopped, handing what it does to `report`. A
    /// server switch that moves it to a new relay hands it the handle to continue with.
    pub(crate) async fn listen(
        &self,
        handle: &ListenHandle,
        report: impl Fn(ListenerEvent),
    ) -> Result<(), WalletError> {
        let mut handle = handle.clone();
        loop {
            // A switch under way ends first, so the listener starts on the servers it set.
            drop(self.servers.read().await);
            let result = {
                let _running = self.listen_run.lock().await;
                if handle.is_stopped() {
                    Ok(())
                } else {
                    self.listen_once(&handle, &report).await
                }
            };
            let next = {
                let _slot = lock(&self.listener);
                let next = self.take_relisten().filter(|next| !next.is_stopped());
                if next.is_none() {
                    // A listener that ended on its own reads as stopped, so it can be started
                    // again and no switch hands it on.
                    handle.stop();
                }
                next
            };
            match next {
                Some(next) => handle = next,
                None => return result,
            }
        }
    }

    async fn listen_once(
        &self,
        handle: &ListenHandle,
        report: &impl Fn(ListenerEvent),
    ) -> Result<(), WalletError> {
        #[cfg(test)]
        if self
            .fail_next_listen
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(WalletError::new(WalletErrorKind::Other, "listen failed"));
        }
        let epicbox = self.epicbox()?;
        let mut events = self.engine.subscribe();
        let listen = self.engine.epicbox_listen(&epicbox, handle);
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
        result: None,
    }
}

const fn scan_result(summary: &ScanSummary) -> ScanResult {
    ScanResult {
        start_height: summary.start_height.value(),
        end_height: summary.end_height.value(),
        resumed: summary.resumed,
        found: summary.found,
        restored: summary.restored,
        revived: summary.revived,
        unlocked: summary.unlocked,
        deleted: summary.deleted,
    }
}

fn wallet_output(details: &OutputDetails) -> WalletOutput {
    let output = &details.output;
    WalletOutput {
        commitment: output.id.commitment.to_hex(),
        value: output.amount.value(),
        status: match output.status {
            EngineOutputStatus::Unconfirmed => OutputStatus::Unconfirmed,
            EngineOutputStatus::Unspent => OutputStatus::Unspent,
            EngineOutputStatus::Locked => OutputStatus::Locked,
            EngineOutputStatus::Spent => OutputStatus::Spent,
        },
        category: details.category.map(|category| match category {
            BalanceCategory::Spendable => OutputCategory::Spendable,
            BalanceCategory::AwaitingConfirmation => OutputCategory::AwaitingConfirmation,
            BalanceCategory::AwaitingFinalization => OutputCategory::AwaitingFinalization,
            BalanceCategory::Immature => OutputCategory::Immature,
            BalanceCategory::Locked => OutputCategory::Locked,
            BalanceCategory::UnpaidInvoice => OutputCategory::UnpaidInvoice,
        }),
        is_coinbase: output.id.features.is_coinbase(),
        height: output.height.value(),
        lock_height: output.lock_height.value(),
        mmr_index: output.mmr_index,
        confirmations: details.confirmations,
        tx_id: output.tx.map(|tx| tx.0),
    }
}

fn self_sent_tx(sent: &SelfSent) -> Result<SelfSentTx, WalletError> {
    let out_of_range = || WalletError::new(WalletErrorKind::Other, "self-send out of range");
    let selection = &sent.selection;
    Ok(SelfSentTx {
        tx_id: sent.tx_id.0,
        received_tx_id: sent.received_tx_id.0,
        amount: selection.amount.value(),
        fee: selection.fee.value(),
        input_count: u32::try_from(selection.inputs.len()).map_err(|_| out_of_range())?,
        output_count: u32::try_from(selection.change.len())
            .ok()
            .and_then(|change| change.checked_add(1))
            .ok_or_else(out_of_range)?,
    })
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
        undelivered: details.undelivered,
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
            EngineTxOrigin::OtherWallet => TxOrigin::OtherWallet,
        },
        imported: details.imported.as_ref().map(|imported| ImportedTx {
            source_id: imported.source_id,
            kind: imported.kind.into(),
            input_count: imported.input_count,
            output_count: imported.output_count,
            check: imported.check.into(),
        }),
        found: details.found.map(|found| ScanFound {
            during: match found.during {
                EngineFoundDuring::Restore => FoundDuring::Restore,
                EngineFoundDuring::Rescan => FoundDuring::Rescan,
            },
            dated_by_block: found.dated_by_block,
        }),
        output_commits: details
            .output_commits
            .iter()
            .copied()
            .map(|commitment| commitment.to_hex())
            .collect(),
        spent_commits: details
            .spent_commits
            .iter()
            .map(Commitment::to_hex)
            .collect(),
        sender_reported_posted_at_ms: details
            .sender_reported_posted_at
            .map(Timestamp::as_millisecond),
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

/// Outputs one send may be told to leave out.
const MAX_EXCLUDED_OUTPUTS: usize = 500;

/// The engine's strategy, change outputs and excluded outputs for `options`. Fails with
/// `InvalidArgument` for change outputs outside 1..=[`MAX_CHANGE_OUTPUTS`], an excluded output
/// that is not a commitment, or more than [`MAX_EXCLUDED_OUTPUTS`] of them.
pub(crate) fn selection_choice(
    options: &SendOptions,
) -> Result<(EngineStrategy, NonZeroUsize, Vec<Commitment>), WalletError> {
    if options.exclude_outputs.len() > MAX_EXCLUDED_OUTPUTS {
        return Err(invalid(format!(
            "at most {MAX_EXCLUDED_OUTPUTS} outputs may be excluded"
        )));
    }
    let exclude = options
        .exclude_outputs
        .iter()
        .map(|hex| {
            Commitment::from_hex(hex)
                .map_err(|_| invalid("an excluded output is not a commitment".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let change_outputs = usize::try_from(options.change_outputs)
        .ok()
        .filter(|count| *count <= MAX_CHANGE_OUTPUTS)
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| {
            invalid(format!(
                "change outputs must be from 1 to {MAX_CHANGE_OUTPUTS}"
            ))
        })?;
    let strategy = match options.strategy {
        SelectionStrategy::Smallest => EngineStrategy::Smallest,
        SelectionStrategy::All => EngineStrategy::All,
    };
    Ok((strategy, change_outputs, exclude))
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
        locked: selection.total.value(),
        change_outputs: u32::try_from(selection.change.len()).map_err(|_| out_of_range())?,
    })
}

fn transport_error(error: &lepic_transport::error::TransportError) -> WalletError {
    WalletError::chained(WalletErrorKind::TransportFailed, error)
}

const fn transport_state(state: EngineTransportState) -> TransportState {
    match state {
        EngineTransportState::Connecting => TransportState::Connecting,
        EngineTransportState::Connected => TransportState::Connected,
        EngineTransportState::Disconnected => TransportState::Disconnected,
        _ => TransportState::Stopped,
    }
}

const fn transport_connection(connection: Connection) -> TransportConnection {
    match connection {
        Connection::PaymentsDrain => TransportConnection::PaymentsDrain,
        Connection::Listener => TransportConnection::Listener,
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
        Event::SelfSent(stored) => WalletEvent {
            tx_id: Some(stored.tx_id.0),
            account: Some(stored.account.0),
            amount: Some(stored.amount.value()),
            ..WalletEvent::of(WalletEventKind::SelfSend)
        },
        Event::Sync(sync) => WalletEvent {
            height: Some(sync.height.value()),
            target_height: Some(sync.target.value()),
            ..WalletEvent::of(WalletEventKind::Sync)
        },
        Event::Transport(status) => WalletEvent {
            transport: Some(status.transport.as_str().to_owned()),
            transport_state: Some(transport_state(status.state)),
            transport_connection: Some(transport_connection(status.connection)),
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
        Event::UnknownSlate(unknown) => WalletEvent {
            slate_id: Some(unknown.slate_id.to_string()),
            sender: Some(unknown.sender.clone()),
            slate_stage: Some(unknown.stage.as_str().to_owned()),
            ..WalletEvent::of(WalletEventKind::UnknownSlate)
        },
        Event::ReceiveSuperseded(superseded) => WalletEvent {
            tx_id: Some(superseded.tx_id.0),
            slate_id: Some(superseded.slate_id.to_string()),
            ..WalletEvent::of(WalletEventKind::ReceiveSuperseded)
        },
        Event::PaymentPosted(posted) => WalletEvent {
            tx_id: Some(posted.tx_id.0),
            slate_id: Some(posted.slate_id.to_string()),
            kernel_excess: Some(posted.excess.to_hex()),
            ..WalletEvent::of(WalletEventKind::PaymentPosted)
        },
        Event::PairingReplied(news) => {
            contact::contact_event(WalletEventKind::PairingReplied, news)
        }
        Event::PairingConfirmed(news) => {
            contact::contact_event(WalletEventKind::PairingConfirmed, news)
        }
        Event::PairingFailed(failed) => WalletEvent {
            contact_id: Some(failed.contact_id.to_string()),
            pairing_failure: Some(contact::failure_reason(failed.reason)),
            ..WalletEvent::of(WalletEventKind::PairingFailed)
        },
        Event::ContactUpdated(news) => {
            contact::contact_event(WalletEventKind::ContactUpdated, news)
        }
        Event::HomeRelayUnreachable(unreachable) => WalletEvent {
            relay: Some(unreachable.relay.clone()),
            ..WalletEvent::of(WalletEventKind::HomeRelayUnreachable)
        },
        Event::ContactKeysRestored(news) => {
            contact::contact_event(WalletEventKind::ContactKeysRestored, news)
        }
        Event::ContactKeysChanged(news) => {
            contact::contact_event(WalletEventKind::ContactKeysChanged, news)
        }
        Event::ContactUnpaired(news) => {
            contact::contact_event(WalletEventKind::ContactUnpaired, news)
        }
        Event::InvoiceFromContact(invoice) => WalletEvent {
            contact_id: Some(invoice.contact_id.to_string()),
            slate_id: Some(invoice.slate_id.to_string()),
            amount: Some(invoice.amount.value()),
            purpose: invoice.purpose.map(contact::slate_purpose),
            reference: invoice.reference.clone(),
            expires: invoice.expires,
            message: invoice.message.clone(),
            ..WalletEvent::of(WalletEventKind::InvoiceFromContact)
        },
        Event::WithdrawalFromContact(slate) => {
            contact::slate_event(WalletEventKind::WithdrawalFromContact, slate)
        }
        Event::SealedReceived(slate) => {
            contact::slate_event(WalletEventKind::SealedReceived, slate)
        }
        Event::SealedUnopenable(news) => {
            contact::contact_event(WalletEventKind::SealedUnopenable, news)
        }
        Event::OutboxDelivered(news) => {
            contact::outbox_event(WalletEventKind::OutboxDelivered, news)
        }
        Event::OutboxStuck(news) => contact::outbox_event(WalletEventKind::OutboxStuck, news),
        Event::ContactPaymentFinalized(slate) => {
            contact::slate_event(WalletEventKind::ContactPaymentFinalized, slate)
        }
        Event::ContactPayload(news) => {
            contact::contact_event(WalletEventKind::ContactPayload, news)
        }
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
            reason: None,
            retry_in_ms: None,
        });
    }
    if let Event::TransportDisconnected(disconnect) = event
        && disconnect.transport == TRANSPORT_ID
        && disconnect.connection == Connection::Listener
    {
        return Some(ListenerEvent {
            kind: ListenerEventKind::Disconnected,
            tx_id: None,
            slate_id: None,
            message: String::new(),
            reason: Some(disconnect.reason.clone()),
            retry_in_ms: disconnect
                .retry_in
                .map(|wait| u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)),
        });
    }
    let (kind, tx_id) = match event {
        Event::Transport(status)
            if status.transport == TRANSPORT_ID && status.connection == Connection::Listener =>
        {
            match transport_state(status.state) {
                TransportState::Connected => (ListenerEventKind::Connected, None),
                TransportState::Connecting
                | TransportState::Disconnected
                | TransportState::Stopped => return None,
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
        reason: None,
        retry_in_ms: None,
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

/// The tip and version of the node `config` names, without opening a wallet. No wallet is
/// open, so there is no tor of its own to go through: the request always goes directly.
pub(crate) async fn node_tip(
    runtime: &Arc<RuntimeInner>,
    config: &WalletConfig,
    node_secret: &NodeSecret,
) -> Result<NodeTip, WalletError> {
    let node = runtime.nodes.client(
        config,
        node_secret,
        &Arc::new(RelayTor::new(true)),
        &Arc::new(OnionRoutes::default()),
    )?;
    ask_node_tip(&node).await
}

impl Session {
    /// The tip and version of the node `config` names, asked as the session asks its own
    /// node: through the wallet's tor and onion routes while node requests go over tor, and
    /// directly otherwise or for a loopback node. The session's node stays as it is. Fails with
    /// `Locked` on a locked wallet, whose tor is stopped.
    pub(crate) async fn node_tip_for(
        &self,
        config: &WalletConfig,
        node_secret: &NodeSecret,
    ) -> Result<NodeTip, WalletError> {
        self.ensure_unlocked()?;
        let over_tor = *self.node_tor.active().borrow();
        let backend =
            self.node_tips
                .get_or_build(BackendKey::new(config, node_secret, over_tor), || {
                    self.runtime.nodes.backend(
                        config,
                        node_secret,
                        &self.node_tor,
                        &self.onion_routes,
                    )
                })?;
        ask_node_tip(&self.runtime.nodes.client_over(backend)).await
    }
}

async fn ask_node_tip(node: &Node) -> Result<NodeTip, WalletError> {
    let tip = node.get_tip().await.map_err(|error| node_error(&error))?;
    let version = node
        .get_version()
        .await
        .map_err(|error| node_error(&error))?;
    // Both are extras of the answer, asked for at once: a node that fails them still gives
    // its tip.
    let (ready_for_txs, header) = tokio::join!(node.ready_for_txs(), node.get_header(tip.height));
    let ready_for_txs = ready_for_txs.unwrap_or_else(|error| {
        debug!(error = %lepic_telemetry::ErrorChain(&error), "ready_for_txs unanswered");
        None
    });
    let tip_time_ms = match header {
        Ok(header) => header.map(|header| header.timestamp.as_millisecond()),
        Err(error) => {
            debug!(error = %lepic_telemetry::ErrorChain(&error), "tip header unanswered");
            None
        }
    };
    Ok(NodeTip {
        height: tip.height.value(),
        node_version: version.node_version,
        ready_for_txs,
        tip_time_ms,
    })
}

/// Whether the app's store holds a wallet vault, also one of an unfinished password change.
pub(crate) async fn wallet_exists(store: &AppSecretStore) -> Result<bool, WalletError> {
    Ok(store.read(VAULT_KEY).await?.is_some() || store.read(VAULT_NEXT_KEY).await?.is_some())
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
    let claim = runtime.claim(Path::new(&config.data_dir)).await?;
    remove_database(&claim.dir).await?;
    store.delete(VAULT_KEY).await?;
    store.delete(VAULT_NEXT_KEY).await?;
    crate::pin::forget(store).await?;
    info!("wallet deleted");
    Ok(())
}

/// Seals the seed of `phrase` under `password` as the vault in `store`, once the database in
/// `config.data_dir` proves it that seed's; the database is left as it is, but for the seed
/// check a database without one gets. It needs no node: the database is opened only for the
/// check, under the directory's claim.
pub(crate) async fn reset_password(
    runtime: &Arc<RuntimeInner>,
    config: &WalletConfig,
    store: &AppSecretStore,
    phrase: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<(), WalletError> {
    let network = config.chain.network();
    // Held to the end, so no wallet on the directory opens while the vault is replaced.
    let claim = runtime.claim(Path::new(&config.data_dir)).await?;
    let dir = claim.dir.clone();
    let phrase = normalize_phrase(&phrase);
    let checked = tokio::task::spawn_blocking(move || {
        lepic_wallet::lifecycle::check_phrase(&lepic_wallet::SqliteStores, &dir, network, &phrase)
    })
    .await
    .map_err(|_| WalletError::new(WalletErrorKind::Panic, "phrase check failed inside lepic"))?;
    let seed = match checked {
        Ok(PhraseCheck::Matches(seed)) => seed,
        Ok(PhraseCheck::Unused) => {
            return Err(WalletError::new(
                WalletErrorKind::WalletNotFound,
                "the wallet directory holds no wallet database to check the phrase against",
            ));
        }
        Ok(PhraseCheck::Unproven) => {
            return Err(WalletError::new(
                WalletErrorKind::WalletNotFound,
                "the wallet database holds nothing that proves the phrase: \
                 delete the wallet and restore it",
            ));
        }
        Err(lepic_wallet::WalletError::ForeignDatabase) => {
            return Err(WalletError::new(
                WalletErrorKind::PhraseMismatch,
                "the recovery phrase is not the phrase of this wallet",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let vault = password_change::seal_seed(seed, password.clone(), runtime.kdf).await?;
    // Before the vault is replaced: a PIN key left beside the new vault would unseal the old
    // password, and every PIN attempt would fail and be counted. A stop between the two
    // leaves the old vault without a PIN; the reset run again finishes.
    crate::pin::forget(store).await?;
    password_change::install(store, vault, password).await?;
    drop(claim);
    info!("wallet password reset");
    Ok(())
}

#[cfg(test)]
mod tests {
    use lepic_wallet::event::{ReceivedTransaction, SelfSentTransaction, TransactionState};

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
    fn a_scan_slot_frees_only_its_own_scan() {
        let slot = Mutex::new(None);
        let first = ScanSlot::claim(&slot, ScanCancel::new()).unwrap();
        assert_eq!(
            ScanSlot::claim(&slot, ScanCancel::new())
                .err()
                .map(|e| e.kind),
            Some(WalletErrorKind::WalletBusy)
        );
        // A lock takes the slot while the scan winds down; a new scan may claim it then.
        lock(&slot).take();
        let second = ScanCancel::new();
        let claimed = ScanSlot::claim(&slot, second.clone()).unwrap();

        drop(first);

        assert!(
            lock(&slot)
                .as_ref()
                .is_some_and(|held| held.is_same(&second))
        );
        drop(claimed);
        assert!(lock(&slot).is_none());
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
        let output = keychain
            .commit(400, &id, SwitchCommitment::Regular)
            .unwrap();
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
            undelivered: true,
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
            found: Some(lepic_wallet::scan::ScanFound {
                during: EngineFoundDuring::Restore,
                dated_by_block: true,
            }),
            output_commits: vec![output],
            spent_commits: vec![output],
            sender_reported_posted_at: Some(confirmed),
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
                undelivered: true,
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
                found: Some(ScanFound {
                    during: FoundDuring::Restore,
                    dated_by_block: true,
                }),
                output_commits: vec![output.to_hex()],
                spent_commits: vec![output.to_hex()],
                sender_reported_posted_at_ms: Some(1_790_000_600_456),
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
    fn an_answer_for_an_unknown_slate_is_its_own_event_with_its_sender() {
        use lepic_wallet::event::{SlateId, UnknownSlate};
        let slate_id = SlateId::from_bytes([4; 16]);
        let sender = "esWpjSHdScqVnFSkbM8mPEpzAGBWWSFg4Pu3sKHnqCsKgjzU4YD6@epicbox.epiccash.com";
        for (stage, text) in [
            (lepic_wallet::slate::Stage::S2, "S2"),
            (lepic_wallet::slate::Stage::I2, "I2"),
        ] {
            let event = wallet_event(&Event::UnknownSlate(UnknownSlate {
                slate_id,
                stage,
                sender: sender.to_owned(),
            }))
            .unwrap();
            assert_eq!(event.kind, WalletEventKind::UnknownSlate);
            assert_eq!(event.slate_id, Some(slate_id.to_string()));
            assert_eq!(event.slate_stage.as_deref(), Some(text));
            assert_eq!(event.sender.as_deref(), Some(sender));
            assert_eq!(event.tx_id, None);
        }
    }

    #[test]
    fn a_superseded_receive_is_its_own_event_with_its_transaction() {
        use lepic_wallet::event::{SlateId, SupersededReceive};
        let slate_id = SlateId::from_bytes([5; 16]);
        let event = wallet_event(&Event::ReceiveSuperseded(SupersededReceive {
            tx_id: TxId(6),
            slate_id,
        }))
        .unwrap();
        assert_eq!(event.kind, WalletEventKind::ReceiveSuperseded);
        assert_eq!(event.tx_id, Some(6));
        assert_eq!(event.slate_id, Some(slate_id.to_string()));
        assert_eq!(event.sender, None);
    }

    #[test]
    fn a_posted_payment_is_its_own_event_with_its_kernel() {
        use lepic_keychain::{Identifier, Keychain, SwitchCommitment};
        use lepic_wallet::event::{PostedPayment, SlateId};
        let slate_id = SlateId::from_bytes([7; 16]);
        let keychain = Keychain::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
            Network::Floonet,
        )
        .unwrap();
        let id = Identifier::new(3, [0, 0, 7, 0]).unwrap();
        let excess = keychain.commit(5, &id, SwitchCommitment::Regular).unwrap();
        let event = wallet_event(&Event::PaymentPosted(PostedPayment {
            tx_id: TxId(8),
            slate_id,
            excess,
        }))
        .unwrap();
        assert_eq!(event.kind, WalletEventKind::PaymentPosted);
        assert_eq!(event.tx_id, Some(8));
        assert_eq!(event.slate_id, Some(slate_id.to_string()));
        assert_eq!(event.kernel_excess, Some(excess.to_hex()));
        assert_eq!(event.sender, None);
    }

    #[test]
    fn a_received_slate_reaches_the_listener_as_received() {
        let event = listener_event(&received()).unwrap();
        assert_eq!(event.kind, ListenerEventKind::Received);
        assert_eq!(event.tx_id, Some(3));
    }

    #[test]
    fn a_self_send_reaches_the_event_stream_as_its_own_kind_and_never_the_listener() {
        let event = Event::SelfSent(SelfSentTransaction {
            tx_id: TxId(7),
            received_tx_id: TxId(8),
            account: DEFAULT_ACCOUNT,
            amount: Amount::new(50),
        });
        let streamed = wallet_event(&event).unwrap();
        assert_eq!(streamed.kind, WalletEventKind::SelfSend);
        assert_eq!(streamed.tx_id, Some(7));
        assert_eq!(streamed.account, Some(DEFAULT_ACCOUNT.0));
        assert_eq!(streamed.amount, Some(50));
        assert_eq!(streamed.to, None);
        assert!(listener_event(&event).is_none());
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
            .await
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
        let epicbox = sender.epicbox().unwrap();
        let outbound = epicbox.outbound().unwrap();
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

    #[test]
    fn app_sends_carry_a_local_limit_and_file_sends_a_ttl_too() {
        let request = Session::send_request_with(1, 1, None, None).unwrap();
        assert_eq!(request.local_ttl_blocks, Some(APP_TTL_BLOCKS));
        assert_eq!(request.ttl_blocks, None);

        let file = Session::file_send_request(1, 1, None, None).unwrap();
        assert_eq!(file.local_ttl_blocks, Some(APP_TTL_BLOCKS));
        assert_eq!(file.ttl_blocks, Some(APP_TTL_BLOCKS));
        assert_eq!(APP_TTL_BLOCKS, 1_440);
    }
}
