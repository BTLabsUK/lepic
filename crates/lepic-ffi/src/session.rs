//! One open wallet: the engine over the binding's ports, and the glue between engine calls,
//! the app's secret store and Dart streams.

use std::path::{Path, PathBuf};
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
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, TxId, TxState};
use lepic_transport::file::{FILE, FileTransport, response_path};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Exchange as _, Location};
use lepic_wallet::event::{Balance, TransportState as EngineTransportState};
use lepic_wallet::inbox::ListenHandle;
use lepic_wallet::refresh::{BALANCE_MINIMUM_CONFIRMATIONS, RefreshOutcome};
use lepic_wallet::scan::{ScanCancel, ScanOptions, ScanStart};
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
    FinalizedTx, InboxReport, ListenerEvent, ListenerEventKind, NodeTip, ScanProgress, SentTx,
    Slate, TransportState, WalletConfig, WalletEvent, WalletEventKind, WalletSummary,
};
use crate::frb_generated::StreamSink;
use crate::node::{Node, node_error};
use crate::vault_port::{AppVault, SharedStorage, VAULT_KEY, VaultBytes, vault_error};

type EngineWallet = Wallet<Node, SqliteStores, AppVault>;

/// Matches the name `lepic-wallet` stores the seed under in the wallet's vault.
const SEED_SECRET: &str = "wallet/seed";

/// The name of the wallet in logs. The binding opens one wallet per data directory.
const WALLET_NAME: &str = "default";

const DEFAULT_ACCOUNT: AccountIndex = AccountIndex(0);

/// The longest slate text the file method imports (`lepic_slate::codec::MAX_WIRE_SLATE_LEN`),
/// checked before the text is written to a scratch file.
const MAX_SLATE_TEXT_LEN: usize = 8 * 1024 * 1024;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
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
    scan: Mutex<Option<ScanCancel>>,
    balance: Mutex<Option<Balance>>,
    claim: DirClaim,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(listener) = lock(&self.listener).take() {
            listener.stop();
        }
        if let Some(scan) = lock(&self.scan).take() {
            scan.cancel();
        }
        if let Some(epicbox) = &self.epicbox {
            epicbox.detach();
        }
        self.engine.lock();
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

fn epicbox_transport(
    config: &WalletConfig,
    network: Network,
) -> Result<Option<EpicboxTransport>, WalletError> {
    if config.epicbox_domain.is_empty() {
        return Ok(None);
    }
    let domain = Domain::parse(&config.epicbox_domain)
        .map_err(|_| invalid("epicbox domain is not a host name"))?;
    let endpoint = RelayEndpoint::new(domain, Some(config.epicbox_port), Security::Tls);
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
        config: &mut WalletConfig,
        store: AppSecretStore,
    ) -> Result<Self, WalletError> {
        let network = config.chain.network();
        let data_dir = PathBuf::from(&config.data_dir);
        let claim = runtime.claim(&data_dir)?;
        let node = runtime.nodes.client(config)?;
        let epicbox = epicbox_transport(config, network)?;
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

    /// Creates the wallet: from `phrase` when given, from new entropy otherwise.
    pub(crate) async fn create(
        &self,
        phrase: Option<Zeroizing<String>>,
        password: Zeroizing<String>,
    ) -> Result<(), WalletError> {
        self.vault.load(&self.store).await?;
        let password = self::password(password);
        match phrase {
            Some(phrase) => {
                let phrase = normalize_phrase(&phrase);
                self.engine.restore(password, &phrase).await?;
            }
            // The phrase is shown later through `recovery_phrase`, after the user set up a PIN.
            None => drop(self.engine.create(password, WordCount::TwentyFour).await?),
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
        Ok(())
    }

    /// The recovery phrase, after checking `password` against the stored vault.
    pub(crate) async fn recovery_phrase(
        &self,
        password: Zeroizing<String>,
    ) -> Result<String, WalletError> {
        let bytes = VaultBytes::default();
        bytes.load(&self.store).await?;
        let password = self::password(password);
        let phrase = tokio::task::spawn_blocking(move || {
            let vault = Vault::open(
                SharedStorage::new(bytes),
                os_rng()?,
                password.expose_bytes(),
            )
            .map_err(|error| {
                WalletError::from(lepic_wallet::WalletError::from(vault_error(error)))
            })?;
            let name = SecretName::new(SEED_SECRET).map_err(|error| invalid(error.to_string()))?;
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
        .await
        .map_err(|_| {
            WalletError::new(
                WalletErrorKind::Panic,
                "recovery phrase failed inside lepic",
            )
        })??;
        Ok(phrase.as_str().to_owned())
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
        lock(&self.balance)
            .as_ref()
            .map(|balance| summary(balance, false))
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

    fn send_request(amount: u64, minimum_confirmations: u64) -> SendRequest {
        SendRequest {
            minimum_confirmations,
            ..SendRequest::new(DEFAULT_ACCOUNT, Amount::new(amount))
        }
    }

    pub(crate) async fn send_file(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        path: PathBuf,
    ) -> Result<SentTx, WalletError> {
        let sent = self
            .engine
            .send(
                Self::send_request(amount, minimum_confirmations),
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
    ) -> Result<Slate, WalletError> {
        let scratch = ScratchFile::new(&self.data_dir)?;
        let sent = self
            .send_file(amount, minimum_confirmations, scratch.path.clone())
            .await?;
        let json = scratch.read().await?;
        Ok(Slate {
            tx_id: sent.tx_id,
            slate_id: sent.slate_id,
            json,
        })
    }

    /// Signs the S1 in the file at `path`. Returns the reply, also written next to the file as
    /// `epic-wallet` names it, when `write_response` is set.
    pub(crate) async fn receive_file(
        &self,
        path: &Path,
        write_response: bool,
    ) -> Result<Slate, WalletError> {
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
        Ok(Slate {
            tx_id: received.tx_id.0,
            slate_id: received.slate.id().to_string(),
            json,
        })
    }

    pub(crate) async fn receive_slate(&self, json: String) -> Result<Slate, WalletError> {
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
        Ok(self.engine.post(TxId(tx_id), Propagation::Fluff).await?)
    }

    pub(crate) async fn cancel(&self, tx_id: u32) -> Result<(), WalletError> {
        Ok(self.engine.cancel(TxId(tx_id)).await?)
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
    ) -> Result<SentTx, WalletError> {
        let epicbox = self.epicbox()?;
        EpicboxAddress::parse(&address, relay_network(self.network))
            .map_err(|_| invalid("not an epicbox address of this network"))?;
        self.engine.epicbox_attach(epicbox)?;
        let sent = self
            .engine
            .send(
                Self::send_request(amount, minimum_confirmations),
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

    /// Runs the listener until `handle` is stopped, forwarding what it does to `sink`.
    pub(crate) async fn listen(
        &self,
        handle: &ListenHandle,
        sink: &StreamSink<ListenerEvent>,
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
                            let _ = sink.add(event);
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
        _ => return None,
    })
}

fn listener_event(event: &Event) -> Option<ListenerEvent> {
    let (kind, tx_id) = match event {
        Event::Transport(status) if status.transport == TRANSPORT_ID => {
            match transport_state(status.state) {
                TransportState::Connected => (ListenerEventKind::Connected, None),
                TransportState::Disconnected => (ListenerEventKind::Disconnected, None),
                TransportState::Connecting | TransportState::Stopped => return None,
            }
        }
        Event::Transaction(change) => match change.to {
            TxState::Received => (ListenerEventKind::Received, Some(change.tx_id.0)),
            TxState::Finalized => (ListenerEventKind::Finalized, Some(change.tx_id.0)),
            _ => return None,
        },
        _ => return None,
    };
    Some(ListenerEvent {
        kind,
        tx_id,
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
    config: &mut WalletConfig,
) -> Result<NodeTip, WalletError> {
    let node = runtime.nodes.client(config)?;
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

/// Deletes the wallet database in `config.data_dir` and the vault in `store`.
pub(crate) async fn delete_wallet(
    runtime: &Arc<RuntimeInner>,
    config: &WalletConfig,
    store: &AppSecretStore,
) -> Result<(), WalletError> {
    let claim = runtime.claim(Path::new(&config.data_dir))?;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = claim.dir.join(format!("{DATABASE_FILE}{suffix}"));
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io("deleting the wallet database", &error)),
        }
    }
    store.delete(VAULT_KEY).await?;
    crate::pin::forget(store).await?;
    info!("wallet deleted");
    Ok(())
}
