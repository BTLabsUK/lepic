//! Wallet operations. Every operation that is not `sync` runs on the [`LepicRuntime`] and
//! returns a Future in Dart. Each fails only with [`WalletError`]; a panic inside LEPIC arrives
//! as [`WalletErrorKind::Panic`].
//!
//! Secrets: passwords and recovery phrases cross from Dart because the user types them, and
//! [`EpicWallet::mnemonic`] returns the phrase for the backup screen. Seeds, keys, blinding
//! factors and nonces never leave Rust; the app's store only ever holds the encrypted vault.

use std::path::PathBuf;
use std::sync::Arc;

use flutter_rust_bridge::frb;
use lepic_epicbox::EpicboxAddress;
use lepic_keychain::Seed;
use zeroize::Zeroizing;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    Chain, FinalizedTx, InboxReport, ListenerEvent, ListenerEventKind, NodeTip, RefreshProgress,
    ScanProgress, SentTx, Slate, WalletConfig, WalletEvent, WalletSummary,
};
use crate::boundary::{Boundary, guard};
use crate::frb_generated::StreamSink;
use crate::session::{self, Session, normalize_phrase, relay_network};

/// A new BIP-39 recovery phrase. `word_count` is 12, 15, 18, 21 or 24.
#[frb(sync)]
pub fn generate_mnemonic(word_count: u32) -> Result<String, WalletError> {
    guard("generate_mnemonic", || {
        let entropy_len = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => {
                return Err(WalletError::new(
                    WalletErrorKind::InvalidArgument,
                    "word count must be 12, 15, 18, 21 or 24",
                ));
            }
        };
        let mut entropy = Zeroizing::new([0u8; 32]);
        let used = entropy.get_mut(..entropy_len).ok_or_else(|| {
            WalletError::new(WalletErrorKind::Other, "entropy length out of range")
        })?;
        getrandom::fill(used)
            .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
        let seed = Seed::from_entropy(used)
            .map_err(|_| WalletError::new(WalletErrorKind::Other, "seed rejected"))?;
        let phrase = seed
            .to_mnemonic()
            .map_err(|_| WalletError::new(WalletErrorKind::Other, "phrase not encoded"))?;
        Ok(phrase.as_str().to_owned())
    })
}

/// True when every word is in the English wordlist and the checksum matches. Case and extra
/// whitespace are ignored.
#[frb(sync)]
pub fn validate_mnemonic(phrase: String) -> bool {
    let phrase = Zeroizing::new(normalize_phrase(&phrase));
    Seed::from_mnemonic(&phrase).is_ok()
}

/// True for `<address>@<relay>[:port]` whose key is valid and belongs to `chain`.
#[frb(sync)]
pub fn validate_epicbox_address(address: String, chain: Chain) -> bool {
    EpicboxAddress::parse(&address, relay_network(chain.network())).is_ok()
}

/// True when `store` holds a wallet vault.
pub async fn wallet_exists(
    runtime: &LepicRuntime,
    store: &AppSecretStore,
) -> Result<bool, WalletError> {
    let store = store.clone();
    runtime
        .inner
        .boundary
        .run("wallet_exists", async move {
            session::wallet_exists(&store).await
        })
        .await
}

/// Deletes the wallet database in `config.data_dir` and the vault in `store`. Fails with
/// [`WalletErrorKind::WalletBusy`] while a wallet on that directory is open in `runtime`. Only
/// the recovery phrase can bring the wallet back.
pub async fn delete_wallet(
    runtime: &LepicRuntime,
    config: WalletConfig,
    store: &AppSecretStore,
) -> Result<(), WalletError> {
    let inner = Arc::clone(&runtime.inner);
    let store = store.clone();
    runtime
        .inner
        .boundary
        .run("delete_wallet", async move {
            session::delete_wallet(&inner, &config, &store).await
        })
        .await
}

/// The configured node's tip, without opening a wallet.
pub async fn node_tip(
    runtime: &LepicRuntime,
    config: WalletConfig,
) -> Result<NodeTip, WalletError> {
    let inner = Arc::clone(&runtime.inner);
    runtime
        .inner
        .boundary
        .run("node_tip", async move {
            session::node_tip(&inner, &config).await
        })
        .await
}

/// An open wallet. Dropping it stops its listener and scan and locks it; the root key is wiped.
#[frb(opaque)]
pub struct EpicWallet {
    session: Arc<Session>,
}

impl Drop for EpicWallet {
    fn drop(&mut self) {
        self.session.stop_listener();
        self.session.cancel_scan();
    }
}

impl EpicWallet {
    fn boundary(&self) -> Boundary {
        self.session.runtime().boundary.clone()
    }

    async fn run<T, F, Fut>(&self, operation: &'static str, work: F) -> Result<T, WalletError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Session>) -> Fut,
        Fut: Future<Output = Result<T, WalletError>> + Send + 'static,
    {
        let session = Arc::clone(&self.session);
        self.boundary().run(operation, work(session)).await
    }

    /// Creates a wallet in `config.data_dir` with its vault in `store`. With `mnemonic` it
    /// restores that seed (call [`EpicWallet::scan`] next); without it a fresh seed is
    /// generated, whose phrase [`EpicWallet::mnemonic`] returns. Returns the open wallet.
    ///
    /// Fails with `WalletAlreadyExists` when `store` holds a vault, `InvalidMnemonic`,
    /// `ForeignWallet` when the directory holds another wallet's database, `WalletBusy` when a
    /// wallet on the directory is open, and `SecretStore` when the vault could not be written.
    pub async fn create(
        runtime: &LepicRuntime,
        config: WalletConfig,
        store: &AppSecretStore,
        mnemonic: Option<String>,
        password: String,
    ) -> Result<EpicWallet, WalletError> {
        let inner = Arc::clone(&runtime.inner);
        let store = store.clone();
        runtime
            .inner
            .boundary
            .run("create", async move {
                let session = Session::new(&inner, &config, store)?;
                session.create(mnemonic, password).await?;
                Ok(EpicWallet {
                    session: Arc::new(session),
                })
            })
            .await
    }

    /// Opens the wallet in `config.data_dir`. Fails with `WrongPassword`, `WalletNotFound` when
    /// `store` holds no vault, `ForeignWallet` and `WalletBusy`.
    pub async fn open(
        runtime: &LepicRuntime,
        config: WalletConfig,
        store: &AppSecretStore,
        password: String,
    ) -> Result<EpicWallet, WalletError> {
        let inner = Arc::clone(&runtime.inner);
        let store = store.clone();
        runtime
            .inner
            .boundary
            .run("open", async move {
                let session = Session::new(&inner, &config, store)?;
                session.open(password).await?;
                Ok(EpicWallet {
                    session: Arc::new(session),
                })
            })
            .await
    }

    /// The recovery phrase, after checking `password` against the stored vault.
    pub async fn mnemonic(&self, password: String) -> Result<String, WalletError> {
        self.run("mnemonic", |session| async move {
            session.recovery_phrase(password).await
        })
        .await
    }

    /// The default account's balance. With `refresh`, or before the first refresh of this
    /// handle, it first updates outputs and transactions from the node.
    pub async fn summary(&self, refresh: bool) -> Result<WalletSummary, WalletError> {
        self.run("summary", |session| async move {
            match session.cached() {
                Some(cached) if !refresh => Ok(cached),
                _ => session.refresh().await,
            }
        })
        .await
    }

    /// `summary(refresh: true)` as a stream: a first event at 0 percent, then one with
    /// `summary` set at 100. A failure ends the stream with the error.
    pub async fn refresh(&self, progress: StreamSink<RefreshProgress>) -> Result<(), WalletError> {
        self.run("refresh", |session| async move {
            let _ = progress.add(RefreshProgress {
                percent: 0,
                message: "checking your funds".to_owned(),
                summary: None,
            });
            let summary = session.refresh().await?;
            let _ = progress.add(RefreshProgress {
                percent: 100,
                message: "up to date".to_owned(),
                summary: Some(summary),
            });
            Ok(())
        })
        .await
    }

    /// Scans the chain for this wallet's outputs from `start_height`, or, by default, from
    /// shortly before the last completed scan (the whole chain after a restore), streaming
    /// progress until an event with `finished`. A cancelled scan fails with `Cancelled` and
    /// resumes where it stopped next time.
    pub async fn scan(
        &self,
        start_height: Option<u64>,
        progress: StreamSink<ScanProgress>,
    ) -> Result<(), WalletError> {
        self.run("scan", |session| async move {
            session.scan(start_height, &progress).await
        })
        .await
    }

    /// Stops a running scan at its next page.
    #[frb(sync)]
    pub fn cancel_scan(&self) {
        self.session.cancel_scan();
    }

    /// Step 1 of a manual send: builds the slate, locks the inputs and returns the slate text
    /// for the recipient, whose answer goes to [`EpicWallet::finalize_and_post`].
    pub async fn create_send_slate(
        &self,
        amount: u64,
        minimum_confirmations: u64,
    ) -> Result<Slate, WalletError> {
        self.run("create_send_slate", |session| async move {
            session
                .create_send_slate(amount, minimum_confirmations)
                .await
        })
        .await
    }

    /// [`EpicWallet::create_send_slate`] writing the slate to the file at `path`.
    pub async fn send_file(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        path: String,
    ) -> Result<SentTx, WalletError> {
        self.run("send_file", |session| async move {
            session
                .send_file(amount, minimum_confirmations, PathBuf::from(path))
                .await
        })
        .await
    }

    /// Recipient side: signs an incoming send and returns the answer for the sender.
    pub async fn receive_slate(&self, slate_json: String) -> Result<Slate, WalletError> {
        self.run("receive_slate", |session| async move {
            session.receive_slate(slate_json).await
        })
        .await
    }

    /// [`EpicWallet::receive_slate`] for the slate file at `path`. The answer is also written to
    /// `<path>.response`, as `epic-wallet` names it.
    pub async fn receive_file(&self, path: String) -> Result<Slate, WalletError> {
        self.run("receive_file", |session| async move {
            session.receive_file(&PathBuf::from(path), true).await
        })
        .await
    }

    /// Sender side: finalizes the recipient's answer and posts the transaction to the node.
    /// Fails with `NotPosted` when it was finalized but the node did not accept it; post it
    /// again with [`EpicWallet::repost_transaction`].
    pub async fn finalize_and_post(&self, slate_json: String) -> Result<FinalizedTx, WalletError> {
        self.run("finalize_and_post", |session| async move {
            session.finalize_slate(slate_json).await
        })
        .await
    }

    /// [`EpicWallet::finalize_and_post`] for the answer file at `path`.
    pub async fn finalize_file(&self, path: String) -> Result<FinalizedTx, WalletError> {
        self.run("finalize_file", |session| async move {
            session.finalize_file(&PathBuf::from(path)).await
        })
        .await
    }

    /// Posts the stored final transaction of `tx_id` to the node again.
    pub async fn repost_transaction(&self, tx_id: u32) -> Result<(), WalletError> {
        self.run("repost_transaction", |session| async move {
            session.repost(tx_id).await
        })
        .await
    }

    /// Cancels a transaction that was not posted and unlocks its outputs.
    pub async fn cancel_transaction(&self, tx_id: u32) -> Result<(), WalletError> {
        self.run("cancel_transaction", |session| async move {
            session.cancel(tx_id).await
        })
        .await
    }

    /// The wallet's Epicbox address, `<key>@<domain>[:port]`. Fails with `Unsupported` when
    /// the configuration names no relay.
    pub async fn epicbox_address(&self) -> Result<String, WalletError> {
        self.run("epicbox_address", |session| async move {
            session.epicbox_address()
        })
        .await
    }

    /// Sends to `<address>@<relay>[:port]` over Epicbox. The listener or a drain finalizes and
    /// posts it when the answer arrives.
    pub async fn send_epicbox(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        address: String,
    ) -> Result<SentTx, WalletError> {
        self.run("send_epicbox", |session| async move {
            session
                .send_epicbox(amount, minimum_confirmations, address)
                .await
        })
        .await
    }

    /// Connects to the relay once, handles every pending message and disconnects: the call for
    /// background work.
    pub async fn drain_epicbox(&self) -> Result<InboxReport, WalletError> {
        self.run("drain_epicbox", |session| async move {
            session.drain_epicbox().await
        })
        .await
    }

    /// Starts the Epicbox listener, unless it runs already, and streams what it does until
    /// [`EpicWallet::stop_listener`]. The last event is `Stopped`.
    pub async fn start_listener(
        &self,
        events: StreamSink<ListenerEvent>,
    ) -> Result<(), WalletError> {
        let Some(handle) = self.session.claim_listener()? else {
            return Ok(());
        };
        let session = Arc::clone(&self.session);
        let boundary = self.boundary();
        let runner = boundary.clone();
        boundary.handle.spawn(async move {
            let sink = events.clone();
            let listening = runner
                .run(
                    "listen",
                    async move { session.listen(&handle, &sink).await },
                )
                .await;
            if let Err(error) = listening {
                let _ = events.add(ListenerEvent {
                    kind: ListenerEventKind::Error,
                    tx_id: None,
                    message: error.to_string(),
                });
            }
            let _ = events.add(ListenerEvent {
                kind: ListenerEventKind::Stopped,
                tx_id: None,
                message: String::new(),
            });
        });
        Ok(())
    }

    /// Stops the listener. Its stream ends with `Stopped` shortly after.
    #[frb(sync)]
    pub fn stop_listener(&self) {
        self.session.stop_listener();
    }

    #[frb(sync)]
    pub fn listener_running(&self) -> bool {
        self.session.listener_running()
    }

    /// Everything the wallet reports from now on: session, balance, transaction, sync and
    /// transport changes. The stream ends when the wallet is dropped.
    pub fn events(&self, sink: StreamSink<WalletEvent>) {
        let events = self.session.subscribe();
        self.boundary()
            .handle
            .spawn(session::forward_events(events, sink));
    }
}
