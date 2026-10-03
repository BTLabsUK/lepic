//! Wallet operations. Every operation that is not `sync` runs on the [`LepicRuntime`] and
//! returns a Future in Dart. Each fails only with [`WalletError`]; a panic inside LEPIC arrives
//! as [`WalletErrorKind::Panic`].
//!
//! Secrets follow ADR 0014. Into Rust: the password, PIN and recovery phrase the user types.
//! Out of Rust: the recovery phrase, only from [`EpicWallet::mnemonic`] and
//! [`EpicWallet::mnemonic_with_pin`] after the credential is checked. Seeds, keys, blinding
//! factors, nonces and the generated wallet password of PIN unlock never leave Rust; the app's
//! store and Dart hold only encrypted vaults and sealed text.

use std::path::PathBuf;
use std::sync::Arc;

use flutter_rust_bridge::frb;
use lepic_epicbox::EpicboxAddress;
use lepic_keychain::Seed;
use zeroize::Zeroizing;

use crate::pin;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    Chain, FinalizedTx, InboxReport, ListenerEvent, ListenerEventKind, NodeTip, RefreshProgress,
    ScanProgress, SentTx, Slate, WalletConfig, WalletEvent, WalletSummary,
};
use crate::boundary::{Boundary, guard_or};
use crate::frb_generated::StreamSink;
use crate::node::NodeSecret;
use crate::session::{self, Session, normalize_phrase, relay_network};

/// True when every word is in the English wordlist and the checksum matches. Case and extra
/// whitespace are ignored.
#[frb(sync)]
pub fn validate_mnemonic(phrase: String) -> bool {
    guard_or("validate_mnemonic", false, || {
        let phrase = normalize_phrase(&Zeroizing::new(phrase));
        Seed::from_mnemonic(&phrase).is_ok()
    })
}

/// True for `<address>@<relay>[:port]` whose key is valid and belongs to `chain`.
#[frb(sync)]
pub fn validate_epicbox_address(address: String, chain: Chain) -> bool {
    guard_or("validate_epicbox_address", false, || {
        EpicboxAddress::parse(&address, relay_network(chain.network())).is_ok()
    })
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
/// [`WalletErrorKind::WalletBusy`] while a wallet on that directory is open in any runtime. Only
/// the recovery phrase can bring the wallet back. Also removes the PIN key and failure count.
///
/// It takes no password or PIN on purpose: a user who forgot both deletes the wallet and
/// restores it from the recovery phrase, and whoever can call it can also clear the app's data.
/// Ask the user to confirm in the app.
pub async fn delete_wallet(
    runtime: &LepicRuntime,
    config: WalletConfig,
    store: &AppSecretStore,
) -> Result<(), WalletError> {
    let mut config = config;
    drop(NodeSecret::take(&mut config));
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
    let mut config = config;
    let node_secret = NodeSecret::take(&mut config);
    let inner = Arc::clone(&runtime.inner);
    runtime
        .inner
        .boundary
        .run("node_tip", async move {
            session::node_tip(&inner, &config, &node_secret).await
        })
        .await
}

/// A wallet created by [`EpicWallet::create_with_pin`], and its wallet password sealed under the
/// PIN and the PIN key in the app's store. Store `sealed_password`;
/// [`EpicWallet::open_with_pin`] needs it. With the store's contents it allows guessing the
/// PIN offline, so keep it where the store is, not in backups.
#[frb(non_opaque)]
pub struct PinWallet {
    pub wallet: EpicWallet,
    pub sealed_password: String,
}

/// An open wallet. Dropping it stops its listener and scan and locks it once calls still
/// running on it finish; [`EpicWallet::lock`] locks it at once.
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
    /// generated, whose phrase [`EpicWallet::mnemonic`] returns for the backup screen. Returns
    /// the open wallet.
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
        let mut config = config;
        let node_secret = NodeSecret::take(&mut config);
        let mnemonic = mnemonic.map(Zeroizing::new);
        let password = Zeroizing::new(password);
        let inner = Arc::clone(&runtime.inner);
        let store = store.clone();
        runtime
            .inner
            .boundary
            .run("create", async move {
                let session = Session::new(&inner, &config, &node_secret, store)?;
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
        let mut config = config;
        let node_secret = NodeSecret::take(&mut config);
        let password = Zeroizing::new(password);
        let inner = Arc::clone(&runtime.inner);
        let store = store.clone();
        runtime
            .inner
            .boundary
            .run("open", async move {
                let session = Session::new(&inner, &config, &node_secret, store)?;
                session.open(password).await?;
                Ok(EpicWallet {
                    session: Arc::new(session),
                })
            })
            .await
    }

    /// [`EpicWallet::create`] with a wallet password LEPIC generates, seals under `pin` and
    /// never hands to Dart. The sealed text is bound to a random key LEPIC writes into `store`
    /// as `lepic.pin-key`, so it opens only together with that store.
    ///
    /// Store `sealed_password` before showing the recovery phrase or receiving funds. If the
    /// app stops before storing it, the wallet cannot be opened by PIN; delete it with
    /// [`delete_wallet`] and create it again (a restored wallet from its phrase).
    ///
    /// Fails with `InvalidArgument` when `pin` has fewer than four characters, and otherwise
    /// as `create` does.
    pub async fn create_with_pin(
        runtime: &LepicRuntime,
        config: WalletConfig,
        store: &AppSecretStore,
        mnemonic: Option<String>,
        pin: String,
    ) -> Result<PinWallet, WalletError> {
        let mut config = config;
        let node_secret = NodeSecret::take(&mut config);
        let mnemonic = mnemonic.map(Zeroizing::new);
        let pin = Zeroizing::new(pin);
        let inner = Arc::clone(&runtime.inner);
        let store = store.clone();
        let kdf = inner.kdf;
        runtime
            .inner
            .boundary
            .run("create_with_pin", async move {
                let pin = pin::NewPin::new(pin)?;
                let session = Session::new(&inner, &config, &node_secret, store.clone())?;
                // Checked before the PIN key is written, so it never replaces another
                // wallet's key.
                if session::wallet_exists(&store).await? {
                    return Err(WalletError::new(
                        WalletErrorKind::WalletAlreadyExists,
                        "the app's store holds a wallet",
                    ));
                }
                let password = pin::generate_password()?;
                let sealed_password = pin::seal_new(&store, pin, password.clone(), kdf).await?;
                session.create(mnemonic, password).await?;
                Ok(PinWallet {
                    wallet: EpicWallet {
                        session: Arc::new(session),
                    },
                    sealed_password,
                })
            })
            .await
    }

    /// [`EpicWallet::open`] with the wallet password sealed in `sealed_password`, opened with
    /// `pin` and the PIN key in `store`. Every attempt is counted in `store` as
    /// `lepic.pin-failures` until a right PIN clears it. The first three attempts never wait;
    /// after the third failure each attempt first waits 30 seconds, twice as long after each
    /// further failure, up to an hour. Attempts of one runtime run one at a time.
    ///
    /// A wrong PIN gives `WrongPassword`, damaged text `InvalidArgument`, a store without the
    /// PIN key `SecretStore`.
    pub async fn open_with_pin(
        runtime: &LepicRuntime,
        config: WalletConfig,
        store: &AppSecretStore,
        pin: String,
        sealed_password: String,
    ) -> Result<EpicWallet, WalletError> {
        let mut config = config;
        let node_secret = NodeSecret::take(&mut config);
        let pin = Zeroizing::new(pin);
        let inner = Arc::clone(&runtime.inner);
        let store = store.clone();
        runtime
            .inner
            .boundary
            .run("open_with_pin", async move {
                let session = Session::new(&inner, &config, &node_secret, store.clone())?;
                let password = pin::unlock(&inner.pin, &store, pin, sealed_password).await?;
                session.open(password).await?;
                Ok(EpicWallet {
                    session: Arc::new(session),
                })
            })
            .await
    }

    /// The recovery phrase, after checking `password` against the stored vault.
    pub async fn mnemonic(&self, password: String) -> Result<String, WalletError> {
        let password = Zeroizing::new(password);
        self.run("mnemonic", |session| async move {
            session.recovery_phrase(password).await
        })
        .await
    }

    /// [`EpicWallet::mnemonic`] for a wallet from [`EpicWallet::create_with_pin`]: `pin` opens
    /// `sealed_password`, which is then checked against the stored vault. PIN attempts are
    /// counted and delayed as in [`EpicWallet::open_with_pin`].
    pub async fn mnemonic_with_pin(
        &self,
        pin: String,
        sealed_password: String,
    ) -> Result<String, WalletError> {
        let pin = Zeroizing::new(pin);
        self.run("mnemonic_with_pin", |session| async move {
            // A locked wallet refuses before the attempt is counted.
            session.ensure_unlocked()?;
            let password = pin::unlock(
                &session.runtime().pin,
                session.store(),
                pin,
                sealed_password,
            )
            .await?;
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

    /// Locks the wallet now, for example when the app goes to the background: stops the
    /// listener and any scan and wipes the root key. Every later call on this handle fails with
    /// `Locked`; calls already running finish first. To use the wallet again, drop this handle
    /// and open the wallet anew. Locking a locked wallet does nothing.
    #[frb(sync)]
    pub fn lock(&self) {
        self.boundary().guard_or("lock", (), || self.session.lock());
    }

    /// Stops a running scan at its next page.
    #[frb(sync)]
    pub fn cancel_scan(&self) {
        self.boundary()
            .guard_or("cancel_scan", (), || self.session.cancel_scan());
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
        let boundary = self.boundary();
        let Some(handle) = boundary.guard("start_listener", || self.session.claim_listener())?
        else {
            return Ok(());
        };
        let session = Arc::clone(&self.session);
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
        self.boundary()
            .guard_or("stop_listener", (), || self.session.stop_listener());
    }

    #[frb(sync)]
    pub fn listener_running(&self) -> bool {
        self.boundary().guard_or("listener_running", false, || {
            self.session.listener_running()
        })
    }

    /// Everything the wallet reports from now on: session, balance, transaction, sync and
    /// transport changes. The stream ends when the wallet is dropped.
    pub fn events(&self, sink: StreamSink<WalletEvent>) {
        let boundary = self.boundary();
        boundary.guard_or("events", (), || {
            let events = self.session.subscribe();
            boundary.handle.spawn(session::forward_events(events, sink));
        });
    }
}
