//! Wallet operations. Every operation that is not `sync` runs on the [`LepicRuntime`] and
//! returns a Future in Dart. Each fails only with [`WalletError`]; a panic inside LEPIC arrives
//! as [`WalletErrorKind::Panic`].
//!
//! Secrets follow ADR 0014. Into Rust: the password, PIN and recovery phrase the user types, the
//! password of a `wallet.seed` file the user imports, and the node API secret in
//! [`WalletConfig`]. Out of Rust: the recovery phrase, only from
//! [`EpicWallet::mnemonic`] and [`EpicWallet::mnemonic_with_pin`] after the credential is
//! checked, and the PIN key, only to the app's store. Seeds, keys, blinding factors, nonces and
//! the generated wallet password of PIN unlock never leave Rust; Dart holds only encrypted
//! vaults and sealed text.

use std::path::PathBuf;
use std::sync::Arc;

use flutter_rust_bridge::frb;
use lepic_keychain::Seed;
use lepic_wallet::Password;
use lepic_wallet::selection::{SelfSendShape, SplitCount};
use zeroize::Zeroizing;

use crate::inspect;
use crate::pin;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{
    Chain, FeeEstimate, FinalizedTx, InboxReport, LegacyImport, ListenerEvent, ListenerEventKind,
    NodeTip, PushSignature, ReceivedSlate, RefreshProgress, ScanProgress, SelfSentTx, SendOptions,
    SentTx, Slate, SlateInfo, TransactionDetails, WalletConfig, WalletEvent, WalletOutput,
    WalletSummary,
};
use crate::boundary::{Boundary, end_stream, guard, guard_or};
use crate::frb_generated::StreamSink;
use crate::node::NodeSecret;
use crate::session::{self, SeedOrigin, Session, normalize_phrase};

/// True when every word is in the English wordlist and the checksum matches. Case and extra
/// whitespace are ignored.
#[frb(sync)]
pub fn validate_mnemonic(phrase: String) -> bool {
    guard_or("validate_mnemonic", false, || {
        let phrase = normalize_phrase(&Zeroizing::new(phrase));
        Seed::from_mnemonic(&phrase).is_ok()
    })
}

/// True for `<address>@<relay>[:port]` whose key is valid and belongs to `chain`. A key without
/// `@<relay>` is refused: Epicbox would send it to a default relay the user never named.
#[frb(sync)]
pub fn validate_epicbox_address(address: String, chain: Chain) -> bool {
    guard_or("validate_epicbox_address", false, || {
        session::relay_address(&address, chain.network()).is_some()
    })
}

/// What the V2 or V3 slate text `json` says, read as [`EpicWallet::receive_slate`] and
/// [`EpicWallet::finalize_and_post`] read it, without a wallet and without checking signatures.
/// `chain` sets the minimum fee a slate must pay. Fails with `InvalidSlate`.
pub fn inspect_slate(json: String, chain: Chain) -> Result<SlateInfo, WalletError> {
    guard("inspect_slate", || inspect::inspect(json, chain.network()))
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

/// The configured node's tip, version, readiness and tip block time, without opening a
/// wallet. Fails with `NodeUnreachable` when the tip or version cannot be had; readiness and
/// the block time are `None` when only they fail.
///
/// No wallet is open, so the request always goes directly, never through tor. While a wallet
/// is open, use [`EpicWallet::node_tip_for`], which follows the wallet's tor.
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

/// A split into `outputs` outputs: refused with `InvalidArgument` outside 2..=10.
fn split_shape(outputs: u32) -> Result<SelfSendShape, WalletError> {
    usize::try_from(outputs)
        .ok()
        .and_then(SplitCount::new)
        .map(SelfSendShape::Split)
        .ok_or_else(|| {
            WalletError::new(
                WalletErrorKind::InvalidArgument,
                format!(
                    "a split makes from {} to {} outputs",
                    SplitCount::MIN,
                    SplitCount::MAX
                ),
            )
        })
}

/// `password` as the password of a new wallet: refused with `InvalidArgument` below
/// [`Password::MIN_NEW_LEN`] characters.
fn new_password(password: Zeroizing<String>) -> Result<Zeroizing<String>, WalletError> {
    if Password::is_long_enough_to_set(&password) {
        Ok(password)
    } else {
        Err(WalletError::new(
            WalletErrorKind::InvalidArgument,
            format!(
                "password has fewer than {} characters",
                Password::MIN_NEW_LEN
            ),
        ))
    }
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
    pub(super) session: Arc<Session>,
}

/// Creates a wallet from `origin` whose generated password is sealed under `pin`.
async fn create_pin_wallet(
    runtime: &LepicRuntime,
    config: WalletConfig,
    store: &AppSecretStore,
    origin: SeedOrigin,
    pin: String,
    operation: &'static str,
) -> Result<PinWallet, WalletError> {
    let mut config = config;
    let node_secret = NodeSecret::take(&mut config);
    let pin = Zeroizing::new(pin);
    let inner = Arc::clone(&runtime.inner);
    let store = store.clone();
    let kdf = inner.kdf;
    runtime
        .inner
        .boundary
        .run(operation, async move {
            let pin = pin::NewPin::new(pin)?;
            let session = Session::new(&inner, &config, &node_secret, store.clone()).await?;
            // Checked before the PIN key is written, so it never replaces another wallet's
            // key.
            if session::wallet_exists(&store).await? {
                return Err(WalletError::new(
                    WalletErrorKind::WalletAlreadyExists,
                    "the app's store holds a wallet",
                ));
            }
            let password = pin::generate_password()?;
            let sealed_password = pin::seal_new(&store, pin, password.clone(), kdf).await?;
            session.create(origin, password).await?;
            Ok(PinWallet {
                wallet: EpicWallet {
                    session: Arc::new(session),
                },
                sealed_password,
            })
        })
        .await
}

impl Drop for EpicWallet {
    fn drop(&mut self) {
        self.session.stop_listener();
        // Tor stops before the listeners it forwards to.
        self.session.stop_tor();
        self.session.stop_http_listener();
        self.session.cancel_scan();
    }
}

impl EpicWallet {
    #[cfg(test)]
    pub(crate) const fn of_session(session: Arc<Session>) -> Self {
        Self { session }
    }

    #[cfg(test)]
    pub(crate) fn session(&self) -> &Arc<Session> {
        &self.session
    }

    pub(super) fn boundary(&self) -> Boundary {
        self.session.runtime().boundary.clone()
    }

    pub(super) async fn run<T, F, Fut>(
        &self,
        operation: &'static str,
        work: F,
    ) -> Result<T, WalletError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<Session>) -> Fut,
        Fut: Future<Output = Result<T, WalletError>> + Send + 'static,
    {
        let session = Arc::clone(&self.session);
        let in_flight = Arc::clone(&self.session.in_flight);
        let gate = Arc::clone(&self.session);
        let work = work(session);
        self.boundary()
            .run_tracked(
                operation,
                async move {
                    // A server switch waiting or under way goes first.
                    let _servers = gate.servers.read().await;
                    work.await
                },
                &in_flight,
            )
            .await
    }

    /// [`EpicWallet::run`] for a call [`EpicWallet::lock`] ends in its own way, so it is not
    /// cut off before it reports that it stopped.
    pub(super) async fn run_until_stopped<T, F, Fut>(
        &self,
        operation: &'static str,
        work: F,
    ) -> Result<T, WalletError>
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
    /// Fails with `InvalidArgument` when `password` has fewer than eight characters, before
    /// anything is written, `WalletAlreadyExists` when `store` holds a vault, `InvalidMnemonic`,
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
                let password = new_password(password)?;
                let session = Session::new(&inner, &config, &node_secret, store).await?;
                session
                    .create(SeedOrigin::phrase(mnemonic), password)
                    .await?;
                Ok(EpicWallet {
                    session: Arc::new(session),
                })
            })
            .await
    }

    /// [`EpicWallet::create`] from an `epic-wallet` `wallet.seed` instead of a phrase:
    /// `seed_file` is the file's text and `seed_password` the password it was written with.
    /// The wallet gets `password`, as `create` does; call [`EpicWallet::scan`] next. The file
    /// is only read; LEPIC keeps no copy of it.
    ///
    /// Fails with `WrongPassword` when `seed_password` does not decrypt the file,
    /// `InvalidArgument` when the text is not a `wallet.seed` (at most 4096 bytes), and
    /// otherwise as `create` does.
    pub async fn import_wallet_seed(
        runtime: &LepicRuntime,
        config: WalletConfig,
        store: &AppSecretStore,
        seed_file: String,
        seed_password: String,
        password: String,
    ) -> Result<EpicWallet, WalletError> {
        let mut config = config;
        let node_secret = NodeSecret::take(&mut config);
        let origin = SeedOrigin::SeedFile {
            text: seed_file,
            password: Zeroizing::new(seed_password),
        };
        let password = Zeroizing::new(password);
        let inner = Arc::clone(&runtime.inner);
        let store = store.clone();
        runtime
            .inner
            .boundary
            .run("import_wallet_seed", async move {
                let password = new_password(password)?;
                let session = Session::new(&inner, &config, &node_secret, store).await?;
                session.create(origin, password).await?;
                Ok(EpicWallet {
                    session: Arc::new(session),
                })
            })
            .await
    }

    /// Opens the wallet in `config.data_dir`. Any password that opens the vault opens it, also
    /// one shorter than `create` accepts today. Fails with `WrongPassword`, `WalletNotFound`
    /// when `store` holds no vault, `ForeignWallet` and `WalletBusy`, and with
    /// `DamagedDatabase` when the database was damaged and has just been set aside: open again
    /// to rebuild it, then `scan`.
    ///
    /// Every attempt is counted in `store` as `lepic.pin-failures`, and waits, as
    /// [`EpicWallet::open_with_pin`] describes; a right password clears the count. Attempts of
    /// one runtime run one at a time.
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
                let session = Session::new(&inner, &config, &node_secret, store.clone()).await?;
                pin::password_attempt(&inner.pin, &store, || session.open(password)).await?;
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
    /// Fails with `InvalidArgument` when `pin` has fewer than six characters, and otherwise
    /// as `create` does.
    pub async fn create_with_pin(
        runtime: &LepicRuntime,
        config: WalletConfig,
        store: &AppSecretStore,
        mnemonic: Option<String>,
        pin: String,
    ) -> Result<PinWallet, WalletError> {
        let origin = SeedOrigin::phrase(mnemonic.map(Zeroizing::new));
        create_pin_wallet(runtime, config, store, origin, pin, "create_with_pin").await
    }

    /// [`EpicWallet::import_wallet_seed`] with a wallet password LEPIC generates and seals
    /// under `pin`, as [`EpicWallet::create_with_pin`] does; store `sealed_password` as it
    /// says. Fails as `import_wallet_seed` and `create_with_pin` do.
    pub async fn import_wallet_seed_with_pin(
        runtime: &LepicRuntime,
        config: WalletConfig,
        store: &AppSecretStore,
        seed_file: String,
        seed_password: String,
        pin: String,
    ) -> Result<PinWallet, WalletError> {
        let origin = SeedOrigin::SeedFile {
            text: seed_file,
            password: Zeroizing::new(seed_password),
        };
        create_pin_wallet(
            runtime,
            config,
            store,
            origin,
            pin,
            "import_wallet_seed_with_pin",
        )
        .await
    }

    /// [`EpicWallet::open`] with the wallet password sealed in `sealed_password`, opened with
    /// `pin` and the PIN key in `store`. Every attempt is counted in `store` as
    /// `lepic.pin-failures` until a right PIN clears it. The first three attempts never wait;
    /// after the third failure each attempt first waits 30 seconds, twice as long after each
    /// further failure, up to an hour. Attempts of one runtime run one at a time.
    ///
    /// A wrong PIN gives `WrongPassword`, damaged text `InvalidArgument`, a store without the
    /// PIN key `SecretStore`; otherwise it fails as [`EpicWallet::open`] does.
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
                let session = Session::new(&inner, &config, &node_secret, store.clone()).await?;
                let password = pin::unlock(&inner.pin, &store, pin, sealed_password).await?;
                session.open(password).await?;
                Ok(EpicWallet {
                    session: Arc::new(session),
                })
            })
            .await
    }

    /// The recovery phrase, after checking `password` against the stored vault. Attempts are
    /// counted and delayed as in [`EpicWallet::open`].
    pub async fn mnemonic(&self, password: String) -> Result<String, WalletError> {
        let password = Zeroizing::new(password);
        self.run("mnemonic", |session| async move {
            // A locked wallet refuses before the attempt is counted.
            session.ensure_unlocked()?;
            pin::password_attempt(&session.runtime().pin, session.store(), || {
                session.recovery_phrase(password)
            })
            .await
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

    /// Changes the PIN of a wallet from [`EpicWallet::create_with_pin`] and returns the new
    /// sealed text, for the same wallet password under `new_pin` and a new PIN key. `old_pin`
    /// must open `sealed_password`; that attempt is counted and delayed as in
    /// [`EpicWallet::open_with_pin`].
    ///
    /// The change is pending until [`EpicWallet::confirm_pin_change`]: the new key is kept as
    /// `lepic.pin-key-pending` beside `lepic.pin-key`, and both the old PIN with the old sealed
    /// text and the new PIN with the new text open the wallet, also in a later runtime. Store
    /// the new text, then confirm. If the app stops before it stored the text, the old pair
    /// still opens.
    ///
    /// A second change before confirmation keeps the pair it started from opening, since that
    /// is the pair the app holds. From the old pair it replaces the pending key, and the text of
    /// the first change stops opening. From the pending pair it makes that pair current, and
    /// the old text stops opening. While a change is pending a wrong PIN costs two key
    /// derivations, and still counts as one failure.
    ///
    /// Fails with `InvalidArgument` when `new_pin` has fewer than six characters, before any
    /// attempt is counted, and otherwise as [`EpicWallet::mnemonic_with_pin`] does.
    pub async fn change_pin(
        &self,
        sealed_password: String,
        old_pin: String,
        new_pin: String,
    ) -> Result<String, WalletError> {
        let old_pin = Zeroizing::new(old_pin);
        let new_pin = Zeroizing::new(new_pin);
        self.run("change_pin", |session| async move {
            session.ensure_unlocked()?;
            let new_pin = pin::NewPin::new(new_pin)?;
            let runtime = session.runtime();
            // Never reseal a password that does not open this wallet's vault.
            let check = |password| session.check_password(password);
            pin::change(
                &runtime.pin,
                session.store(),
                old_pin,
                sealed_password,
                new_pin,
                runtime.kdf,
                check,
            )
            .await
        })
        .await
    }

    /// Ends a PIN change of [`EpicWallet::change_pin`]: the old sealed text stops opening and
    /// only the new PIN with the new text opens the wallet. Call it once the app has stored the
    /// text `change_pin` returned, and pass the text it now holds as `sealed_password`. Text
    /// other than the pending change's, such as the old text of an app that stopped before it
    /// stored the new one, is refused, so the text the app holds always keeps opening. Does
    /// nothing when no change is pending.
    ///
    /// Fails with `InvalidArgument`, changing nothing, when `sealed_password` is not the text of
    /// the pending change, with `Locked` on a locked wallet, and with `SecretStore` when the
    /// store cannot be read or written or holds a damaged pending key; the change then stays
    /// pending.
    pub async fn confirm_pin_change(&self, sealed_password: String) -> Result<(), WalletError> {
        self.run("confirm_pin_change", |session| async move {
            session.ensure_unlocked()?;
            pin::confirm_change(&session.runtime().pin, session.store(), &sealed_password).await
        })
        .await
    }

    /// Changes the password of a wallet from [`EpicWallet::create`] or
    /// [`EpicWallet::import_wallet_seed`]: the vault is encrypted anew under `new_password`
    /// with Argon2id and a fresh salt. `current_password` must open the stored vault; that
    /// attempt is counted and delayed as in [`EpicWallet::open`]. Afterwards only the new
    /// password opens the wallet, also this handle's [`EpicWallet::mnemonic`].
    ///
    /// The new vault is written to the store as `lepic.vault-next` and read back before it
    /// replaces `lepic.vault`, and `lepic.vault-next` is deleted last. If the app stops part way,
    /// the wallet opens with the old or the new password, and the next [`EpicWallet::open`]
    /// with the password that works drops or finishes the change. Use a store whose `write`
    /// has stored the value durably when it completes.
    ///
    /// Fails with `InvalidArgument` when `new_password` has fewer than eight characters, and
    /// `Unsupported` for a wallet from [`EpicWallet::create_with_pin`] (change its PIN with
    /// [`EpicWallet::change_pin`]), both before any attempt is counted; with `WrongPassword`
    /// when `current_password` does not open the vault, `Locked` on a locked wallet, and
    /// `SecretStore` when the store fails or does not give back what was written: the old
    /// password then still opens the wallet, or, if the store failed while replacing
    /// `lepic.vault`, either password does until the next open settles it.
    pub async fn change_password(
        &self,
        current_password: String,
        new_password: String,
    ) -> Result<(), WalletError> {
        let current_password = Zeroizing::new(current_password);
        let new_password = Zeroizing::new(new_password);
        self.run("change_password", |session| async move {
            session.ensure_unlocked()?;
            let new_password = self::new_password(new_password)?;
            session
                .change_password(current_password, new_password)
                .await
        })
        .await
    }

    /// The default account's balance. With `refresh` it first updates outputs and
    /// transactions from the node. Without, it answers from what the wallet stored at its last
    /// refresh or scan, without the node, also before the first refresh of this handle, with
    /// `validated_with_node` false.
    pub async fn summary(&self, refresh: bool) -> Result<WalletSummary, WalletError> {
        self.run("summary", |session| async move {
            if refresh {
                session.refresh().await
            } else {
                session.stored_summary()
            }
        })
        .await
    }

    /// Every output of the default account, spent ones included, ordered by commitment, from
    /// the store alone. The values of the outputs in each `category` add up to that part of
    /// `summary(refresh: false)`; refresh first for the node's view.
    pub async fn outputs(&self) -> Result<Vec<WalletOutput>, WalletError> {
        self.run("outputs", |session| async move { session.outputs() })
            .await
    }

    /// Every transaction of the default account, newest first, from the store alone.
    pub async fn transactions(&self) -> Result<Vec<TransactionDetails>, WalletError> {
        self.run("transactions", |session| async move {
            session.transactions().await
        })
        .await
    }

    /// Imports the transaction history of an epic-wallet wallet (the GUI's or the CLI's) whose
    /// folder is `source_dir`: the folder holding `wallet_data`, or `wallet_data` itself. The
    /// wallet must have been made from the same recovery phrase, for example by
    /// [`EpicWallet::import_wallet_seed`] from that folder's `wallet.seed`. Call it once after
    /// the import, before or after the restore scan; calling it again with the same folder
    /// only links what a later scan found and dates it.
    ///
    /// Nothing in `source_dir` is written, locked or moved: the database is copied into this
    /// wallet's folder, read from the copy, and the copy is removed. Imported transactions
    /// keep their dates, types, amounts, fees, slate ids, messages and kernel, and show
    /// `origin` `Imported`. Balances still come from the scan alone. A history that cannot be
    /// imported (none there, too old a wallet, a damaged or encrypted database, another
    /// recovery phrase) is reported in `status`, not as an error; the scan restores the funds.
    ///
    /// Asks the node for block times and for the kernels of unfinished transactions; a node
    /// that cannot be reached leaves those undone. Fails with `Locked` on a locked wallet and
    /// `Io` when the import folder cannot be made in the wallet's folder. A copy that cannot be
    /// written there, for example on a full disk, is reported as status `unreadable`.
    pub async fn import_legacy_history(
        &self,
        source_dir: String,
    ) -> Result<LegacyImport, WalletError> {
        self.run("import_legacy_history", |session| async move {
            session.import_legacy_history(&source_dir).await
        })
        .await
    }

    /// The transaction `tx_id`, from the store alone. Fails with `InvalidArgument` when the
    /// wallet holds no such transaction.
    pub async fn transaction(&self, tx_id: u32) -> Result<TransactionDetails, WalletError> {
        self.run("transaction", |session| async move {
            session.transaction(tx_id).await
        })
        .await
    }

    /// The fee and inputs a send of `amount` with `minimum_confirmations` would take, chosen
    /// as [`EpicWallet::create_send_slate`], [`EpicWallet::send_file`] and
    /// [`EpicWallet::send_epicbox`] choose them, with nothing locked. Such a send at the same
    /// chain tip, with no outputs changed in between, charges this fee. Asks the node for its
    /// tip. Fails as those sends do, for example with `NotEnoughFunds` or `NodeUnreachable`.
    /// Pass the `options` the send will get.
    ///
    /// `options` chooses the inputs and change, `Smallest` with one change output when `None`;
    /// change outputs outside 1..=10 fail with `InvalidArgument`.
    pub async fn estimate_fee(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        options: Option<SendOptions>,
    ) -> Result<FeeEstimate, WalletError> {
        self.run("estimate_fee", |session| async move {
            session
                .estimate_fee(amount, minimum_confirmations, options)
                .await
        })
        .await
    }

    /// The largest amount a send with `minimum_confirmations` can pay now, with its fee and
    /// inputs. A send of that amount at the same chain tip, with no outputs changed in between,
    /// charges this fee. Fails with `NotEnoughFunds` when no amount can be paid, and otherwise
    /// as [`EpicWallet::estimate_fee`]. Sending everything takes `All`: with `Smallest`
    /// the largest amount is the one the smallest outputs that cover it can pay, which is the
    /// same total here but may differ past 500 outputs.
    ///
    /// `options` chooses the inputs and change, `Smallest` with one change output when `None`;
    /// change outputs outside 1..=10 fail with `InvalidArgument`.
    pub async fn estimate_max(
        &self,
        minimum_confirmations: u64,
        options: Option<SendOptions>,
    ) -> Result<FeeEstimate, WalletError> {
        self.run("estimate_max", |session| async move {
            session.estimate_max(minimum_confirmations, options).await
        })
        .await
    }

    /// The fee and inputs of [`EpicWallet::split_outputs`] into `outputs` outputs now, with
    /// nothing locked. Fails as that call does.
    pub async fn estimate_split(
        &self,
        outputs: u32,
        minimum_confirmations: u64,
    ) -> Result<FeeEstimate, WalletError> {
        self.run("estimate_split", |session| async move {
            session
                .estimate_self_send(split_shape(outputs)?, minimum_confirmations)
                .await
        })
        .await
    }

    /// Splits the wallet's funds into `outputs` outputs of nearly equal value, from 2 to 10, so
    /// that several sends can follow without waiting for each other's change: a normal network
    /// transaction to the wallet itself, confirmed as any send, never through its Epicbox
    /// address. It spends every output with `minimum_confirmations`, so the whole balance is
    /// locked until it confirms; a wallet with more than 500 spendable outputs spends the 500
    /// smallest and keeps the rest spendable. It shows as two transactions over transport
    /// `self`, a send holding the change outputs and a receive holding one output; the fee is
    /// that of [`EpicWallet::estimate_split`] at the same tip.
    ///
    /// Fails with `InvalidArgument` for a count outside 2..=10, with `NotEnoughFunds` when the
    /// spendable outputs cannot pay the fee and one base unit into each output, and otherwise
    /// as [`EpicWallet::estimate_fee`], storing nothing. Fails with `NotPosted` when it was
    /// stored but the node did not take it: post the send again with
    /// [`EpicWallet::repost_transaction`] or cancel it with
    /// [`EpicWallet::cancel_transaction`].
    pub async fn split_outputs(
        &self,
        outputs: u32,
        minimum_confirmations: u64,
    ) -> Result<SelfSentTx, WalletError> {
        self.run("split_outputs", |session| async move {
            session
                .self_send(split_shape(outputs)?, minimum_confirmations)
                .await
        })
        .await
    }

    /// The fee and inputs of [`EpicWallet::consolidate_outputs`] now, with nothing locked.
    /// Fails as that call does.
    pub async fn estimate_consolidate(
        &self,
        minimum_confirmations: u64,
    ) -> Result<FeeEstimate, WalletError> {
        self.run("estimate_consolidate", |session| async move {
            session
                .estimate_self_send(SelfSendShape::Consolidate, minimum_confirmations)
                .await
        })
        .await
    }

    /// Merges every output with `minimum_confirmations` into one, as
    /// [`EpicWallet::split_outputs`] does with one output: with more than 500 spendable
    /// outputs it merges the 500 smallest, and a later call merges the rest. Fails as that
    /// call does, and with `NothingToConsolidate` when fewer than two outputs are spendable.
    pub async fn consolidate_outputs(
        &self,
        minimum_confirmations: u64,
    ) -> Result<SelfSentTx, WalletError> {
        self.run("consolidate_outputs", |session| async move {
            session
                .self_send(SelfSendShape::Consolidate, minimum_confirmations)
                .await
        })
        .await
    }

    /// Spends exactly the outputs `commitments` names, by `WalletOutput.commitment`, into one
    /// output of this wallet, as [`EpicWallet::consolidate_outputs`] does, and locks nothing
    /// else. Use it to make a cancelled payment final: once a payment is cancelled its inputs
    /// are spendable here, but the other wallet may still hold a signed copy that spends them,
    /// for example the issuer of an invoice that was paid, until they are spent elsewhere.
    ///
    /// Fails with `InvalidArgument` when `commitments` is empty, or names an output that is
    /// unknown, not unspent with `minimum_confirmations`, or named twice; with `NotEnoughFunds`
    /// when the fee takes their whole value; and otherwise as
    /// [`EpicWallet::consolidate_outputs`] does, storing nothing.
    pub async fn spend_outputs_to_self(
        &self,
        commitments: Vec<String>,
        minimum_confirmations: u64,
    ) -> Result<SelfSentTx, WalletError> {
        self.run("spend_outputs_to_self", |session| async move {
            session
                .spend_outputs_to_self(commitments, minimum_confirmations)
                .await
        })
        .await
    }

    /// `summary(refresh: true)` as a stream: a first event at 0 percent, then one with
    /// `summary` set at 100. A failure ends the stream with its [`WalletError`] as the stream's
    /// error, after the first event.
    pub async fn refresh(&self, progress: StreamSink<RefreshProgress>) {
        let sink = progress.clone();
        let result = self
            .run("refresh", |session| async move {
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
            .await;
        end_stream(&sink, result);
    }

    /// Scans the chain for this wallet's outputs from `start_height`, or, by default, from
    /// shortly before the last completed scan (the whole chain after a restore), streaming
    /// progress until an event with `finished`, which carries its `result`. A failure
    /// ends the stream with its [`WalletError`] as the stream's error; a cancelled scan ends it
    /// with `Cancelled`.
    ///
    /// With `delete_unconfirmed` the scan also runs the repair of `epic-wallet scan
    /// --delete_unconfirmed` and always starts from the beginning of the chain, so
    /// `start_height` must be `None`. Every output locked by a transaction in progress that is
    /// found unspent on chain is unlocked, and every output not on chain yet is deleted; the
    /// transactions they belong to are cancelled as `cancel_transaction` cancels them. That
    /// includes sends waiting for an answer and payments signed but not yet confirmed: a
    /// payment already on its way may then fail. If one is still mined, its output is not lost,
    /// but it stays hidden until the next scan finds it. The repair covers only the outputs
    /// that were locked or unconfirmed when the scan started; sends and receives made while it
    /// runs are left alone.
    ///
    /// Every page of outputs is stored as it is scanned, so a cancelled or failed scan leaves
    /// the wallet consistent, with what it found so far stored. The next scan with the same
    /// start and the same `delete_unconfirmed` resumes after the last stored page; the repair
    /// of unconfirmed outputs runs only when a scan completes.
    ///
    /// Fails with `InvalidArgument` for `delete_unconfirmed` with a `start_height`, and with
    /// `WalletBusy` while another scan of this wallet runs.
    pub async fn scan(
        &self,
        start_height: Option<u64>,
        delete_unconfirmed: bool,
        progress: StreamSink<ScanProgress>,
    ) {
        let sink = progress.clone();
        let result = self
            .run("scan", |session| async move {
                // A closed stream only means nobody is listening.
                let report = |event| drop(progress.add(event));
                session.scan(start_height, delete_unconfirmed, report).await
            })
            .await;
        end_stream(&sink, result);
    }

    /// Locks the wallet now, for example when the app goes to the background: stops the
    /// listener and any scan, wipes the root key and ends the calls still running, which fail
    /// with `Cancelled`; a store write under way is finished first. Every later call on this
    /// handle fails with `Locked`. The wallet directory is released as soon as the database
    /// closes, at once when nothing was running, so the wallet can be opened anew on a fresh
    /// handle right away; drop this one. An open that comes while the write still runs waits
    /// for it, up to about two seconds. Locking a locked wallet does nothing.
    ///
    /// A call that failed with `Cancelled` at a lock may still have stored its effect, since
    /// the write ran to its end: a send, resend or repost may be stored as sent or finalized,
    /// and a cancel as cancelled. After a lock, re-read the transactions on the next open
    /// instead of taking the failure as the outcome; a send stored as sent is delivered again
    /// with its resend, one finalized is posted again with [`EpicWallet::repost_transaction`].
    #[frb(sync)]
    pub fn lock(&self) {
        self.boundary().guard_or("lock", (), || self.session.lock());
    }

    /// Stops a running scan: a node request in flight is abandoned at once and a page being
    /// stored is finished first, so the scan's stream ends with `Cancelled` within about the
    /// time one page takes to identify. Does nothing when no scan runs; a scan started later
    /// is not affected.
    #[frb(sync)]
    pub fn cancel_scan(&self) {
        self.boundary()
            .guard_or("cancel_scan", (), || self.session.cancel_scan());
    }

    /// Step 1 of a manual send: builds the slate, locks the inputs and returns the slate text
    /// for the recipient, whose answer goes to [`EpicWallet::finalize_and_post`].
    ///
    /// `message` goes to the recipient signed with the slate, as `epic-wallet send --message`
    /// sends it. It is cut to its first 256 bytes, on a character boundary, before it is signed.
    ///
    /// `options` chooses the inputs and change, `Smallest` with one change output when `None`;
    /// change outputs outside 1..=10 fail with `InvalidArgument`.
    pub async fn create_send_slate(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<Slate, WalletError> {
        self.run("create_send_slate", |session| async move {
            session
                .create_send_slate_with(amount, minimum_confirmations, message, options)
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
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SentTx, WalletError> {
        self.run("send_file", |session| async move {
            session
                .send_file(
                    amount,
                    minimum_confirmations,
                    PathBuf::from(path),
                    message,
                    options,
                )
                .await
        })
        .await
    }

    /// Recipient side: signs an incoming send and returns the answer for the sender.
    ///
    /// The same slate again, from text, a file or the listener, returns the answer stored the
    /// first time with `repeated` set and the first call's `tx_id`; nothing is stored or
    /// signed again, so a lost answer can be handed out again. Fails with `InvalidSlate` for
    /// another slate under an id received before, or when that receive was cancelled or
    /// expired.
    pub async fn receive_slate(&self, slate_json: String) -> Result<ReceivedSlate, WalletError> {
        self.run("receive_slate", |session| async move {
            session.receive_slate(slate_json).await
        })
        .await
    }

    /// [`EpicWallet::receive_slate`] for the slate file at `path`. The answer is also written to
    /// `<path>.response`, as `epic-wallet` names it, for a repeated slate too.
    pub async fn receive_file(&self, path: String) -> Result<ReceivedSlate, WalletError> {
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

    /// Cancels a transaction that was not posted and unlocks its outputs. Cancelling an
    /// invoice issued with `issue_invoice_epicbox` withdraws it and sends the payer a
    /// `withdrawn` notice when the payer proved it runs LEPIC.
    ///
    /// Fails with `OnChain` or `InPool` when the node's chain or pool holds the kernel of a
    /// finalized transaction, and with `NodeUnreachable` when the node cannot be asked.
    pub async fn cancel_transaction(&self, tx_id: u32) -> Result<(), WalletError> {
        self.run("cancel_transaction", |session| async move {
            session.cancel(tx_id).await
        })
        .await
    }

    /// Releases a finalized or posted send the network never took, once
    /// `TransactionDetails.releasable` says so: the send is cancelled, its inputs are unlocked
    /// and its change is dropped. The node is asked once more first.
    ///
    /// If another node still holds the transaction and mines it later, the inputs are spent by
    /// it after all, and a new send that spends them fails. A refresh within 10080 blocks of
    /// the release then confirms the send, with a transaction event, and restores its change.
    ///
    /// Fails with `NotReleasable`, with `OnChain` or `InPool` when the node's chain or pool
    /// holds the transaction, and with `NodeUnreachable` when the node cannot be asked.
    pub async fn release_transaction(&self, tx_id: u32) -> Result<(), WalletError> {
        self.run("release_transaction", |session| async move {
            session.release(tx_id).await
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

    /// Signs a push registration for this wallet's Epicbox address, so a push service can tie
    /// the FCM `token` to it. LEPIC builds the text itself, `epic-push-v1`, `action`, the
    /// address key, `token` and `timestamp` (unix seconds) on five lines, and signs nothing
    /// else. `action` is `register` or `unregister`; `token` is 1 to 4096 characters of
    /// `[A-Za-z0-9_:.-]`. Fails with `InvalidArgument` for any other, and with `Unsupported`
    /// when the configuration names no relay.
    pub async fn push_signature(
        &self,
        action: String,
        token: String,
        timestamp: u64,
    ) -> Result<PushSignature, WalletError> {
        self.run("push_signature", |session| async move {
            session.push_signature(&action, &token, timestamp)
        })
        .await
    }

    /// Sends to `<address>@<relay>[:port]` over Epicbox. The listener or a drain finalizes and
    /// posts it when the answer arrives. Fails with `InvalidArgument`, storing nothing, for an
    /// address that [`validate_epicbox_address`] refuses, such as a key without `@<relay>`.
    /// `message` and `options` work as in [`EpicWallet::create_send_slate`].
    pub async fn send_epicbox(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        address: String,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SentTx, WalletError> {
        self.run("send_epicbox", |session| async move {
            session
                .send_epicbox(amount, minimum_confirmations, address, message, options)
                .await
        })
        .await
    }

    /// Connects to the relay once, handles every pending message and disconnects: the call for
    /// background work. While the listener runs it does nothing and reports nothing handled,
    /// as the listener receives the same messages.
    pub async fn drain_epicbox(&self) -> Result<InboxReport, WalletError> {
        self.run("drain_epicbox", |session| async move {
            session.drain_epicbox().await
        })
        .await
    }

    /// Moves the open wallet to the node and Epicbox relay `config` names, keeping it unlocked.
    /// Calls running when it starts end first, and calls made while it waits or runs start
    /// after it; a running scan is waited for too, so cancel it first to switch at once. A
    /// running listener moves to a new relay once the message in hand is settled and
    /// acknowledged, at most 30 seconds later, and its stream goes on without `Stopped`. A new
    /// relay changes the wallet's Epicbox address to `<key>@<new relay>`; answers sent to the
    /// old address stay on the old relay.
    ///
    /// `config.data_dir` and `config.chain` must be those the wallet was opened with: another
    /// chain is another wallet. Fails with `InvalidArgument`, keeping the servers in use, for
    /// a node URL or relay that is not one, for another directory or chain, and when
    /// `config` turns Epicbox on or off; with `Locked` on a locked wallet.
    pub async fn set_servers(&self, config: WalletConfig) -> Result<(), WalletError> {
        let mut config = config;
        let node_secret = NodeSecret::take(&mut config);
        let session = Arc::clone(&self.session);
        let in_flight = Arc::clone(&self.session.in_flight);
        self.boundary()
            .run_tracked(
                "set_servers",
                async move { session.set_servers(&config, &node_secret).await },
                &in_flight,
            )
            .await
    }

    /// The tip, version, readiness and tip block time of the node `config` names, asked as the
    /// open wallet asks its own node: through the wallet's tor, with its onion routes, while
    /// node requests go over tor, and directly when they do not or for a node on this
    /// computer. Use it instead of [`node_tip`] while a wallet is open, also to probe a node
    /// that is not the wallet's; the wallet's node stays as it is. Only `node_url` and
    /// `node_api_secret` of `config` are used.
    ///
    /// Fails with `NodeUnreachable` when the tip or version cannot be had, `InvalidArgument`
    /// for a URL that is not one of a node, and `Locked` on a locked wallet.
    pub async fn node_tip_for(&self, config: WalletConfig) -> Result<NodeTip, WalletError> {
        let mut config = config;
        let node_secret = NodeSecret::take(&mut config);
        self.run("node_tip_for", |session| async move {
            session.node_tip_for(&config, &node_secret).await
        })
        .await
    }

    /// Starts the Epicbox listener, unless it runs already, and streams what it does until
    /// [`EpicWallet::stop_listener`]. The last event is `Stopped`; a listener that fails while
    /// running reports an `Error` event first. When the listener cannot start, for example
    /// with `Unsupported` when the configuration names no relay, the stream ends with that
    /// [`WalletError`] as its error and no event. A second call while the listener runs gets
    /// a stream that ends at once.
    pub async fn start_listener(&self, events: StreamSink<ListenerEvent>) {
        let boundary = self.boundary();
        let handle = match boundary.guard("start_listener", || self.session.claim_listener()) {
            Ok(Some(handle)) => handle,
            Ok(None) => return,
            Err(error) => return end_stream(&events, Err(error)),
        };
        let session = Arc::clone(&self.session);
        let runner = boundary.clone();
        boundary.handle.spawn(async move {
            let sink = events.clone();
            let listening = runner
                .run("listen", async move {
                    // A closed stream only means the app stopped listening.
                    let report = |event| drop(sink.add(event));
                    session.listen(&handle, report).await
                })
                .await;
            if let Err(error) = listening {
                let _ = events.add(ListenerEvent {
                    kind: ListenerEventKind::Error,
                    tx_id: None,
                    slate_id: None,
                    message: error.to_string(),
                    reason: None,
                    retry_in_ms: None,
                });
            }
            let _ = events.add(ListenerEvent {
                kind: ListenerEventKind::Stopped,
                tx_id: None,
                slate_id: None,
                message: String::new(),
                reason: None,
                retry_in_ms: None,
            });
        });
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
    /// transport changes. The stream ends when the wallet is dropped. A failure to subscribe,
    /// which only a defect inside LEPIC causes, ends the stream with a `Panic` [`WalletError`]
    /// as its error.
    pub fn events(&self, sink: StreamSink<WalletEvent>) {
        let boundary = self.boundary();
        let failed = sink.clone();
        let subscribed = boundary.guard("events", || {
            let events = self.session.subscribe();
            boundary.handle.spawn(session::forward_events(events, sink));
            Ok(())
        });
        end_stream(&failed, subscribed);
    }
}
