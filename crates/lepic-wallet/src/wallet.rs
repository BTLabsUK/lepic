// SPDX-License-Identifier: Apache-2.0
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use lepic_keychain::{Seed, WalletSeedError, WalletSeedFile};
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_store::WalletStore;
use tokio::sync::broadcast;
use tracing::{Dispatch, Span, debug, dispatcher, info, instrument};

use crate::account::{self, Account, AccountLabel};
use crate::config::WalletConfig;
use crate::error::WalletError;
use crate::event::{EVENT_CAPACITY, Event, SessionState};
use crate::extension::{ContactNotices, NativeSlates, PairRequests, ReplyKeys};
use crate::lifecycle::{
    self, Password, PhraseCheck, RecoveryPhrase, SeedSource, Session, Target, WordCount,
    generate_seed, recovery_phrase,
};
use crate::ports::{Ports, SecretVault, StoreOpener};

/// One wallet: its configuration, the ports it runs on and, while unlocked, its root key and
/// open database.
///
/// A new handle is locked. [`Wallet::create`], [`Wallet::restore`],
/// [`Wallet::import_wallet_seed`] and [`Wallet::open`] unlock it; [`Wallet::lock`] drops the
/// root key and closes the database again.
pub struct Wallet<N, S: StoreOpener, V> {
    config: Arc<WalletConfig>,
    ports: Arc<Ports<N, S, V>>,
    session: RwLock<Option<Arc<Session<S::Store>>>>,
    events: broadcast::Sender<Event>,
    unsolicited: tokio::sync::Mutex<()>,
    contacts: tokio::sync::Mutex<()>,
    reply_keys: OnceLock<Arc<dyn ReplyKeys>>,
    native_slates: OnceLock<Arc<dyn NativeSlates>>,
    contact_notices: OnceLock<Arc<dyn ContactNotices<N, S, V>>>,
    pair_requests: OnceLock<Arc<dyn PairRequests<N, S, V>>>,
    posting: tokio::sync::Mutex<()>,
    boosts: crate::boost::Boosts,
}

impl<N, S, V> Wallet<N, S, V>
where
    N: NodeApi + 'static,
    S: StoreOpener + 'static,
    V: SecretVault + 'static,
{
    /// A locked handle. Fails with [`WalletError::Config`] when a policy value is out of range:
    /// a receipt cap of zero, or fewer than one default minimum confirmation.
    pub fn new(config: WalletConfig, ports: Ports<N, S, V>) -> Result<Self, WalletError> {
        config.policy.validate()?;
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Ok(Self {
            config: Arc::new(config),
            ports: Arc::new(ports),
            session: RwLock::new(None),
            events,
            unsolicited: tokio::sync::Mutex::new(()),
            contacts: tokio::sync::Mutex::new(()),
            reply_keys: OnceLock::new(),
            native_slates: OnceLock::new(),
            contact_notices: OnceLock::new(),
            pair_requests: OnceLock::new(),
            posting: tokio::sync::Mutex::new(()),
            boosts: crate::boost::Boosts::default(),
        })
    }

    /// Polls `poller` every `interval` for `duration` from now, merged with the boost it has
    /// (ADR 0058), and returns the window that took effect.
    pub fn boost(
        &self,
        poller: crate::boost::Poller,
        duration: std::time::Duration,
        interval: std::time::Duration,
    ) -> crate::boost::Window {
        self.boosts
            .boost(poller, duration, interval, self.ports.clock.now())
    }

    /// The wallet's boosts, for the host loops that poll.
    pub fn boosts(&self) -> &crate::boost::Boosts {
        &self.boosts
    }

    pub fn config(&self) -> &WalletConfig {
        &self.config
    }

    pub fn ports(&self) -> &Ports<N, S, V> {
        &self.ports
    }

    /// Installs the hook that gives file and paste S1s and I1s their reply key. The first hook
    /// installed stays; returns whether this one was.
    pub fn set_reply_keys(&self, keys: Arc<dyn ReplyKeys>) -> bool {
        self.reply_keys.set(keys).is_ok()
    }

    pub(crate) fn reply_keys(&self) -> Option<Arc<dyn ReplyKeys>> {
        self.reply_keys.get().cloned()
    }

    /// Installs the hook that converts slates to and from `lepic.v1` for native slates over
    /// Epicbox. The first hook installed stays; returns whether this one was.
    pub fn set_native_slates(&self, slates: Arc<dyn NativeSlates>) -> bool {
        self.native_slates.set(slates).is_ok()
    }

    /// The hook installed with [`Self::set_native_slates`], if any.
    pub fn native_slates(&self) -> Option<Arc<dyn NativeSlates>> {
        self.native_slates.get().cloned()
    }

    /// Installs the hook that seals notices about a paired contact's slates into its mailbox.
    /// The first hook installed stays; returns whether this one was.
    pub fn set_contact_notices(&self, notices: Arc<dyn ContactNotices<N, S, V>>) -> bool {
        self.contact_notices.set(notices).is_ok()
    }

    pub(crate) fn contact_notices(&self) -> Option<Arc<dyn ContactNotices<N, S, V>>> {
        self.contact_notices.get().cloned()
    }

    /// Installs the hook that takes pairing requests to the payments address. The first hook
    /// installed stays; returns whether this one was.
    pub fn set_pair_requests(&self, requests: Arc<dyn PairRequests<N, S, V>>) -> bool {
        self.pair_requests.set(requests).is_ok()
    }

    pub(crate) fn pair_requests(&self) -> Option<Arc<dyn PairRequests<N, S, V>>> {
        self.pair_requests.get().cloned()
    }

    /// Events from now on. See [`crate::event`] for what a slow subscriber misses.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn is_unlocked(&self) -> bool {
        self.session
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Creates a wallet from new entropy, stores its seed under `password` and unlocks it.
    /// Returns the recovery phrase, which the user must write down; it is not shown again.
    ///
    /// Fails with [`WalletError::WalletExists`] when the secret storage already holds a wallet,
    /// and with [`WalletError::ForeignDatabase`] when the data directory holds another wallet's
    /// database. Neither failure changes anything.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub async fn create(
        &self,
        password: Password,
        words: WordCount,
    ) -> Result<RecoveryPhrase, WalletError> {
        self.ensure_locked()?;
        let seed = generate_seed(&mut **self.ports.rng.lock(), words)?;
        let phrase = recovery_phrase(&seed)?;
        self.install_new(password, seed, SeedSource::Generated)
            .await?;
        info!("wallet created");
        Ok(phrase)
    }

    /// Recreates a wallet from its recovery phrase and unlocks it. Outputs on chain are found
    /// by a later scan from genesis. A data directory that already holds this wallet's database
    /// is reused.
    ///
    /// Fails with [`WalletError::Mnemonic`] for a phrase that is not valid BIP39 English, and
    /// otherwise as [`Wallet::create`] does.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub async fn restore(&self, password: Password, phrase: &str) -> Result<(), WalletError> {
        self.restore_from_height(password, phrase, Height::ZERO)
            .await
    }

    /// [`Wallet::restore`] of a wallet with no output below `scan_from`: a scan from that
    /// height, or from below it, to the tip completes the restore, and outputs older than it
    /// are not found until a scan from genesis. A database the restore reuses keeps the restore
    /// scan it waited for. Fails as [`Wallet::restore`] does.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub async fn restore_from_height(
        &self,
        password: Password,
        phrase: &str,
        scan_from: Height,
    ) -> Result<(), WalletError> {
        self.ensure_locked()?;
        let seed = Seed::from_mnemonic(phrase).map_err(WalletError::Mnemonic)?;
        self.install_new(password, seed, SeedSource::Recovered { scan_from })
            .await?;
        info!(height = %scan_from, "wallet restored");
        Ok(())
    }

    /// Recreates a wallet from the text of an `epic-wallet` `wallet.seed` file, decrypted with
    /// `file_password`, stores the seed under `password` and unlocks it. The file is only read.
    ///
    /// Fails with [`WalletError::WrongPassword`] when the file does not decrypt, with
    /// [`WalletError::WalletSeedFile`] when it is malformed, and otherwise as
    /// [`Wallet::restore`] does.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub async fn import_wallet_seed(
        &self,
        password: Password,
        file: &str,
        file_password: Password,
    ) -> Result<(), WalletError> {
        self.ensure_locked()?;
        let file = WalletSeedFile::parse(file).map_err(WalletError::WalletSeedFile)?;
        let seed = self
            .blocking(move |_, _| {
                let seed =
                    file.decrypt(file_password.expose_bytes())
                        .map_err(|error| match error {
                            WalletSeedError::Decryption => WalletError::WrongPassword,
                            other => WalletError::WalletSeedFile(other),
                        })?;
                debug!("wallet.seed decrypted");
                Ok(seed)
            })
            .await?;
        self.install_new(
            password,
            seed,
            SeedSource::Recovered {
                scan_from: Height::ZERO,
            },
        )
        .await?;
        info!("wallet imported");
        Ok(())
    }

    /// Unlocks an existing wallet with its password.
    ///
    /// Fails with [`WalletError::WrongPassword`], [`WalletError::NoWallet`] when the secret
    /// storage holds no wallet, [`WalletError::AlreadyOpen`], or
    /// [`WalletError::NetworkMismatch`] and [`WalletError::ForeignDatabase`] when the database
    /// in the data directory is not this wallet's.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub async fn open(&self, password: Password) -> Result<(), WalletError> {
        self.ensure_locked()?;
        let session = self
            .blocking(move |ports, config| {
                let key_start = account::draw_key_start(&mut **ports.rng.lock());
                lifecycle::open(
                    &ports.stores,
                    &ports.secrets,
                    &target(config),
                    &password,
                    key_start,
                )
            })
            .await?;
        self.install(session)?;
        info!("wallet opened");
        Ok(())
    }

    /// Drops the root key and closes the database. Does nothing when already locked.
    /// Operations already running keep the session until they finish.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn lock(&self) {
        let previous = self
            .session
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if previous.is_some() {
            info!("wallet locked");
            self.emit(Event::Session(SessionState::Locked));
        }
    }

    /// Locks the wallet and ends the event stream.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn close(self) {
        self.lock();
        info!("wallet closed");
        self.emit(Event::Session(SessionState::Closed));
    }

    /// Whether the database was rebuilt from the seed, by [`Wallet::restore`],
    /// [`Wallet::restore_from_height`], [`Wallet::import_wallet_seed`] or [`Wallet::open`] on a
    /// missing database, and no scan from [`Wallet::restore_scan_start`] or below has reached
    /// the tip since. Until one does, receiving, issuing invoices and sends with change fail
    /// with [`WalletError::RestoreScanRequired`]. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn restore_scan_required(&self) -> Result<bool, WalletError> {
        let session = self.session()?;
        session
            .store
            .read(|repos| Ok(lifecycle::restore_scan_pending(repos)?))
    }

    /// The height the pending restore scan must start at or below to complete it: the start of
    /// [`Wallet::restore_from_height`], genesis for every other rebuilt database. `None` when
    /// [`Wallet::restore_scan_required`] is false. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn restore_scan_start(&self) -> Result<Option<Height>, WalletError> {
        let session = self.session()?;
        session
            .store
            .read(|repos| Ok(lifecycle::restore_scan_start(repos)?))
    }

    /// How the database was found on disk when the wallet was unlocked: encrypted, moved into
    /// an encrypted database by this unlock, or still plain because that move failed (tried
    /// again at the next unlock), and whether an older build's plain database was set aside.
    /// `None` for an opener that does not keep the database encrypted at rest. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn store_at_rest(&self) -> Result<Option<lepic_store::AtRestReport>, WalletError> {
        Ok(self.session()?.at_rest.clone())
    }

    /// The record the open database keeps of the plain database it was copied from
    /// ([`lepic_store::MIGRATED_FROM_SETTING`]), for [`lepic_store::retire_plain_store`];
    /// `None` when it was not copied from one. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn migrated_from(&self) -> Result<Option<String>, WalletError> {
        self.session()?
            .store
            .read(|repos| Ok(repos.setting(lepic_store::MIGRATED_FROM_SETTING)?))
    }

    /// The fingerprint of the wallet's seed that its database stores, as lowercase hex; equal
    /// to [`lifecycle::seed_fingerprint`] of its recovery phrase, on any network. It is no
    /// secret, but it identifies the wallet; it never proves a phrase. Fails with
    /// [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn fingerprint(&self) -> Result<String, WalletError> {
        lifecycle::fingerprint(&self.session()?.keychain)
    }

    /// Checks, on a locked handle, that `phrase` is the recovery phrase of the database in the
    /// data directory, without unlocking, as [`lifecycle::check_phrase`] does; a match holds
    /// its seed. A host that lost the wallet's password uses it before it stores the seed
    /// under a new one.
    ///
    /// Fails as [`lifecycle::check_phrase`] does, and with [`WalletError::AlreadyOpen`] on an
    /// unlocked handle.
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub async fn check_phrase(&self, phrase: &str) -> Result<PhraseCheck, WalletError> {
        self.ensure_locked()?;
        let seed = Seed::from_mnemonic(phrase).map_err(WalletError::Mnemonic)?;
        self.blocking(move |ports, config| {
            lifecycle::check_seed(&ports.stores, &target(config), seed)
        })
        .await
    }

    /// Every account, ordered by index. Fails with [`WalletError::Locked`].
    #[instrument(skip_all, fields(wallet = %self.config.name))]
    pub fn accounts(&self) -> Result<Vec<Account>, WalletError> {
        let session = self.session()?;
        session
            .store
            .read(|repos| Ok(repos.accounts()?.into_iter().map(Account::from).collect()))
    }

    /// Fails with [`WalletError::Locked`] or an [`crate::AccountError::UnknownLabel`].
    #[instrument(skip_all, fields(wallet = %self.config.name, account = %label))]
    pub fn account(&self, label: &str) -> Result<Account, WalletError> {
        let session = self.session()?;
        session
            .store
            .read(|repos| account::account_by_label(repos, label))
    }

    /// Adds an account under the next free index `m/<index>/0`. Fails with
    /// [`WalletError::Locked`], or an [`crate::AccountError`] when the label is invalid or taken.
    #[instrument(skip_all, fields(wallet = %self.config.name, account = %label))]
    pub fn create_account(&self, label: &str) -> Result<Account, WalletError> {
        let label = AccountLabel::new(label)?;
        let session = self.session()?;
        let account = session
            .store
            .write(|repos| account::create_account(repos, &label))?;
        info!("account created");
        Ok(account)
    }

    async fn install_new(
        &self,
        password: Password,
        seed: Seed,
        source: SeedSource,
    ) -> Result<(), WalletError> {
        let session = self
            .blocking(move |ports, config| {
                let key_start = account::draw_key_start(&mut **ports.rng.lock());
                lifecycle::create(
                    &ports.stores,
                    &ports.secrets,
                    &target(config),
                    &password,
                    &seed,
                    source,
                    key_start,
                )
            })
            .await?;
        self.install(session)
    }

    fn install(&self, session: Session<S::Store>) -> Result<(), WalletError> {
        {
            let mut slot = self.session.write().unwrap_or_else(PoisonError::into_inner);
            if slot.is_some() {
                return Err(WalletError::AlreadyOpen);
            }
            *slot = Some(Arc::new(session));
        }
        self.emit(Event::Session(SessionState::Unlocked));
        Ok(())
    }

    fn ensure_locked(&self) -> Result<(), WalletError> {
        if self.is_unlocked() {
            return Err(WalletError::AlreadyOpen);
        }
        Ok(())
    }

    /// The unlocked wallet's keychain and store. Fails with [`WalletError::Locked`].
    pub fn session(&self) -> Result<Arc<Session<S::Store>>, WalletError> {
        self.session
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(WalletError::Locked)
    }

    /// Serves receipts of payments nobody asked for one at a time, so the open receipt caps
    /// hold under concurrent listeners.
    pub(crate) async fn unsolicited_turn(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.unsolicited.lock().await
    }

    /// Keeps a push of a finalized transaction and a cancel or release from overlapping: a push
    /// holds it from its state check to the write of `posted`, a cancel or release from its
    /// lookup to its write. Otherwise a cancel could release the inputs of a transaction the
    /// node takes a moment later.
    pub(crate) async fn posting_turn(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.posting.lock().await
    }

    /// Serves the contact engine's runs one at a time: a collecting cycle, a pairing link
    /// entered by hand and an outbox run each read, reach a relay and write, so two at once
    /// could take one message twice or post one entry twice.
    pub async fn contact_turn(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.contacts.lock().await
    }

    /// Sends `event` to every subscriber.
    pub fn emit(&self, event: Event) {
        // Sending fails only when nobody is subscribed, which is not an error.
        let _ = self.events.send(event);
    }

    /// Runs key derivation and database work on the runtime's blocking pool, so an async host
    /// is never stalled by Argon2 or disk access. The work runs under the caller's subscriber
    /// and inside the operation's span, so what it logs is attributed and filtered like the rest
    /// of the operation.
    pub async fn blocking<T, F>(&self, work: F) -> Result<T, WalletError>
    where
        T: Send + 'static,
        F: FnOnce(&Ports<N, S, V>, &WalletConfig) -> Result<T, WalletError> + Send + 'static,
    {
        let ports = Arc::clone(&self.ports);
        let config = Arc::clone(&self.config);
        let span = Span::current();
        let dispatch = dispatcher::get_default(Dispatch::clone);
        self.ports
            .runtime
            .spawn_blocking(move || {
                dispatcher::with_default(&dispatch, || span.in_scope(|| work(&ports, &config)))
            })
            .await
            .map_err(WalletError::Task)?
    }
}

fn target(config: &WalletConfig) -> Target<'_> {
    Target {
        data_dir: &config.data_dir,
        network: config.network,
    }
}

impl<N, S: StoreOpener, V> std::fmt::Debug for Wallet<N, S, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("name", &self.config.name)
            .field("network", &self.config.network)
            .finish_non_exhaustive()
    }
}
