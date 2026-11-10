// SPDX-License-Identifier: Apache-2.0
//! Each command: what it asks the engine and what it reports.

use std::future::Future;
use std::io::{Read as _, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use jiff::Timestamp;
use lepic_epicbox::{ClientSettings, EpicboxAddress, Network as RelayNetwork, TRANSPORT_ID};
use lepic_keychain::KdfParams;
use lepic_keychain::vault::MAX_WALLET_SEED_FILE_LEN;
use lepic_methods::epicbox::Epicbox;
use lepic_methods::http::{
    CoinbaseAccess, Counts, DirectPeer, Exposure, Host as ReceiveHost, Http, HttpPeer,
    ListenSettings, ListenerHandle, ListenerUrl, PeerClient, PeerEndpoint, PlainHttp, Receiver,
    Refusal, RpcClient, refuse, webpki_tls_config,
};
use lepic_methods::registry::Methods;
use lepic_methods::tor::{SocksProxy, Tor, TorPeer, TorProcess, TorSettings, TorState};
use lepic_node::{NodeApi, NodeClient, Propagation, RpcTransport};
use lepic_primitives::amount::Height;
use lepic_primitives::params::Network;
use lepic_store::{
    ChainCheck, ContactId, ImportedKind, OutboxStatus, OutputStatus, Repositories, SlateStage,
    StoredTransaction, TxDirection, TxId, WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::file::{FILE, FileTransport, response_path};
use lepic_transport::transport::{BoxFuture, Destination, Exchange as _, Location, TransportId};
use lepic_wallet::chain::ImplausibleNodeData;
use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};
use lepic_wallet::details::TransactionDetails;
use lepic_wallet::epicbox_invoice::{
    IncomingInvoice, InvoiceExpiry, InvoiceSweep, PeerInvoiceSupport,
};
use lepic_wallet::event::{Balance, SlateId};
use lepic_wallet::finalize::{FinalizeError, Posted};
use lepic_wallet::inbox::{InboxSummary, ListenHandle};
use lepic_wallet::invoice::{InvoiceError, InvoiceRequest, PayRequest};
use lepic_wallet::legacy_history::{ImportWorkDir, LegacyImportStatus, TxOrigin};
use lepic_wallet::method::{Method, MethodLookup};
use lepic_wallet::namespace::SealKeyKind;
use lepic_wallet::refresh::{BalanceCategory, OutputDetails, RefreshError, RefreshOutcome};
use lepic_wallet::scan::{ScanCancel, ScanOptions, ScanStart, ScanSummary};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendError, SendRequest, SentSlate};
use lepic_wallet::slate::WireSlate;
use lepic_wallet::state::state_name;
use lepic_wallet::{
    Clock, Event, Password, Ports, ProofKey, ReceiveRequest, Received, SharedRng, Wallet,
    WalletConfig, WalletError, WalletName, WordCount,
};
use lepic_wallet_contacts::{Dialect, DirectHandler, WalletContacts as _};
use rand::Rng as _;
use rand::SeedableRng as _;
use rand::rngs::{StdRng, SysRng};
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

use crate::Console;
use crate::amount::{format_amount, format_fee, format_units, parse_amount};
use crate::cli::{
    ApiCommand, Command, DestinationArgs, EpicboxCommand, FinalizeArgs, HttpCommand,
    HttpListenArgs, HttpReach, ImportHistoryArgs, ImportSeedArgs, InitArgs, InvoiceCommand,
    IssueArgs, ListingArgs, NodeCommand, PayArgs, PostArgs, ReceiveArgs, ResendArgs, RestoreArgs,
    ScanArgs, SelectionArg, SendArgs, SendDestinationArgs, SpendArgs, TorAddressArgs,
    TorBinaryArgs, TorCommand, TorListenArgs, TxCommand, WalletCommand, WalletScanArgs, WordsArg,
};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{
    AccountReport, AddressReport, EpicboxStatusReport, ExpiredReport, FinalizeReport,
    HttpListenReport, ImportHistoryReport, ImportedReport, InboxReport, InfoReport, InitReport,
    InvoiceDeclineReport, InvoiceIssueReport, InvoiceListReport, InvoicePayReport, ListingReport,
    MessageReport, NodeStatusReport, OutputReport, OutputsReport, ParkedInvoiceReport,
    PasswordReport, PeerReport, PostReport, ReceiveReport, Report, ResendReport, RestoreReport,
    ScanReport, SendReport, TorAddressReport, TorListenReport, TxListReport, TxReport,
    TxStateReport, WalletScanReport,
};
use crate::progress::Progress;
use crate::secret::NEW_PASSWORD_FILE_ENV;
use crate::settings::{OutputFormat, Settings};
use crate::stores::{CliStores, SharedStore};
use crate::vault::{FileVault, VAULT_FILE};

mod api_client;
mod contact;
mod epic1;
#[cfg(unix)]
pub(crate) mod files;
mod in_person;
pub(crate) mod peer;
mod profile;
#[cfg(unix)]
mod serve;

/// The directory inside the data directory that holds the wallet's tor files.
const TOR_DIR: &str = "tor";

/// Every CLI wallet has this name in logs; one data directory holds one wallet.
const WALLET_NAME: &str = "default";

type CliWallet<N> = Wallet<N, CliStores, FileVault>;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// One command's wallet handle and the methods it sends and receives over.
struct Opened<N: NodeApi + 'static> {
    wallet: CliWallet<N>,
    /// Every method below, looked up by id.
    methods: Arc<Methods>,
    file: Arc<dyn Method>,
    epicbox: Arc<Epicbox>,
    /// Holds the answers of HTTP sends until they are finalized.
    http: Arc<Http>,
    /// The HTTP method for sends that may not reach this computer, with its own connection
    /// pool; it holds its answers with [`Self::http`].
    http_to_other_computers: Arc<dyn Method>,
    /// The native endpoints of HTTP listeners, their adverts read through [`Self::http`].
    http_peer: HttpPeer,
    /// As [`Self::http_peer`], the adverts read through [`Self::http_to_other_computers`].
    http_peer_to_other_computers: HttpPeer,
    /// Holds the answers of Tor sends until they are finalized.
    tor: Arc<Tor>,
    /// The native endpoints of listeners behind onions, reached through [`Self::tor`].
    tor_peer: TorPeer,
    /// Taken by a send over Tor for as long as its tor is attached to [`Self::tor`], which only
    /// one send at a time can use.
    tor_gate: Arc<tokio::sync::Mutex<()>>,
    /// Held until the command ends; `None` when the data directory does not exist.
    _lock: Option<lepic_store::DataDirLock>,
}

/// A tor started for one send, and the hold on the wallet's tor transport it keeps until stopped.
struct SendTor {
    process: Arc<TorProcess>,
    _gate: tokio::sync::OwnedMutexGuard<()>,
}

impl<N: NodeApi + 'static> Opened<N> {
    /// The database the wallet opened when it was unlocked.
    fn store(&self) -> Result<SharedStore, CliError> {
        self.wallet
            .ports()
            .stores
            .opened()
            .ok_or(CliError::Wallet(WalletError::Locked))
    }

    /// The Epicbox method, as the engine's calls that name a method take it.
    fn epicbox_method(&self) -> Arc<dyn Method> {
        Arc::clone(&self.epicbox) as Arc<dyn Method>
    }

    /// The method a send or resend over `transport` goes through.
    fn send_method(&self, transport: TransportId) -> Result<&Arc<dyn Method>, SendError> {
        self.methods
            .get(transport)
            .ok_or(SendError::UnknownTransport { transport })
    }

    /// The method and native endpoints of a send over `transport`, over HTTP only to the
    /// computers `reach` allows.
    fn route(&self, transport: TransportId, reach: HttpReach) -> Result<Route<'_>, SendError> {
        if transport == lepic_methods::http::TRANSPORT_ID {
            return Ok(match reach {
                HttpReach::OtherComputers => (
                    &self.http_to_other_computers,
                    Some(&self.http_peer_to_other_computers),
                ),
                HttpReach::Any => (self.send_method(transport)?, Some(&self.http_peer)),
            });
        }
        let peer: Option<&dyn DirectPeer> = if transport == lepic_methods::tor::TRANSPORT_ID {
            Some(&self.tor_peer)
        } else {
            None
        };
        Ok((self.send_method(transport)?, peer))
    }

    /// Sends over `transport` to the payee `delivery` names, over HTTP only to the computers
    /// `reach` allows. A send to a listener takes its native endpoint unless `legacy` asks
    /// for the legacy dialect, under the rules of [`lepic_wallet_contacts::DirectError`].
    async fn send(
        &self,
        transport: TransportId,
        reach: HttpReach,
        request: SendRequest,
        delivery: Delivery,
        legacy: bool,
    ) -> Result<Sent, CliError> {
        let (method, peer) = self.route(transport, reach)?;
        match (peer, delivery) {
            (Some(peer), Delivery::Deliver { to }) => {
                let direct = self
                    .wallet
                    .contact_book()
                    .direct_send(peer, method, request, to, legacy)
                    .await?;
                Ok(Sent {
                    sent: direct.sent,
                    dialect: Some(direct.dialect),
                    reply: direct.reply,
                })
            }
            (_, delivery) => Ok(Sent::plain(
                self.wallet.send(method, request, delivery).await?,
            )),
        }
    }

    /// Sends the stored S1 of `tx_id` again over `transport`, choosing the dialect of a
    /// listener as [`Self::send`] does. Returns the dialect, `None` for a transport that is
    /// not direct, and the answer a native exchange brought back.
    async fn resend(
        &self,
        transport: TransportId,
        tx_id: TxId,
        delivery: Delivery,
        legacy: bool,
    ) -> Result<(Option<Dialect>, Option<WireSlate>), CliError> {
        let (method, peer) = self.route(transport, HttpReach::Any)?;
        match (peer, delivery) {
            (Some(peer), Delivery::Deliver { to }) => {
                let direct = self
                    .wallet
                    .contact_book()
                    .direct_resend(peer, method, tx_id, to, legacy)
                    .await?;
                Ok((Some(direct.dialect), direct.reply))
            }
            (_, delivery) => {
                self.wallet.resend(method, tx_id, delivery).await?;
                Ok((None, None))
            }
        }
    }
}

/// A send that went out, the dialect it took to a listener, and the answer a native exchange
/// brought back.
struct Sent {
    sent: SentSlate,
    dialect: Option<Dialect>,
    reply: Option<WireSlate>,
}

impl Sent {
    /// A send over a transport that is not direct.
    const fn plain(sent: SentSlate) -> Self {
        Self {
            sent,
            dialect: None,
            reply: None,
        }
    }
}

/// The method a send goes through, and the native endpoints it can reach.
type Route<'a> = (&'a Arc<dyn Method>, Option<&'a dyn DirectPeer>);

struct Run<'a, H: Host> {
    host: &'a H,
    settings: &'a Settings,
    console: &'a mut Console,
    /// Turns true once the user interrupts.
    interrupt: watch::Receiver<bool>,
    /// Set by a command that stops on its own when interrupted and reports what it did.
    graceful: Arc<AtomicBool>,
    /// The wallet `lepic serve` holds open, which every command then uses.
    held: Option<Arc<Opened<HostNode<H>>>>,
}

/// Runs `command` until it ends or the user interrupts it. An interrupt ends any command at
/// once, at a prompt too, which drops the prompt's echo guard; the engine keeps its stored state
/// consistent at every await point, as it must when an app is killed. Listen and scan instead
/// stop themselves and report what they stored.
pub(crate) async fn execute<H: Host>(
    host: &H,
    command: Command,
    settings: &Settings,
    console: &mut Console,
) -> Result<Report, CliError> {
    let (signal, interrupt) = watch::channel(false);
    let interrupted = host.interrupted();
    let watcher = tokio::spawn(async move {
        interrupted.await;
        signal.send_replace(true);
    });
    let graceful = Arc::new(AtomicBool::new(false));
    let mut run = Run {
        host,
        settings,
        console,
        interrupt: interrupt.clone(),
        graceful: Arc::clone(&graceful),
        held: None,
    };
    let result = tokio::select! {
        result = run.dispatch(command) => result,
        () = abort_on(interrupt, &graceful) => Err(CliError::Interrupted),
    };
    watcher.abort();
    result
}

async fn abort_on(mut interrupt: watch::Receiver<bool>, graceful: &AtomicBool) {
    let stopped = interrupt.wait_for(|stopped| *stopped).await.is_ok();
    if !stopped || graceful.load(Ordering::SeqCst) {
        std::future::pending::<()>().await;
    }
}

impl<H: Host> Run<'_, H> {
    async fn dispatch(&mut self, command: Command) -> Result<Report, CliError> {
        match command {
            Command::Wallet(command) => self.wallet(command).await,
            Command::Tx(command) => self.tx(command).await,
            Command::Invoice(command) => self.invoice(command).await,
            Command::Epicbox(command) => self.epicbox(command).await,
            Command::Http(HttpCommand::Listen(args)) => self.http_listen(&args).await,
            Command::Tor(TorCommand::Address(args)) => self.tor_address(args).await,
            Command::Tor(TorCommand::Listen(args)) => self.tor_listen(args).await,
            Command::Peer(command) => self.peer(command).await,
            Command::Node(NodeCommand::Status) => self.node_status().await,
            Command::Contact(args) => self.contact(args).await,
            Command::InPerson(args) => self.in_person(args).await,
            Command::Epic1(args) => self.epic1(args).await,
            Command::Epictx(command) => self.epictx(command).await,
            Command::Profile(command) => self.profile(command).await,
            Command::Serve(args) => self.serve(args).await,
            Command::Api(ApiCommand::Client(command)) => self.api_client(command),
        }
    }

    /// Runs `work` to its end. When the user interrupts first, `stop` asks it to end early and
    /// its result is still awaited, so what it stored is reported. With human output, the
    /// wallet's events while it runs become progress lines on stderr, including one for each
    /// transaction a received slate creates.
    async fn until_interrupted<T>(
        &mut self,
        events: broadcast::Receiver<Event>,
        work: impl Future<Output = T>,
        stop: impl FnOnce(),
    ) -> T {
        self.graceful.store(true, Ordering::SeqCst);
        let human = self.settings.output == OutputFormat::Human;
        let mut interrupt = self.interrupt.clone();
        let mut stop = Some(stop);
        let mut events = human.then_some(events);
        let mut progress = Progress::default();
        tokio::pin!(work);
        let result = loop {
            tokio::select! {
                result = &mut work => break result,
                Ok(_) = interrupt.wait_for(|stopped| *stopped), if stop.is_some() => {
                    if let Some(stop) = stop.take() {
                        stop();
                    }
                }
                event = next_event(&mut events) => match event {
                    Ok(event) => self.show_progress(&mut progress, &event),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => events = None,
                },
            }
        };
        while let Some(Ok(event)) = events.as_mut().map(broadcast::Receiver::try_recv) {
            self.show_progress(&mut progress, &event);
        }
        result
    }

    fn show_progress(&mut self, progress: &mut Progress, event: &Event) {
        if let Some(line) = receipt_line(event).or_else(|| progress.line(event)) {
            self.show_line(&line);
        }
    }

    /// With human output, a line on stderr for each invoice event `events` holds: what a drain
    /// parked, finalized or expired.
    fn show_invoice_events(&mut self, mut events: broadcast::Receiver<Event>) {
        if self.settings.output != OutputFormat::Human {
            return;
        }
        while let Ok(event) = events.try_recv() {
            if matches!(
                event,
                Event::InvoiceParked(_)
                    | Event::InvoiceFinalized(_)
                    | Event::InvoiceExpired(_)
                    | Event::InvoicePosted(_)
                    | Event::InvoiceDeclined(_)
                    | Event::InvoiceWithdrawn(_)
                    | Event::InvoiceBounced(_)
                    | Event::PaymentPosted(_)
                    | Event::PaymentCancelled(_)
                    | Event::PaymentDeclined(_)
            ) && let Some(line) = receipt_line(&event)
            {
                self.show_line(&line);
            }
        }
    }

    fn show_line(&mut self, line: &str) {
        // Progress is a courtesy; a closed stderr must not end the command.
        let _ = writeln!(self.console.stderr, "{line}");
        let _ = self.console.stderr.flush();
    }

    async fn wallet(&mut self, command: WalletCommand) -> Result<Report, CliError> {
        match command {
            WalletCommand::Init(args) => self.init(&args).await,
            WalletCommand::Restore(args) => self.restore(&args).await,
            WalletCommand::ImportSeed(args) => self.import_seed(&args).await,
            WalletCommand::Info => self.info().await,
            WalletCommand::Scan(args) => self.scan(&args).await,
            WalletCommand::ImportHistory(args) => self.import_history(&args).await,
            WalletCommand::Outputs(args) => {
                let opened = self.open().await?;
                let account = opened.wallet.account(&args.account)?;
                let outputs = opened.wallet.outputs(account.index)?;
                Ok(Report::Outputs(OutputsReport {
                    account: account.label,
                    outputs: outputs.iter().map(output_report).collect(),
                }))
            }
            WalletCommand::Password => self.change_password().await,
            WalletCommand::Address => {
                let opened = self.open().await?;
                let address = opened.epicbox.attach_wallet(&opened.wallet)?;
                Ok(Report::Address(AddressReport {
                    address: address.to_string(),
                }))
            }
        }
    }

    async fn tx(&mut self, command: TxCommand) -> Result<Report, CliError> {
        match command {
            TxCommand::Send(args) => self.send(args).await,
            TxCommand::Receive(args) => self.receive(args).await,
            TxCommand::Finalize(args) => self.finalize(&args).await,
            TxCommand::Resend(args) => self.resend(args).await,
            TxCommand::Post(PostArgs { tx, fluff }) => {
                let opened = self.open().await?;
                let tx_id = TxId(tx.tx_id);
                let posted = opened.wallet.post(tx_id, propagation(fluff.fluff)).await?;
                Ok(Report::Post(post_report(tx_id, posted)))
            }
            TxCommand::Cancel(args) => {
                let opened = self.open().await?;
                // Cancelling an invoice issued over Epicbox tells its payer it is withdrawn.
                opened.epicbox.attach_wallet(&opened.wallet)?;
                let tx_id = TxId(args.tx_id);
                opened.wallet.cancel(tx_id).await?;
                Ok(Report::Cancel(TxStateReport {
                    tx_id: tx_id.0,
                    state: "cancelled".to_owned(),
                }))
            }
            TxCommand::Release(args) => {
                let opened = self.open().await?;
                let tx_id = TxId(args.tx_id);
                opened.wallet.release(tx_id).await?;
                Ok(Report::Release(TxStateReport {
                    tx_id: tx_id.0,
                    state: "cancelled".to_owned(),
                }))
            }
            TxCommand::List(args) => {
                let opened = self.open().await?;
                if args.refresh.refresh {
                    refreshed::<H>(&opened).await?;
                }
                let account = opened.wallet.account(&args.account.account)?;
                let transactions = opened
                    .store()?
                    .read(|repos| repos.transactions(account.index))?;
                Ok(Report::List(TxListReport {
                    account: account.label,
                    transactions: transactions.iter().map(|tx| tx_report(tx, None)).collect(),
                }))
            }
            TxCommand::Show(args) => {
                let slate_id = args.slate_id.slate_id.as_deref().map(SlateId::parse);
                let opened = self.open().await?;
                if args.refresh.refresh {
                    refreshed::<H>(&opened).await?;
                }
                let details = match (args.tx_id, slate_id) {
                    (Some(tx_id), _) => opened.wallet.transaction_details(TxId(tx_id)).await?,
                    (None, Some(Ok(slate_id))) => opened
                        .wallet
                        .sent_with_slate(slate_id)
                        .await?
                        .ok_or(CliError::NoSendWithSlate)?,
                    (None, Some(Err(_))) => return Err(CliError::SlateId),
                    (None, None) => return Err(CliError::NoSendWithSlate),
                };
                let report = opened.store()?.read(|repos| show(repos, &details))?;
                Ok(Report::Show(report))
            }
        }
    }

    async fn epicbox(&mut self, command: EpicboxCommand) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let expiry = self.settings.invoice_expiry;
        let (summary, expired) = match command {
            EpicboxCommand::Drain(ListingArgs {
                listing: Some(service_key),
                generation,
            }) => {
                let listing = listing_of(&service_key, generation)?;
                let summary = opened.epicbox.drain_at(&opened.wallet, &listing).await?;
                (summary, None)
            }
            EpicboxCommand::Drain(ListingArgs { listing: None, .. }) => {
                let events = opened.wallet.subscribe();
                // A sweep that cancels an invoice sends its `withdrawn` notice from the
                // payments address.
                opened.epicbox.attach_wallet(&opened.wallet)?;
                let expired = sweep(&opened.wallet, expiry).await;
                let summary = opened.epicbox.drain(&opened.wallet).await?;
                self.show_invoice_events(events);
                (summary, expired)
            }
            EpicboxCommand::Listen => {
                opened.epicbox.attach_wallet(&opened.wallet)?;
                let handle = ListenHandle::new();
                let swept = std::sync::Mutex::new(Some(InvoiceSweep::default()));
                let summary = self
                    .until_interrupted(
                        opened.wallet.subscribe(),
                        listen_and_sweep(&opened, &handle, expiry, &swept),
                        || finish_listen(&handle),
                    )
                    .await?;
                let expired = swept
                    .into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (summary, expired)
            }
            EpicboxCommand::Status(ListingArgs {
                listing: Some(service_key),
                generation,
            }) => {
                let listing = listing_of(&service_key, generation)?;
                let address = opened.epicbox.address_at(&opened.wallet, &listing)?;
                return Ok(Report::EpicboxStatus(EpicboxStatusReport {
                    relay: self.settings.relay.url(),
                    address: address.to_string(),
                    pending_deliveries: 0,
                }));
            }
            EpicboxCommand::Status(ListingArgs { listing: None, .. }) => {
                let address = opened.epicbox.attach_wallet(&opened.wallet)?;
                let pending = opened
                    .store()?
                    .read(|repos| repos.outbox(OutboxStatus::Pending))?
                    .len();
                return Ok(Report::EpicboxStatus(EpicboxStatusReport {
                    relay: self.settings.relay.url(),
                    address: address.to_string(),
                    pending_deliveries: pending,
                }));
            }
            EpicboxCommand::Peer(args) => {
                let capability = match opened
                    .wallet
                    .peer_capability(&opened.epicbox_method(), &args.address)?
                {
                    PeerInvoiceSupport::Unknown => "unknown",
                    PeerInvoiceSupport::Lepic => "lepic",
                    PeerInvoiceSupport::NoInvoices => "no_invoices",
                };
                let facts = opened
                    .wallet
                    .peer_compat(&opened.epicbox_method(), &args.address)?;
                let stored = facts.stored.unwrap_or_default();
                return Ok(Report::Peer(PeerReport {
                    address: args.address,
                    capability,
                    last_marked_at: stored.last_marked_at.map(|time| time.to_string()),
                    last_unmarked_at: stored.last_unmarked_at.map(|time| time.to_string()),
                    notices: facts.notices,
                    native_slates: stored.native_key.is_some(),
                }));
            }
        };
        Ok(Report::Inbox(inbox_report(summary, expired)))
    }

    async fn node_status(&mut self) -> Result<Report, CliError> {
        let node = self.host.node(self.settings)?;
        let version = node.get_version().await?;
        let tip = node.get_tip().await?;
        Ok(Report::NodeStatus(NodeStatusReport {
            node: self.settings.node.host().to_owned(),
            node_version: version.node_version,
            block_header_version: version.block_header_version,
            height: tip.height.value(),
            last_block: tip.last_block_pushed.to_hex(),
        }))
    }

    async fn init(&mut self, args: &InitArgs) -> Result<Report, CliError> {
        let password = self.new_password().await?;
        let wallet = self.prepare(true).await?;
        let phrase = wallet
            .wallet
            .create(password, word_count(args.words))
            .await?;
        Ok(Report::Init(InitReport {
            network: self.settings.network.to_string(),
            data_dir: self.data_dir_text(),
            recovery_phrase: Zeroizing::new(phrase.expose().to_owned()),
        }))
    }

    async fn restore(&mut self, args: &RestoreArgs) -> Result<Report, CliError> {
        let phrase = self
            .console
            .secrets
            .read("recovery phrase", "Recovery phrase: ")
            .await?;
        let password = self.new_password().await?;
        let opened = self.prepare(true).await?;
        let scan_from = Height::new(args.from_height.unwrap_or(0));
        opened
            .wallet
            .restore_from_height(password, phrase.trim(), scan_from)
            .await?;
        self.restored(&opened, &args.scan).await
    }

    async fn import_seed(&mut self, args: &ImportSeedArgs) -> Result<Report, CliError> {
        let file = read_seed_file(&args.seed_file)?;
        let file_password = self
            .console
            .secrets
            .read("wallet.seed password", "Password of the wallet.seed file: ")
            .await?;
        let password = self.new_password().await?;
        let opened = self.prepare(true).await?;
        opened
            .wallet
            .import_wallet_seed(password, &file, password_from(file_password))
            .await?;
        self.restored(&opened, &args.scan).await
    }

    async fn restored(
        &mut self,
        opened: &Opened<HostNode<H>>,
        args: &ScanArgs,
    ) -> Result<Report, CliError> {
        let scan = if args.no_scan {
            None
        } else {
            let options = ScanOptions {
                start: pending_restore_start(opened.wallet.restore_scan_start()?)
                    .unwrap_or(ScanStart::Genesis),
                ..ScanOptions::restore(self.settings.network)
            };
            let cancel = ScanCancel::new();
            let summary: ScanSummary = self
                .until_interrupted(
                    opened.wallet.subscribe(),
                    opened.wallet.scan(options, &cancel),
                    || cancel.cancel(),
                )
                .await?;
            Some(ScanReport {
                start_height: summary.start_height.value(),
                end_height: summary.end_height.value(),
                found: summary.found,
                restored: summary.restored,
            })
        };
        Ok(Report::Restore(RestoreReport {
            network: self.settings.network.to_string(),
            data_dir: self.data_dir_text(),
            scan,
        }))
    }

    /// A scan to the node's tip from where the arguments say, or from shortly before the last
    /// completed scan. A pending restore scan is completed only by a scan from its start or
    /// below, so it starts there unless a start height is given.
    async fn scan(&mut self, args: &WalletScanArgs) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let network = self.settings.network;
        let start = match args.start_height {
            Some(0) => ScanStart::Genesis,
            Some(height) => ScanStart::Height(Height::new(height)),
            None => pending_restore_start(opened.wallet.restore_scan_start()?)
                .unwrap_or(ScanOptions::update(network).start),
        };
        let options = ScanOptions {
            start,
            delete_unconfirmed: args.delete_unconfirmed,
            ..ScanOptions::update(network)
        };
        let cancel = ScanCancel::new();
        let work = async {
            if args.reset_chain {
                opened.wallet.reset_chain_position(options, &cancel).await
            } else {
                opened.wallet.scan(options, &cancel).await
            }
        };
        let summary = self
            .until_interrupted(opened.wallet.subscribe(), work, || cancel.cancel())
            .await?;
        // The engine skips a start above the tip without storing anything; saying so beats a
        // report of a scan that never ran.
        if summary.start_height > summary.end_height {
            return Err(CliError::StartAboveTip {
                start: summary.start_height.value(),
                tip: summary.end_height.value(),
            });
        }
        Ok(Report::Scan(WalletScanReport {
            start_height: summary.start_height.value(),
            end_height: summary.end_height.value(),
            resumed: summary.resumed,
            found: summary.found,
            restored: summary.restored,
            revived: summary.revived,
            unlocked: summary.unlocked,
            deleted: summary.deleted,
            delete_unconfirmed: args.delete_unconfirmed,
        }))
    }

    async fn import_history(&mut self, args: &ImportHistoryArgs) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            jiff::Timestamp::now().as_nanosecond()
        );
        let work = ImportWorkDir::create(&self.settings.data_dir, &suffix)
            .map_err(CliError::io("create the import folder"))?;
        let outcome = opened
            .wallet
            .import_legacy_history(&args.dir, work.path())
            .await?;
        Ok(Report::ImportHistory(ImportHistoryReport {
            status: import_status_name(outcome.status),
            transactions: outcome.transactions,
            outputs: outcome.outputs,
            accounts_named: outcome.accounts_named,
            linked: outcome.linked,
            skipped: outcome.skipped,
            confirmed_by_kernel: outcome.confirmed_by_kernel,
            dated: outcome.dated,
        }))
    }

    async fn info(&mut self) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let (outcome, balances) = refreshed::<H>(&opened).await?;
        let (height, node_behind, node_height) = match outcome {
            RefreshOutcome::Refreshed(summary) => {
                let height = balances_height(&balances).unwrap_or(summary.height);
                let held = (height < summary.height).then_some(summary.height.value());
                (height, false, held)
            }
            RefreshOutcome::NodeBehind { tip, .. } => (tip, true, None),
        };
        let accounts = opened
            .wallet
            .accounts()?
            .into_iter()
            .map(|account| {
                let balance = balances.iter().find(|b| b.account == account.index);
                let field = |pick: fn(&Balance) -> u64| balance.map(|b| format_units(pick(b)));
                AccountReport {
                    index: account.index.0,
                    label: account.label,
                    total: field(|b| b.total.value()),
                    spendable: field(|b| b.spendable.value()),
                    awaiting_confirmation: field(|b| b.awaiting_confirmation.value()),
                    awaiting_finalization: field(|b| b.awaiting_finalization.value()),
                    immature: field(|b| b.immature.value()),
                    locked: field(|b| b.locked.value()),
                }
            })
            .collect();
        Ok(Report::Info(InfoReport {
            network: self.settings.network.to_string(),
            height: height.value(),
            node_behind,
            catching_up: node_height.is_some(),
            node_height,
            accounts,
        }))
    }

    async fn send(&mut self, args: SendArgs) -> Result<Report, CliError> {
        let amount = parse_amount(&args.amount)?;
        let spend = Spend::from_args(&args.spend)?;
        let (payee, destination) =
            self.payee(args.destination, args.plain_http.allow_plain_http)?;
        let slate_id = args
            .slate_id
            .slate_id
            .as_deref()
            .map(caller_slate_id)
            .transpose()?;
        let opened = self.open().await?;
        let account = opened.wallet.account(&args.account.account)?;
        let repeat = |to| repeat_of(&opened, slate_id, account.index, amount, &payee, to);
        if let Some(report) = repeat(destination.clone()).await? {
            return Ok(report);
        }
        let transport = payee.transport();
        if transport == TRANSPORT_ID {
            opened.epicbox.attach_wallet(&opened.wallet)?;
        }
        // Drawn here when the caller gave none, so an interrupted send can still be found.
        let drawn = slate_id.map_or_else(drawn_slate_id, Ok)?;
        let request = SendRequest {
            slate_id: Some(drawn),
            ..spend.send_request(account.index, amount, args.message.message)
        };
        if transport == lepic_methods::tor::TRANSPORT_ID {
            // The checks the send makes before it stores anything, before tor takes its time
            // to connect for a send that cannot be made.
            opened
                .wallet
                .estimate_fee(request.amount, request.selection_options())
                .await?;
        }
        let tor = self.tor_for(transport, &args.tor, &opened).await?;
        // From here the send may store its transaction, so an interrupt ends it here and reports
        // the transaction it stored, which the caller can then resend or cancel.
        let sent_slate = request.slate_id;
        self.graceful.store(true, Ordering::SeqCst);
        let mut interrupt = self.interrupt.clone();
        let purpose = args.purpose.map(contact::purpose);
        let data_dir = &self.settings.data_dir;
        let sending = async {
            let sent = match &payee {
                Payee::Delivery(_, delivery) => {
                    opened
                        .send(
                            transport,
                            args.reach,
                            request,
                            delivery.clone(),
                            args.legacy.legacy,
                        )
                        .await?
                }
                Payee::Contact(id) => Sent::plain(
                    contact::send_to_contact(&opened, *id, request, purpose, data_dir).await?,
                ),
            };
            let state = finalize_direct_reply(
                &opened,
                transport,
                sent.sent.tx_id,
                &sent.sent.slate_id.to_string(),
                sent.reply,
                args.fluff.fluff,
            )
            .await?;
            Ok::<_, CliError>((sent.sent, sent.dialect, state))
        };
        let sending = tokio::select! {
            result = sending => Some(result),
            Ok(_) = interrupt.wait_for(|stopped| *stopped) => None,
        };
        stop_tor(&opened, tor).await;
        let Some(sending) = sending else {
            return Err(interrupted_send(&opened, sent_slate).await?);
        };
        let sending = match (sending, slate_id) {
            // A send under the same id that ran at the same time stored its transaction first.
            (
                Err(error @ CliError::Send(SendError::SlateIdTaken { sent: Some(_), .. })),
                Some(_),
            ) => return repeat(destination).await?.ok_or(error),
            (sending, _) => sending,
        };
        let (sent, dialect, state) = sending?;
        Ok(sent_report(&sent, transport, destination, state, dialect))
    }

    async fn resend(&mut self, args: ResendArgs) -> Result<Report, CliError> {
        let (transport, delivery, destination) =
            self.delivery(args.destination, args.plain_http.allow_plain_http)?;
        let opened = self.open().await?;
        if transport == TRANSPORT_ID {
            opened.epicbox.attach_wallet(&opened.wallet)?;
        }
        let tx_id = TxId(args.tx.tx_id);
        let tor = self.tor_for(transport, &args.tor, &opened).await?;
        let resending = async {
            let (dialect, reply) = opened
                .resend(transport, tx_id, delivery, args.legacy.legacy)
                .await?;
            if !lepic_methods::http::is_direct(transport) {
                return Ok(("sent", dialect));
            }
            let details = opened.wallet.transaction_details(tx_id).await?;
            let slate_id = details
                .transaction
                .entry
                .slate_id
                .ok_or(CliError::HttpReplyLost { tx_id: tx_id.0 })?;
            let state = finalize_direct_reply(
                &opened,
                transport,
                tx_id,
                &slate_id.to_string(),
                reply,
                args.fluff.fluff,
            )
            .await?;
            Ok::<_, CliError>((state, dialect))
        }
        .await;
        stop_tor(&opened, tor).await;
        let (state, dialect) = resending?;
        Ok(Report::Resend(ResendReport {
            tx_id: tx_id.0,
            transport: transport.to_string(),
            destination,
            state,
            dialect: dialect.map(Dialect::as_str),
        }))
    }

    /// Answers payments over HTTP until interrupted.
    async fn http_listen(&mut self, args: &HttpListenArgs) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let listener = HttpListener::start(&opened, self.settings, args).await?;
        if self.settings.output == OutputFormat::Human {
            let what = if args.coinbase {
                "payments and block rewards"
            } else {
                "payments"
            };
            self.show_line(&format!(
                "Listening for {what} over HTTP on port {} ({}). Ctrl-C stops.",
                listener.port,
                listener.exposure.as_str()
            ));
        }
        let stop = tokio::sync::Notify::new();
        self.until_interrupted(opened.wallet.subscribe(), stop.notified(), || {
            stop.notify_one();
        })
        .await;
        Ok(Report::HttpListen(listener.shutdown().await))
    }

    /// For a send over Tor, starts the wallet's tor from `binary`, waits until it can send and
    /// attaches it to the wallet's tor transport.
    async fn tor_for<N: NodeApi + 'static>(
        &mut self,
        transport: lepic_transport::transport::TransportId,
        binary: &TorBinaryArgs,
        opened: &Opened<N>,
    ) -> Result<Option<SendTor>, CliError> {
        if transport != lepic_methods::tor::TRANSPORT_ID {
            return Ok(None);
        }
        let gate = Arc::clone(&opened.tor_gate).lock_owned().await;
        let tor = Arc::new(self.start_tor(binary)?);
        self.wait_for_tor(&tor).await?;
        opened.tor.attach(Arc::clone(&tor) as Arc<dyn SocksProxy>);
        if self.settings.output == OutputFormat::Human {
            self.show_line(
                "Reaching the other wallet over Tor; one that is not online takes up to about two \
                 and a half minutes to fail.",
            );
        }
        Ok(Some(SendTor {
            process: tor,
            _gate: gate,
        }))
    }

    fn start_tor(&self, binary: &TorBinaryArgs) -> Result<TorProcess, CliError> {
        let tor_binary = binary.tor_binary.clone().ok_or(CliError::TorBinaryNeeded)?;
        let mut settings = TorSettings::new(
            tor_binary,
            self.settings.data_dir.join(TOR_DIR),
            self.settings.tuning.tor_timings(),
        );
        settings.lib_dir.clone_from(&binary.lib_dir);
        settings.withheld_env = vec![crate::secret::PASSWORD_ENV.to_owned()];
        Ok(TorProcess::start(settings))
    }

    /// Waits until `tor` can send, with its bootstrap progress on stderr for people.
    async fn wait_for_tor(&mut self, tor: &TorProcess) -> Result<(), CliError> {
        let human = self.settings.output == OutputFormat::Human;
        let mut states = tor.subscribe();
        let mut shown = None;
        loop {
            let state = states.borrow_and_update().clone();
            match state {
                TorState::Starting { progress, .. } => {
                    if human && shown != Some(progress) {
                        shown = Some(progress);
                        self.show_line(&format!("Connecting to the Tor network: {progress}%"));
                    }
                }
                state if state.can_send() => return Ok(()),
                // Failed, or stopped: its error says which.
                _ => return Ok(tor.wait_bootstrapped().await.map(drop)?),
            }
            if states.changed().await.is_err() {
                return Ok(tor.wait_bootstrapped().await.map(drop)?);
            }
        }
    }

    async fn tor_address(&mut self, args: TorAddressArgs) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let key = if args.previous {
            opened.wallet.previous_onion_key()?
        } else {
            opened.wallet.onion_key()?
        };
        Ok(Report::TorAddress(TorAddressReport {
            onion: lepic_methods::tor::onion_address(key.public_key()),
        }))
    }

    /// Publishes the wallet's onion, and with `--previous-onion` the previous one on its own
    /// listener, and answers payments over Tor until interrupted.
    async fn tor_listen(&mut self, args: TorListenArgs) -> Result<Report, CliError> {
        if args.tor.tor_binary.is_none() {
            return Err(CliError::TorBinaryNeeded);
        }
        let opened = self.open().await?;
        let key = opened.wallet.onion_key()?;
        let onion = lepic_methods::tor::onion_address(key.public_key());
        let previous_key = if args.previous_onion {
            Some(opened.wallet.previous_onion_key()?)
        } else {
            None
        };
        let previous_onion = previous_key
            .as_ref()
            .map(|key| lepic_methods::tor::onion_address(key.public_key()));
        let counts = Arc::new(Counts::default());
        let host = Arc::new(CliHost {
            opened: Arc::clone(&opened),
            counts: Arc::clone(&counts),
        });
        let (handle, previous_handle) =
            onion_listeners(&opened, self.settings, &host, previous_key.is_some()).await?;
        let tor = self.start_tor(&args.tor)?;
        let published = async {
            self.wait_for_tor(&tor).await?;
            if self.settings.output == OutputFormat::Human {
                self.show_line("Publishing the wallet's onion address.");
            }
            tor.publish_onion(key.expose_seed(), handle.local_addr().port())
                .await?;
            if let (Some(key), Some(previous)) = (&previous_key, &previous_handle) {
                let target = lepic_methods::tor::OnionTarget::Port(previous.local_addr().port());
                tor.add_onion_to(key.expose_seed(), target).await?;
            }
            Ok::<_, CliError>(())
        }
        .await;
        drop(key);
        drop(previous_key);
        let ended = match published {
            Ok(()) => {
                if self.settings.output == OutputFormat::Human {
                    let at = match &previous_onion {
                        Some(previous) => format!("{onion} and {previous}"),
                        None => onion.clone(),
                    };
                    self.show_line(&format!(
                        "Listening for payments at {at} over Tor. Ctrl-C stops."
                    ));
                }
                let stop = tokio::sync::Notify::new();
                let work = async {
                    tokio::select! {
                        () = stop.notified() => Ok(()),
                        failure = lepic_methods::tor::ended(&tor) => Err(CliError::Tor(failure)),
                    }
                };
                self.until_interrupted(opened.wallet.subscribe(), work, || {
                    stop.notify_one();
                })
                .await
            }
            Err(error) => Err(error),
        };
        tor.stop().await;
        handle.shutdown().await;
        if let Some(previous) = previous_handle {
            previous.shutdown().await;
        }
        ended?;
        Ok(Report::TorListen(TorListenReport {
            onion,
            previous_onion,
            received: counts.received.load(Ordering::Relaxed),
            repeated: counts.repeated.load(Ordering::Relaxed),
            refused: counts.refused.load(Ordering::Relaxed),
        }))
    }

    /// Where a send goes, and how the report names it: a contact by its id, anything else as
    /// [`Self::delivery`] parses it.
    fn payee(
        &self,
        destination: SendDestinationArgs,
        allow_plain_http: bool,
    ) -> Result<(Payee, String), CliError> {
        let SendDestinationArgs {
            to,
            to_file,
            to_contact,
        } = destination;
        if let Some(text) = to_contact {
            let id = contact::contact_id(&text)?;
            return Ok((Payee::Contact(id), id.to_string()));
        }
        let (transport, delivery, destination) =
            self.delivery(DestinationArgs { to, to_file }, allow_plain_http)?;
        Ok((Payee::Delivery(transport, delivery), destination))
    }

    /// Where a first slate goes, the method it goes through, and how the report names it. An address is parsed here,
    /// before the wallet stores anything: a send to an address that cannot be delivered to
    /// would leave a transaction behind with its inputs locked. An address with a scheme is a
    /// listening wallet's HTTP endpoint; plain HTTP to another computer needs
    /// `allow_plain_http`.
    fn delivery(
        &self,
        destination: DestinationArgs,
        allow_plain_http: bool,
    ) -> Result<(TransportId, Delivery, String), CliError> {
        match (destination.to, destination.to_file) {
            (Some(address), _) if is_onion(&address) => {
                let onion =
                    lepic_methods::tor::parse_onion(&address).map_err(CliError::OnionAddress)?;
                Ok((
                    lepic_methods::tor::TRANSPORT_ID,
                    Delivery::Deliver {
                        to: Destination::new(onion.host()),
                    },
                    onion.host(),
                ))
            }
            (Some(address), _) if address.contains("://") => {
                let plain = if allow_plain_http {
                    PlainHttp::Allowed
                } else {
                    PlainHttp::LoopbackOnly
                };
                let url = ListenerUrl::parse(&address, plain).map_err(CliError::HttpUrl)?;
                Ok((
                    lepic_methods::http::TRANSPORT_ID,
                    Delivery::Deliver {
                        to: Destination::new(url.as_uri()),
                    },
                    url.as_uri(),
                ))
            }
            (Some(address), _) => {
                let parsed = EpicboxAddress::parse_with_default(
                    &address,
                    relay_network(self.settings.network),
                    &self.settings.servers.default_epicbox_domain,
                )
                .map_err(CliError::Address)?;
                // A relay the user wrote is kept as written: the message carries its port.
                let address = if address.contains('@') {
                    address
                } else {
                    parsed.to_string()
                };
                Ok((
                    TRANSPORT_ID,
                    Delivery::Deliver {
                        to: Destination::new(address.clone()),
                    },
                    address,
                ))
            }
            (None, Some(path)) => {
                let text = path.display().to_string();
                Ok((
                    FILE,
                    Delivery::Export {
                        to: Location::File(path),
                    },
                    text,
                ))
            }
            (None, None) => Err(CliError::NoDestination),
        }
    }

    async fn receive(&mut self, args: ReceiveArgs) -> Result<Report, CliError> {
        check_payment_file(&args.slate.file)?;
        let opened = self.open().await?;
        let files = FileTransport::new();
        let wire = files
            .import(&Location::File(args.slate.file.clone()))
            .await
            .map_err(slate_file(&args.slate.file))?;
        let received =
            receive_slate(&opened, &wire, args.account.account, args.message.message).await?;
        let reply = args
            .reply
            .reply_file
            .unwrap_or_else(|| response_path(&args.slate.file));
        refuse_saved_txs(&reply)?;
        let answer = answer_wire(&opened, &wire, &received.reply)?;
        files
            .export(&answer, &Location::File(reply.clone()))
            .await
            .map_err(slate_file(&reply))?;
        Ok(Report::Receive(ReceiveReport {
            tx_id: received.tx_id.0,
            slate_id: received.slate.id().to_string(),
            amount: format_amount(received.slate.amount()),
            reply_file: reply.display().to_string(),
            repeated: received.repeated,
        }))
    }

    async fn finalize(&mut self, args: &FinalizeArgs) -> Result<Report, CliError> {
        check_payment_file(&args.slate.file)?;
        let opened = self.open().await?;
        let wire = FileTransport::new()
            .import(&Location::File(args.slate.file.clone()))
            .await
            .map_err(slate_file(&args.slate.file))?;
        finalize_slate(&opened, &wire, args.fluff.fluff).await
    }

    async fn invoice(&mut self, command: InvoiceCommand) -> Result<Report, CliError> {
        match command {
            InvoiceCommand::Issue(args) => self.issue_invoice(args).await,
            InvoiceCommand::Pay(args) => match parked_slate_id(&args.invoice) {
                Some(slate_id) => self.pay_parked_invoice(slate_id, args).await,
                None => self.pay_invoice_file(args).await,
            },
            InvoiceCommand::List => {
                let opened = self.open().await?;
                let invoices = opened
                    .wallet
                    .pending_invoices(self.settings.invoice_expiry)?;
                Ok(Report::InvoiceList(InvoiceListReport {
                    invoices: invoices.into_iter().map(parked_invoice_report).collect(),
                }))
            }
            InvoiceCommand::Decline(args) => {
                let slate_id = SlateId::parse(&args.slate_id).map_err(|_| CliError::SlateId)?;
                let opened = self.open().await?;
                // The declined notice goes out from the payments address.
                opened.epicbox.attach_wallet(&opened.wallet)?;
                opened
                    .wallet
                    .decline_invoice(&opened.epicbox_method(), slate_id)
                    .await?;
                Ok(Report::InvoiceDecline(InvoiceDeclineReport {
                    slate_id: slate_id.to_string(),
                    state: "declined".to_owned(),
                }))
            }
        }
    }

    async fn issue_invoice(&mut self, args: IssueArgs) -> Result<Report, CliError> {
        let amount = parse_amount(&args.amount)?;
        // Any address with a scheme would go over HTTP, whatever else is wrong with it.
        if args
            .destination
            .to
            .as_deref()
            .is_some_and(|address| address.contains("://"))
        {
            return Err(CliError::InvoiceOverHttp);
        }
        let (transport, delivery, destination) = self.delivery(args.destination, false)?;
        let opened = self.open().await?;
        let account = opened.wallet.account(&args.account.account)?;
        if transport == TRANSPORT_ID {
            opened.epicbox.attach_wallet(&opened.wallet)?;
        }
        let method = opened
            .methods
            .get(transport)
            .ok_or(InvoiceError::UnknownTransport { transport })?;
        let file = matches!(delivery, Delivery::Export { .. }).then(|| destination.clone());
        let issued = opened
            .wallet
            .issue_invoice(
                method,
                InvoiceRequest {
                    account: account.index,
                    amount,
                    message: args.message.message,
                    ttl_blocks: None,
                },
                delivery,
            )
            .await?;
        Ok(Report::InvoiceIssue(InvoiceIssueReport {
            tx_id: issued.tx_id.0,
            slate_id: issued.slate_id.to_string(),
            amount: format_amount(issued.amount),
            transport: transport.to_string(),
            destination,
            file,
        }))
    }

    /// Pays a parked invoice over Epicbox, to the address its sender was allowed under.
    async fn pay_parked_invoice(
        &mut self,
        slate_id: SlateId,
        args: PayArgs,
    ) -> Result<Report, CliError> {
        if args.reply.reply_file.is_some() {
            return Err(CliError::ReplyFileForParked);
        }
        let amount = parse_amount(&args.amount)?;
        let spend = Spend::from_args(&args.spend)?;
        let opened = self.open().await?;
        let account = opened.wallet.account(&args.account.account)?;
        let sender = opened
            .wallet
            .pending_invoices(self.settings.invoice_expiry)?
            .into_iter()
            .find(|invoice| invoice.slate_id == slate_id)
            .map(|invoice| invoice.sender.clone())
            .ok_or(InvoiceError::NotParked { slate_id })?;
        opened.epicbox.attach_wallet(&opened.wallet)?;
        let request = spend.pay_request(account.index, amount, args.message.message);
        let epicbox: Arc<dyn Method> = opened.epicbox.clone();
        let paid = opened
            .wallet
            .pay_parked_invoice(&epicbox, slate_id, request)
            .await?;
        Ok(Report::InvoicePay(InvoicePayReport {
            tx_id: paid.tx_id.0,
            slate_id: paid.slate.id().to_string(),
            amount: format_amount(paid.slate.amount()),
            fee: format_fee(paid.slate.fee()),
            transport: TRANSPORT_ID.to_string(),
            destination: sender,
            reply_file: None,
        }))
    }

    async fn pay_invoice_file(&mut self, args: PayArgs) -> Result<Report, CliError> {
        let amount = parse_amount(&args.amount)?;
        let spend = Spend::from_args(&args.spend)?;
        let opened = self.open().await?;
        let account = opened.wallet.account(&args.account.account)?;
        let file = PathBuf::from(&args.invoice);
        check_payment_file(&file)?;
        let files = FileTransport::new();
        let wire = files
            .import(&Location::File(file.clone()))
            .await
            .map_err(slate_file(&file))?;
        let request = spend.pay_request(account.index, amount, args.message.message);
        let paid = opened
            .wallet
            .pay_invoice(&opened.file, &wire, request)
            .await?;
        let reply = args
            .reply
            .reply_file
            .unwrap_or_else(|| response_path(&file));
        refuse_saved_txs(&reply)?;
        let answer = answer_wire(&opened, &wire, &paid.reply)?;
        files
            .export(&answer, &Location::File(reply.clone()))
            .await
            .map_err(slate_file(&reply))?;
        let reply = reply.display().to_string();
        Ok(Report::InvoicePay(InvoicePayReport {
            tx_id: paid.tx_id.0,
            slate_id: paid.slate.id().to_string(),
            amount: format_amount(paid.slate.amount()),
            fee: format_fee(paid.slate.fee()),
            transport: FILE.to_string(),
            destination: reply.clone(),
            reply_file: Some(reply),
        }))
    }

    /// Re-encrypts the vault under a new password.
    async fn change_password(&mut self) -> Result<Report, CliError> {
        let vault = self.settings.data_dir.join(VAULT_FILE);
        if !vault.exists() {
            return Err(WalletError::NoWallet.into());
        }
        let current = self
            .console
            .secrets
            .wallet_password(
                &mut self.console.env,
                self.settings.password_file.as_deref(),
                false,
            )
            .await?;
        let file = self
            .console
            .env
            .get(NEW_PASSWORD_FILE_ENV)
            .map(PathBuf::from);
        let new = self
            .console
            .secrets
            .changed_wallet_password(&mut self.console.env, file.as_deref())
            .await?;
        check_private_dir(&self.settings.data_dir)?;
        let _lock = lock_data_dir(&self.settings.data_dir).await?;
        rekey(self.host.vault_kdf(), &self.settings.data_dir, current, new)
    }

    async fn new_password(&mut self) -> Result<Password, CliError> {
        let password = self
            .console
            .secrets
            .wallet_password(
                &mut self.console.env,
                self.settings.password_file.as_deref(),
                true,
            )
            .await?;
        Ok(password_from(password))
    }

    /// Unlocks the wallet in the data directory. A directory without a vault is reported before
    /// the password is asked for, which would otherwise be typed for nothing.
    async fn open(&mut self) -> Result<Arc<Opened<HostNode<H>>>, CliError> {
        if let Some(held) = &self.held {
            return Ok(Arc::clone(held));
        }
        self.open_fresh().await.map(Arc::new)
    }

    async fn open_fresh(&mut self) -> Result<Opened<HostNode<H>>, CliError> {
        if !self.settings.data_dir.join(VAULT_FILE).exists() {
            return Err(WalletError::NoWallet.into());
        }
        let password = self
            .console
            .secrets
            .wallet_password(
                &mut self.console.env,
                self.settings.password_file.as_deref(),
                false,
            )
            .await?;
        let opened = self.prepare(false).await?;
        opened.wallet.open(password_from(password)).await?;
        start_from_confirmed_tip(&opened.wallet)?;
        Ok(opened)
    }

    /// A locked wallet handle on the data directory, which a new wallet creates.
    async fn prepare(&self, create_dir: bool) -> Result<Opened<HostNode<H>>, CliError> {
        if create_dir {
            create_private_dir(&self.settings.data_dir)?;
        }
        check_private_dir(&self.settings.data_dir)?;
        let lock = lock_data_dir(&self.settings.data_dir).await?;
        let tls = webpki_tls_config().map_err(|error| CliError::Io {
            what: "set up tls for http",
            source: std::io::Error::other(error),
        })?;
        let http = Http::new(RpcClient::new(self.settings.tuning.send, tls.clone()));
        let other_computers = http.through(RpcClient::to_other_computers(
            self.settings.tuning.send,
            tls.clone(),
        ));
        // A native post goes to the host the user named, so it never reaches this computer,
        // whatever the legacy send to the same address may reach.
        let native_post =
            PeerClient::to_other_computers(self.settings.tuning.http_peer(), tls.clone());
        let http_peer = HttpPeer::new(http.clone(), native_post.clone()).to_other_computers_only();
        let http_peer_to_other_computers =
            HttpPeer::new(other_computers.clone(), native_post).to_other_computers_only();
        let http_to_other_computers: Arc<dyn Method> = Arc::new(other_computers);
        let http = Arc::new(http);
        let relay = ClientSettings::new(self.settings.relay.clone(), self.settings.tuning.relay);
        let epicbox = Arc::new(Epicbox::new(
            relay,
            relay_network(self.settings.network),
            self.host.relay_connector(self.settings)?,
        ));
        let tor = Arc::new(Tor::new(lepic_methods::tor::OnionClient::new(
            self.settings.tuning.onion_client(),
        )));
        let tor_peer = TorPeer::new(
            Tor::clone(&tor),
            PeerClient::with_dialer(
                self.settings.tuning.tor_peer(),
                tls,
                tor.peer_dialer(self.settings.tuning.tor_connect),
            ),
        );
        let file: Arc<dyn Method> = Arc::new(FileTransport::new());
        let mut methods = Methods::new();
        for method in [
            Arc::clone(&file),
            Arc::clone(&epicbox) as Arc<dyn Method>,
            Arc::clone(&http) as Arc<dyn Method>,
            Arc::clone(&tor) as Arc<dyn Method>,
        ] {
            methods.register(method)?;
        }
        let methods = Arc::new(methods);
        let rng = system_rng()?;
        let ports = Ports {
            node: self.host.node(self.settings)?,
            stores: CliStores::default(),
            secrets: FileVault::new(&self.settings.data_dir, self.host.vault_kdf()),
            clock: Arc::new(SystemClock),
            rng,
            runtime: tokio::runtime::Handle::current(),
            methods: Some(Arc::clone(&methods) as Arc<dyn MethodLookup>),
        };
        let config = WalletConfig {
            name: WalletName::new(WALLET_NAME).map_err(WalletError::from)?,
            network: self.settings.network,
            data_dir: self.settings.data_dir.clone(),
            node: self.settings.node.clone(),
            policy: lepic_wallet::WalletPolicy {
                refuse_unsolicited_payments: self.settings.refuse_unsolicited_payments,
                refuse_unsolicited_invoices: self.settings.refuse_unsolicited_invoices,
                ..Default::default()
            },
            offline: false,
            host_features: self.settings.host_features,
            profile: self.settings.profile,
            domain: self.settings.domain.clone(),
            native_direct: self.settings.native_direct,
        };
        let wallet = Wallet::new(config, ports)?;
        lepic_wallet_contacts::install(&wallet);
        Ok(Opened {
            wallet,
            methods,
            file,
            epicbox,
            http,
            http_to_other_computers,
            http_peer,
            http_peer_to_other_computers,
            tor,
            tor_peer,
            tor_gate: Arc::new(tokio::sync::Mutex::new(())),
            _lock: lock,
        })
    }

    #[cfg(not(unix))]
    async fn serve(&mut self, _: crate::cli::ServeArgs) -> Result<Report, CliError> {
        Err(CliError::ServiceUnsupported)
    }

    fn data_dir_text(&self) -> String {
        self.settings.data_dir.display().to_string()
    }
}

/// Starts the wallet's node client from the tip the wallet last confirmed, so the first tip a
/// node reports in this command is bounded by how far the chain can have grown since, not only
/// by later answers. Must run before the command's first node request: the client takes the
/// given tip as its reference unconditionally. Clones of a client share what it has seen.
fn start_from_confirmed_tip<T: RpcTransport + Clone + 'static>(
    wallet: &CliWallet<NodeClient<T>>,
) -> Result<(), CliError> {
    let Some(tip) = wallet.confirmed_tip()? else {
        return Ok(());
    };
    let now = wallet.ports().clock.now();
    // A tip stamped after now, from a clock that was ahead, counts as just seen.
    let seen_ago = std::time::Duration::try_from(now.duration_since(tip.seen_at))
        .unwrap_or(std::time::Duration::ZERO);
    let _started = wallet
        .ports()
        .node
        .clone()
        .with_known_tip(tip.height, seen_ago);
    Ok(())
}

/// A random version-4 slate id, drawn as the engine draws one.
fn drawn_slate_id() -> Result<SlateId, CliError> {
    random_bytes().map(SlateId::from_random_bytes)
}

/// A generator seeded from the system's random source.
fn system_rng() -> Result<SharedRng, CliError> {
    let rng = StdRng::try_from_rng(&mut SysRng).map_err(|error| CliError::Io {
        what: "seed the random number generator",
        source: std::io::Error::other(error),
    })?;
    Ok(SharedRng::new(rng))
}

/// Bytes from the system's random source.
fn random_bytes<const N: usize>() -> Result<[u8; N], CliError> {
    let mut rng = StdRng::try_from_rng(&mut SysRng).map_err(|error| CliError::Io {
        what: "seed the random number generator",
        source: std::io::Error::other(error),
    })?;
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// A slate id for `tx send --slate-id`. It travels in the slate, so only a random version-4
/// UUID is taken: one derived from a user or an order id would leak it to the receiver.
fn caller_slate_id(text: &str) -> Result<SlateId, CliError> {
    let slate_id = SlateId::parse(text).map_err(|_| CliError::SlateId)?;
    let bytes = slate_id.as_bytes();
    let version = bytes.get(6).map(|byte| byte >> 4);
    let variant = bytes.get(8).map(|byte| byte & 0xc0);
    if version != Some(4) || variant != Some(0x80) {
        return Err(CliError::NotRandomSlateId);
    }
    Ok(slate_id)
}

/// Where a send goes: through a method, or to a paired contact's mailbox.
enum Payee {
    Delivery(TransportId, Delivery),
    Contact(ContactId),
}

impl Payee {
    /// The transport the send is stored with: a contact's slate leaves as a file to seal.
    const fn transport(&self) -> TransportId {
        match self {
            Self::Delivery(transport, _) => *transport,
            Self::Contact(_) => FILE,
        }
    }
}

/// The report of a send made before under the same slate id: nothing is sent again. A first
/// send with another account, amount, transport or destination is refused, since the caller
/// asked for a payment that was not made. A file export records no destination to compare; a
/// send to a contact compares the contact.
/// The error of a send stopped by an interrupt, naming the transaction it stored if any.
async fn interrupted_send<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    slate_id: Option<SlateId>,
) -> Result<CliError, CliError> {
    let stored = match slate_id {
        Some(slate_id) => opened.wallet.sent_with_slate(slate_id).await?,
        None => None,
    };
    Ok(
        stored.map_or(CliError::Interrupted, |stored| CliError::SendInterrupted {
            tx_id: stored.transaction.id.0,
        }),
    )
}

/// The report of the send made earlier under `slate_id`, if there was one.
async fn repeat_of<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    slate_id: Option<SlateId>,
    account: lepic_store::AccountIndex,
    amount: lepic_primitives::amount::Amount,
    payee: &Payee,
    destination: String,
) -> Result<Option<Report>, CliError> {
    let Some(slate_id) = slate_id else {
        return Ok(None);
    };
    let Some(first) = opened.wallet.sent_with_slate(slate_id).await? else {
        return Ok(None);
    };
    let first_contact = contact::contact_of(opened, first.transaction.id).await?;
    repeated_send(
        &first,
        first_contact,
        slate_id,
        account,
        amount,
        payee,
        destination,
    )
    .map(Some)
}

fn repeated_send(
    first: &TransactionDetails,
    first_contact: Option<ContactId>,
    slate_id: SlateId,
    account: lepic_store::AccountIndex,
    amount: lepic_primitives::amount::Amount,
    payee: &Payee,
    destination: String,
) -> Result<Report, CliError> {
    let entry = &first.transaction.entry;
    let tx_id = first.transaction.id;
    let fee = entry.fee.map_or(0, lepic_primitives::amount::Fee::value);
    let sent = entry
        .amount_debited
        .value()
        .checked_sub(entry.amount_credited.value())
        .and_then(|value| value.checked_sub(fee));
    let to_same = match payee {
        Payee::Delivery(_, Delivery::Deliver { to }) => first.counterparty.as_ref() == Some(to),
        Payee::Delivery(_, Delivery::Export { .. }) => first_contact.is_none(),
        Payee::Contact(id) => first_contact == Some(*id),
    };
    let transport = payee.transport();
    if entry.account != account
        || sent != Some(amount.value())
        || entry.transport.as_deref() != Some(transport.as_str())
        || !to_same
    {
        return Err(CliError::SlateIdReused { tx_id: tx_id.0 });
    }
    Ok(Report::Send(SendReport {
        tx_id: tx_id.0,
        slate_id: slate_id.to_string(),
        amount: format_amount(amount),
        fee: format_units(fee),
        transport: transport.to_string(),
        destination,
        state: state_name(entry.state),
        repeated: true,
        delivered: !first.undelivered,
        dialect: None,
        format: None,
    }))
}

/// The report of a send this run made and delivered.
fn sent_report(
    sent: &SentSlate,
    transport: TransportId,
    destination: String,
    state: &'static str,
    dialect: Option<Dialect>,
) -> Report {
    // A native exchange with a listener stores its S1 as a legacy slate; what went out was
    // native.
    let format = match dialect {
        Some(Dialect::Native) => "native",
        _ => sent.format.as_str(),
    };
    Report::Send(SendReport {
        tx_id: sent.tx_id.0,
        slate_id: sent.slate_id.to_string(),
        amount: format_amount(sent.amount),
        fee: format_fee(sent.fee),
        transport: transport.to_string(),
        destination,
        state,
        repeated: false,
        delivered: true,
        dialect: dialect.map(Dialect::as_str),
        format: Some(format),
    })
}

/// Whether the address the user gave names an onion, valid or not.
pub(crate) fn is_onion(address: &str) -> bool {
    lepic_methods::tor::parse_onion(address).is_ok()
        || address.to_ascii_lowercase().contains(".onion")
}

/// Finalizes the answer of a direct send and posts it: `native`, the answer a native exchange
/// brought back, or else the one the transport kept. Returns the state the send is reported
/// in: `sent` for a transport whose answer comes later.
async fn finalize_direct_reply<N: NodeApi + 'static>(
    opened: &Opened<N>,
    transport: TransportId,
    tx_id: TxId,
    slate_id: &str,
    native: Option<WireSlate>,
    fluff: bool,
) -> Result<&'static str, CliError> {
    let reply = if native.is_some() {
        native
    } else if transport == lepic_methods::http::TRANSPORT_ID {
        opened.http.take_reply(slate_id)
    } else if transport == lepic_methods::tor::TRANSPORT_ID {
        opened.tor.take_reply(slate_id)
    } else {
        return Ok("sent");
    };
    let reply = reply.ok_or(CliError::HttpReplyLost { tx_id: tx_id.0 })?;
    let method = opened
        .methods
        .get(transport)
        .ok_or(FinalizeError::UnknownTransport { transport })?;
    opened
        .wallet
        .finalize(method, &reply, propagation(fluff))
        .await?;
    Ok("posted")
}

/// Detaches and stops the tor a send started.
async fn stop_tor<N: NodeApi + 'static>(opened: &Opened<N>, tor: Option<SendTor>) {
    let Some(tor) = tor else { return };
    opened.tor.detach();
    // Dropping the last handle kills tor at once instead.
    if let Ok(tor) = Arc::try_unwrap(tor.process) {
        tor.stop().await;
    }
}

/// The HTTP payment listener of `http listen` and `serve --http`.
struct HttpListener {
    handle: ListenerHandle,
    counts: Arc<Counts>,
    port: u16,
    exposure: Exposure,
    coinbase: CoinbaseAccess,
}

impl HttpListener {
    /// Binds the listener on the wallet `opened`; a port that cannot be bound is an error.
    async fn start<N: NodeApi + 'static>(
        opened: &Arc<Opened<N>>,
        settings: &Settings,
        args: &HttpListenArgs,
    ) -> Result<Self, CliError> {
        let exposure = if args.internet {
            Exposure::Internet
        } else {
            Exposure::LocalOnly
        };
        let counts = Arc::new(Counts::default());
        let host = Arc::new(CliHost {
            opened: Arc::clone(opened),
            counts: Arc::clone(&counts),
        });
        let method = Arc::clone(&opened.http) as Arc<dyn Method>;
        let peer = peer_endpoint(
            opened,
            settings,
            Arc::clone(&host),
            Arc::clone(&method),
            ProofKey::Payments,
            SealKeyKind::Web,
        )?;
        let receiver = Arc::new(Receiver::new(host, method, ProofKey::Payments));
        let port = args.port.unwrap_or(settings.tuning.listen_port);
        let coinbase = match (args.coinbase, args.coinbase_remote) {
            (_, true) => CoinbaseAccess::Remote,
            (true, false) => CoinbaseAccess::LocalOnly,
            (false, false) => CoinbaseAccess::Off,
        };
        let handle = lepic_methods::http::listen_with(
            ListenSettings::new(exposure, port, settings.tuning.listen).with_coinbase(coinbase),
            receiver,
            peer,
        )
        .await?;
        Ok(Self {
            port: handle.local_addr().port(),
            handle,
            counts,
            exposure,
            coinbase,
        })
    }

    /// What was answered so far.
    fn report(&self) -> HttpListenReport {
        counted(self.port, self.exposure, &self.counts)
    }

    /// Stops the listener once its requests have ended and returns what it answered.
    async fn shutdown(self) -> HttpListenReport {
        self.handle.shutdown().await;
        counted(self.port, self.exposure, &self.counts)
    }
}

fn counted(port: u16, exposure: Exposure, counts: &Counts) -> HttpListenReport {
    HttpListenReport {
        port,
        exposure: exposure.as_str(),
        received: counts.received(),
        repeated: counts.repeated(),
        refused: counts.refused(),
    }
}

/// The listeners of `tor listen`: the current onion's, which serves the native endpoint under
/// the wallet's onion listener key as `cli` allows, and with `previous` the previous onion's,
/// which keeps answering the foreign API alone.
async fn onion_listeners<N: NodeApi + 'static>(
    opened: &Arc<Opened<N>>,
    cli: &Settings,
    host: &Arc<CliHost<N>>,
    previous: bool,
) -> Result<(ListenerHandle, Option<ListenerHandle>), CliError> {
    let settings = lepic_methods::tor::listen_settings(cli.tuning.listen);
    let method = Arc::clone(&opened.tor) as Arc<dyn Method>;
    let receiver = |proof_key| {
        Arc::new(Receiver::new(
            Arc::clone(host),
            Arc::clone(&method),
            proof_key,
        ))
    };
    let peer = peer_endpoint(
        opened,
        cli,
        Arc::clone(host),
        Arc::clone(&method),
        ProofKey::Onion,
        SealKeyKind::Onion,
    )?;
    let handle =
        lepic_methods::http::listen_with(settings, receiver(ProofKey::Onion), peer).await?;
    if !previous {
        return Ok((handle, None));
    }
    match lepic_methods::http::listen(settings, receiver(ProofKey::Payments)).await {
        Ok(previous) => Ok((handle, Some(previous))),
        Err(error) => {
            handle.shutdown().await;
            Err(error.into())
        }
    }
}

/// The native endpoint (ADR 0052) of a listener socket: payments in envelopes sealed to the
/// wallet's listener key of `kind`, received through `host` over `method` as the socket's
/// foreign API receives them, with payment proofs signed by `proof_key`. None unless
/// `native_direct` is set, so the socket answers as a listener without it does: no advert,
/// no native routes.
fn peer_endpoint<N: NodeApi + 'static>(
    opened: &Opened<N>,
    settings: &Settings,
    host: Arc<CliHost<N>>,
    method: Arc<dyn Method>,
    proof_key: ProofKey,
    kind: SealKeyKind,
) -> Result<Option<Arc<PeerEndpoint>>, CliError> {
    if !settings.native_direct {
        return Ok(None);
    }
    let key = opened.wallet.listener_seal_key(kind)?;
    let seal = *key.public_key().as_bytes();
    let network = opened.wallet.config().network;
    let handler = DirectHandler::new(host, method, proof_key, key, network, system_rng()?);
    Ok(Some(Arc::new(PeerEndpoint::new(
        Arc::new(handler),
        seal,
        network,
    ))))
}

/// The wallet behind `http listen` and `tor listen`. Receipts reach the user as the wallet's
/// events.
struct CliHost<N: NodeApi + 'static> {
    opened: Arc<Opened<N>>,
    counts: Arc<Counts>,
}

impl<N: NodeApi + 'static> ReceiveHost for CliHost<N> {
    fn receive(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> BoxFuture<'_, Result<Received, Refusal>> {
        let method = Arc::clone(method);
        let wire = wire.clone();
        Box::pin(async move {
            let received = self
                .opened
                .wallet
                .receive_unsolicited(&method, &wire, request)
                .await;
            received.map_err(|error| {
                let refusal = refuse(&error);
                let error = CliError::from(error);
                tracing::debug!(
                    transport = %method.id(),
                    error = %lepic_telemetry::ErrorChain(&error),
                    "payment refused"
                );
                refusal
            })
        })
    }

    fn build_coinbase(&self, request: CoinbaseRequest) -> BoxFuture<'_, Result<Coinbase, Refusal>> {
        Box::pin(async move {
            self.opened
                .wallet
                .build_coinbase(request)
                .await
                .map_err(|error| {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(&error),
                        "coinbase refused"
                    );
                    Refusal::Unavailable
                })
        })
    }

    fn received(&self, received: &Received) {
        self.counts.count_received(received);
    }

    fn refused(&self, _refusal: Refusal) {
        self.counts.count_refused();
    }
}

/// Refuses a path in a `saved_txs` directory: another Epic wallet keeps its saved
/// transactions there and reads what it finds there as its own.
pub(crate) fn refuse_saved_txs(path: &Path) -> Result<(), CliError> {
    if path
        .parent()
        .is_some_and(|dir| dir.components().any(|part| part.as_os_str() == "saved_txs"))
    {
        return Err(CliError::SavedTxsDir {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// Reads at most the first 64 KiB of the slate file `path` and refuses it unless the
/// classifier of payment files (RFC 0003 5.12) says it is one. A file that cannot be read is
/// left to the slate reader, whose error names it.
fn check_payment_file(path: &Path) -> Result<(), CliError> {
    use std::io::Read as _;
    let mut data = Vec::new();
    let read =
        std::fs::File::open(path).and_then(|file| file.take(64 * 1024).read_to_end(&mut data));
    if read.is_err() {
        return Ok(());
    }
    match lepic_wallet_contacts::payment_file(&data) {
        // A prefix of a long JSON slate may end in the middle; only its first byte counts.
        Ok(_) => Ok(()),
        Err(error) => Err(CliError::Contact(error)),
    }
}

/// Names the slate file in a file transport error, which knows only what failed.
fn slate_file(path: &Path) -> impl FnOnce(TransportError) -> CliError {
    let path = path.to_owned();
    move |source| CliError::SlateFile { path, source }
}

/// A post leaves the transaction `posted` either way; a kernel already on chain is told apart
/// by its own fields, so scripts keep reading `state`.
fn post_report(tx_id: TxId, posted: Posted) -> PostReport {
    let height = match posted {
        Posted::AlreadyOnChain { height } => Some(height.value()),
        Posted::Accepted => None,
    };
    PostReport {
        tx_id: tx_id.0,
        state: "posted".to_owned(),
        already_on_chain: height.is_some(),
        height,
    }
}

/// The line for a transaction a received slate created, or for a slate received before that
/// was answered again.
fn receipt_line(event: &Event) -> Option<String> {
    match event {
        Event::Received(received) => Some(format!(
            "transaction {} received {} EPIC",
            received.tx_id.0,
            format_amount(received.amount)
        )),
        Event::AnsweredAgain(again) => Some(format!(
            "transaction {} answered again; nothing new was received",
            again.tx_id.0
        )),
        Event::InvoiceParked(parked) => Some(format!(
            "invoice {} for {} EPIC parked; `lepic invoice pay {} {}` pays it",
            parked.slate_id,
            format_amount(parked.amount),
            parked.slate_id,
            format_amount(parked.amount)
        )),
        Event::InvoiceFinalized(finalized) => Some(format!(
            "invoice {} paid; transaction {} finalized",
            finalized.slate_id, finalized.tx_id.0
        )),
        Event::InvoiceExpired(expired) => Some(match expired.tx_id {
            Some(tx_id) => format!(
                "invoice {} expired unpaid; transaction {} cancelled",
                expired.slate_id, tx_id.0
            ),
            None => format!(
                "invoice {} expired unpaid and was deleted",
                expired.slate_id
            ),
        }),
        Event::InvoicePosted(posted) => Some(format!(
            "invoice {} posted by the issuer; transaction {} waits for confirmation",
            posted.slate_id, posted.tx_id.0
        )),
        Event::PaymentPosted(posted) => Some(format!(
            "payment {} reported posted by its sender; transaction {} waits for confirmation",
            posted.slate_id, posted.tx_id.0
        )),
        Event::PaymentCancelled(cancelled) => Some(format!(
            "payment {} reported cancelled by its sender; `lepic tx cancel {}` ends it here",
            cancelled.slate_id, cancelled.tx_id.0
        )),
        Event::PaymentDeclined(declined) => Some(format!(
            "payment {} declined by the receiver; transaction {} was cancelled and its inputs \
             are free",
            declined.slate_id, declined.tx_id.0
        )),
        Event::InvoiceDeclined(declined) => Some(format!(
            "invoice {} declined by the payer; `lepic tx cancel {}` withdraws it",
            declined.slate_id, declined.tx_id.0
        )),
        Event::InvoiceWithdrawn(withdrawn) => Some(match withdrawn.tx_id {
            Some(tx_id) => format!(
                "invoice {} withdrawn by the issuer after transaction {} paid it; `lepic tx \
                 cancel {}` gives up on the payment",
                withdrawn.slate_id, tx_id.0, tx_id.0
            ),
            None => format!(
                "invoice {} withdrawn by the issuer and deleted",
                withdrawn.slate_id
            ),
        }),
        Event::InvoiceBounced(bounced) => Some(format!(
            "invoice {} sent back unpaid by {}, which does not pay invoices; `lepic tx cancel {}` \
             withdraws it",
            bounced.slate_id,
            bounced.peer_key.as_deref().unwrap_or(&bounced.peer),
            bounced.tx_id.0
        )),
        _ => None,
    }
}

/// The next event, or never when there is no subscription.
async fn next_event(
    events: &mut Option<broadcast::Receiver<Event>>,
) -> Result<Event, broadcast::error::RecvError> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

/// How often a refresh the chain outgrew while it ran is asked for.
const REFRESH_ATTEMPTS: u32 = 3;

/// How many more refreshes are asked for while the wallet holds the node's tip as
/// pending. One agreeing answer confirms it; a second covers a chain that grew past the bound
/// in between.
const CATCH_UP_REFRESHES: u32 = 2;

/// The lowest height the balances of a refresh were computed at.
fn balances_height(balances: &[Balance]) -> Option<Height> {
    balances.iter().map(|balance| balance.height).min()
}

/// True when a refresh was refused because a block arrived between two of its node requests:
/// an answer from above the tip it read first, or a second tip that differs. Nothing was stored,
/// so asking again is safe, and on a chain with short blocks the race is common. Answers that
/// could not be true at any tip are not retried.
fn chain_moved_during(error: &RefreshError) -> bool {
    match error {
        RefreshError::Implausible(
            ImplausibleNodeData::OutputAboveTip { .. } | ImplausibleNodeData::TipChanged { .. },
        ) => true,
        RefreshError::Implausible(ImplausibleNodeData::KernelOutOfRange {
            height, tip, ..
        }) => height > tip,
        _ => false,
    }
}

/// Refreshes the wallet from the node and returns the outcome with the balances it announced.
/// A refresh the chain outgrew while it ran is asked for again, up to [`REFRESH_ATTEMPTS`]
/// times, and a tip held as pending up to [`CATCH_UP_REFRESHES`] more times.
async fn refreshed<H: Host>(
    opened: &Opened<HostNode<H>>,
) -> Result<(RefreshOutcome, Vec<Balance>), CliError> {
    let mut attempt = 1;
    let mut catch_up = 0;
    loop {
        let mut events = opened.wallet.subscribe();
        let outcome = match opened.wallet.refresh().await {
            Err(error) if attempt < REFRESH_ATTEMPTS && chain_moved_during(&error) => {
                attempt = attempt.saturating_add(1);
                tracing::debug!(attempt, error = %error, "refresh repeated");
                continue;
            }
            outcome => outcome?,
        };
        let mut balances: Vec<Balance> = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let Event::Balance(balance) = event {
                balances.push(balance);
            }
        }
        // A tip too far above the last confirmed one is held until a later answer agrees, and
        // the balances stay at the confirmed height; the next refresh is that answer.
        if let RefreshOutcome::Refreshed(summary) = &outcome
            && balances_height(&balances).is_some_and(|height| height < summary.height)
            && catch_up < CATCH_UP_REFRESHES
        {
            catch_up = catch_up.saturating_add(1);
            tracing::debug!(tip = %summary.height, "refresh repeated for a held tip");
            continue;
        }
        return Ok((outcome, balances));
    }
}

/// The spending options shared by `tx send`, `invoice pay` and `in-person`.
struct Spend {
    minimum_confirmations: u64,
    change_outputs: NonZeroUsize,
    strategy: SelectionStrategy,
    ttl_blocks: Option<u64>,
}

impl Spend {
    fn pay_request(
        self,
        account: lepic_store::AccountIndex,
        amount: lepic_primitives::amount::Amount,
        message: Option<String>,
    ) -> PayRequest {
        PayRequest {
            minimum_confirmations: self.minimum_confirmations,
            change_outputs: self.change_outputs,
            strategy: self.strategy,
            ttl_blocks: self.ttl_blocks,
            message,
            ..PayRequest::new(account, amount)
        }
    }

    fn send_request(
        self,
        account: lepic_store::AccountIndex,
        amount: lepic_primitives::amount::Amount,
        message: Option<String>,
    ) -> SendRequest {
        SendRequest {
            minimum_confirmations: self.minimum_confirmations,
            change_outputs: self.change_outputs,
            strategy: self.strategy,
            ttl_blocks: self.ttl_blocks,
            message,
            ..SendRequest::new(account, amount)
        }
    }

    fn from_args(args: &SpendArgs) -> Result<Self, CliError> {
        Ok(Self {
            minimum_confirmations: args.min_confirmations,
            change_outputs: NonZeroUsize::new(args.change_outputs).ok_or(CliError::Zero {
                what: "--change-outputs",
            })?,
            strategy: match args.selection {
                SelectionArg::All => SelectionStrategy::All,
                SelectionArg::Smallest => SelectionStrategy::Smallest,
            },
            ttl_blocks: args.ttl_blocks,
        })
    }
}

/// Where a pending restore scan starts: genesis, or the start height it was restored with.
fn pending_restore_start(pending: Option<Height>) -> Option<ScanStart> {
    pending.map(|from| {
        if from == Height::ZERO {
            ScanStart::Genesis
        } else {
            ScanStart::Height(from)
        }
    })
}

/// The CLI's view of a stored output. Key ids and derivation paths stay inside the wallet.
fn output_report(details: &OutputDetails) -> OutputReport {
    let output = &details.output;
    OutputReport {
        commitment: output.id.commitment.to_hex(),
        value: format_units(output.amount.value()),
        status: status_name(output.status),
        category: details.category.map(category_name),
        is_coinbase: output.id.features.is_coinbase(),
        height: output.height.value(),
        lock_height: Some(output.lock_height.value()).filter(|height| *height != 0),
        confirmations: details.confirmations,
        tx_id: output.tx.map(|tx| tx.0),
    }
}

const fn status_name(status: OutputStatus) -> &'static str {
    match status {
        OutputStatus::Unconfirmed => "unconfirmed",
        OutputStatus::Unspent => "unspent",
        OutputStatus::Locked => "locked",
        OutputStatus::Spent => "spent",
    }
}

const fn category_name(category: BalanceCategory) -> &'static str {
    match category {
        BalanceCategory::Spendable => "spendable",
        BalanceCategory::AwaitingConfirmation => "awaiting_confirmation",
        BalanceCategory::AwaitingFinalization => "awaiting_finalization",
        BalanceCategory::Immature => "immature",
        BalanceCategory::Locked => "locked",
        BalanceCategory::UnpaidInvoice => "unpaid_invoice",
    }
}

/// The file that answers `incoming`: `reply` sealed to the reply key in the LEPIC marker of a
/// slate a LEPIC wallet wrote (RFC 0002 5, ADR 0052), and `reply` as stored for a slate without
/// one, so a stock wallet reads it.
fn answer_wire<N: NodeApi + 'static>(
    opened: &Opened<N>,
    incoming: &WireSlate,
    reply: &WireSlate,
) -> Result<WireSlate, CliError> {
    let sealed = opened
        .wallet
        .contact_book()
        .sealed_answer_to_marker(incoming, reply)?;
    Ok(match sealed {
        Some(text) => WireSlate::text(reply.media_type(), text),
        None => reply.clone(),
    })
}

/// Receives `wire`, a slate as a file holds it, into `account`.
async fn receive_slate<N: NodeApi + 'static>(
    opened: &Opened<N>,
    wire: &WireSlate,
    account: String,
    message: Option<String>,
) -> Result<Received, CliError> {
    let request = ReceiveRequest {
        account: Some(account),
        message,
        ..ReceiveRequest::default()
    };
    Ok(opened.wallet.receive(&opened.file, wire, request).await?)
}

/// Finalizes `wire`, a reply slate as a file holds it, to a send or to an invoice, and posts it.
async fn finalize_slate<N: NodeApi + 'static>(
    opened: &Opened<N>,
    wire: &WireSlate,
    fluff: bool,
) -> Result<Report, CliError> {
    let propagation = propagation(fluff);
    // A reply sealed to this wallet's reply key (ADR 0052) is armored text.
    let armoured = matches!(
        wire.as_text()
            .map(|text| lepic_wallet_contacts::payment_file(text.as_bytes())),
        Some(Ok(lepic_wallet_contacts::PaymentFile::Armour))
    );
    if armoured {
        let text = wire.as_text().unwrap_or_default();
        let finalized = opened
            .wallet
            .contact_book()
            .sealed_finalize(text, propagation)
            .await?;
        return Ok(Report::Finalize(FinalizeReport {
            tx_id: finalized.tx_id.0,
            slate_id: finalized.slate.id().to_string(),
            state: "posted".to_owned(),
        }));
    }
    // Which flow the slate answers is known only once it is decoded, which the engine does.
    let finalized = match opened
        .wallet
        .finalize(&opened.file, wire, propagation)
        .await
    {
        Err(error @ FinalizeError::WrongStage { .. }) => {
            match opened
                .wallet
                .finalize_invoice(&opened.file, wire, propagation)
                .await
            {
                Err(InvoiceError::WrongStage { .. }) => return Err(error.into()),
                other => other?,
            }
        }
        other => other?,
    };
    Ok(Report::Finalize(FinalizeReport {
        tx_id: finalized.tx_id.0,
        slate_id: finalized.slate.id().to_string(),
        state: "posted".to_owned(),
    }))
}

/// Taken for the whole of a rekey, so two password changes in one process run one after the
/// other: the second reads the vault the first wrote, and its current password is checked
/// against that.
static REKEY: Mutex<()> = Mutex::new(());

/// Re-encrypts the vault in `data_dir` under `new`. Only the vault file changes: the database key
/// comes from the seed (ADR 0032). The caller holds the data directory lock, which keeps other
/// processes out; [`REKEY`] keeps the other requests of serve out. It runs Argon2id twice, so
/// serve calls it off its runtime thread.
fn rekey(
    kdf: KdfParams,
    data_dir: &Path,
    current: Zeroizing<String>,
    new: Zeroizing<String>,
) -> Result<Report, CliError> {
    let _rekeying = REKEY.lock().unwrap_or_else(PoisonError::into_inner);
    FileVault::new(data_dir, kdf)
        .rekey(&password_from(current), &password_from(new))
        .map_err(WalletError::from)?;
    Ok(Report::Password(PasswordReport { changed: true }))
}

fn password_from(mut secret: Zeroizing<String>) -> Password {
    Password::new(std::mem::take(&mut *secret))
}

const fn propagation(fluff: bool) -> Propagation {
    if fluff {
        Propagation::Fluff
    } else {
        Propagation::Stem
    }
}

const fn word_count(words: WordsArg) -> WordCount {
    match words {
        WordsArg::Twelve => WordCount::Twelve,
        WordsArg::Fifteen => WordCount::Fifteen,
        WordsArg::Eighteen => WordCount::Eighteen,
        WordsArg::TwentyOne => WordCount::TwentyOne,
        WordsArg::TwentyFour => WordCount::TwentyFour,
    }
}

const fn relay_network(network: Network) -> RelayNetwork {
    match network {
        Network::Mainnet => RelayNetwork::Mainnet,
        Network::Floonet => RelayNetwork::Floonet,
    }
}

fn read_seed_file(path: &Path) -> Result<String, CliError> {
    let file = std::fs::File::open(path).map_err(CliError::io("read the wallet.seed file"))?;
    let mut text = String::new();
    // One byte over the limit lets the parser refuse the file as too long.
    file.take(
        u64::try_from(MAX_WALLET_SEED_FILE_LEN)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_string(&mut text)
    .map_err(CliError::io("read the wallet.seed file"))?;
    Ok(text)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(CliError::io("create the data directory"))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(dir).map_err(CliError::io("create the data directory"))
}

/// Refuses a data directory that other users can enter or list, since the mode set at creation
/// does not apply to a directory that already existed. A missing directory is left to the wallet
/// to report.
#[cfg(unix)]
fn check_private_dir(dir: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = match std::fs::metadata(dir) {
        Ok(metadata) => metadata.permissions().mode(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CliError::io("inspect the data directory")(error)),
    };
    if mode & 0o077 != 0 {
        return Err(CliError::SharedDataDir);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_dir(_: &Path) -> Result<(), CliError> {
    Ok(())
}

/// The directory lock of `dir`, the same one the mobile binding takes, so a CLI command and an
/// app never open one database at once. A missing data directory holds no wallet to protect and
/// is left to the wallet to report. While the holder copies a plain database into an encrypted
/// one, the copy is waited for.
async fn lock_data_dir(dir: &Path) -> Result<Option<lepic_store::DataDirLock>, CliError> {
    use lepic_store::DataDirLockError;
    match lepic_store::lock_data_dir(dir, MIGRATION_WAIT).await {
        Ok(lock) => Ok(Some(lock)),
        Err(DataDirLockError::Open(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(DataDirLockError::Busy) => Err(in_use(dir).await),
        Err(DataDirLockError::Open(error)) => {
            Err(CliError::io("open the data directory lock")(error))
        }
        Err(DataDirLockError::Lock(error)) => Err(CliError::io("lock the data directory")(error)),
    }
}

/// Why a locked `dir` cannot be opened: the `lepic serve` that answers on its socket, which
/// runs the commands its API has a route for, or another holder.
async fn in_use(dir: &Path) -> CliError {
    #[cfg(unix)]
    if let Some(socket) = crate::through_serve::serving(dir).await {
        return CliError::ServeHoldsWallet { socket };
    }
    CliError::DataDirInUse
}

/// How long a data directory whose holder copies its plain database into an encrypted one is
/// waited for, as the mobile binding waits.
const MIGRATION_WAIT: std::time::Duration = std::time::Duration::from_secs(10 * 60);

fn inbox_report(summary: InboxSummary, expired: Option<InvoiceSweep>) -> InboxReport {
    InboxReport {
        received: summary.received,
        finalized: summary.finalized,
        repeated: summary.repeated,
        rejected: summary.rejected,
        held: summary.held,
        parked: summary.parked,
        bounced: summary.bounced,
        dropped: summary.dropped,
        notices: summary.notices,
        buffered: summary.buffered,
        expired: expired.map(|sweep| ExpiredReport {
            deleted: sweep.deleted.iter().map(ToString::to_string).collect(),
            cancelled: sweep.cancelled.iter().map(|tx_id| tx_id.0).collect(),
            cancellable: sweep.cancellable.iter().map(|tx_id| tx_id.0).collect(),
        }),
    }
}

/// How long an interrupted listen may take to settle the message in hand, as the app's listener
/// gets when it moves to another relay; then the message is abandoned and stays on the relay.
const LISTEN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// Ends a listen once the message in hand is settled and acknowledged, so a stop never leaves a
/// slate handled but unacknowledged, and at once after [`LISTEN_GRACE`].
fn finish_listen(handle: &ListenHandle) {
    handle.finish();
    let handle = handle.clone();
    tokio::spawn(async move {
        tokio::time::sleep(LISTEN_GRACE).await;
        handle.stop();
    });
}

/// How often a listen expires unpaid invoices. Expiry is counted in hours, so a sweep every
/// few minutes keeps it close without loading the store.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Expires unpaid invoices once. A failure, such as the node being unreachable while a payment
/// is checked, is logged and leaves the inbox work to go on; the next sweep tries again.
async fn sweep<N: NodeApi + 'static>(
    wallet: &CliWallet<N>,
    expiry: InvoiceExpiry,
) -> Option<InvoiceSweep> {
    match wallet.sweep_invoices(expiry).await {
        Ok(sweep) => Some(sweep),
        Err(error) => {
            tracing::warn!(error = %lepic_telemetry::ErrorChain(&error), "invoice expiry failed");
            None
        }
    }
}

/// Listens until `handle` stops, and expires unpaid invoices when it starts and every
/// [`SWEEP_INTERVAL`] while it runs. The listen is polled during a sweep, so the relay
/// connection is never left unattended. `swept` collects what every sweep did, and becomes
/// `None` once a sweep fails.
async fn listen_and_sweep<N: NodeApi + 'static>(
    opened: &Opened<N>,
    handle: &ListenHandle,
    expiry: InvoiceExpiry,
    swept: &std::sync::Mutex<Option<InvoiceSweep>>,
) -> Result<InboxSummary, lepic_wallet::inbox::InboxError> {
    let listen = opened.epicbox.listen(&opened.wallet, handle);
    tokio::pin!(listen);
    let mut ticks = tokio::time::interval(SWEEP_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            result = &mut listen => return result,
            _ = ticks.tick() => {
                let once = sweep(&opened.wallet, expiry);
                tokio::pin!(once);
                let outcome = tokio::select! {
                    result = &mut listen => return result,
                    outcome = &mut once => outcome,
                };
                let mut total = swept.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                *total = total.take().zip(outcome).map(|(mut total, more)| {
                    total.deleted.extend(more.deleted);
                    total.cancelled.extend(more.cancelled);
                    total.cancellable.extend(more.cancellable);
                    total.cancellable.sort_unstable();
                    total.cancellable.dedup();
                    total
                });
            }
        }
    }
}

/// The slate id `text` names, when it is one: `invoice pay` then pays a parked invoice. Any
/// other text is a slate file path.
fn parked_slate_id(text: &str) -> Option<SlateId> {
    SlateId::parse(text).ok()
}

fn parked_invoice_report(invoice: IncomingInvoice) -> ParkedInvoiceReport {
    ParkedInvoiceReport {
        slate_id: invoice.slate_id.to_string(),
        sender: invoice.sender,
        amount: format_amount(invoice.amount),
        message: invoice.message,
        received_at: invoice.received_at.to_string(),
        expires_at: invoice.expires_at.to_string(),
    }
}

/// The listing of the service key `service_key`, 66 hex digits, and `generation`.
fn listing_of(
    service_key: &str,
    generation: u32,
) -> Result<lepic_wallet::namespace::Listing, CliError> {
    Ok(lepic_wallet::namespace::Listing::from_hex(
        service_key,
        generation,
    )?)
}

fn show(repos: &dyn Repositories, details: &TransactionDetails) -> Result<TxReport, CliError> {
    let tx = &details.transaction;
    let stages = match tx.entry.slate_id {
        Some(slate_id) => repos
            .slates(slate_id)?
            .iter()
            .map(|slate| stage_name(slate.stage).to_owned())
            .collect(),
        None => Vec::new(),
    };
    Ok(TxReport {
        kernel_excess: details.kernel_excess.map(|excess| excess.to_hex()),
        confirmed_height: details.confirmed_height.map(Height::value),
        releasable_from: details.releasable_from.map(Height::value),
        releasable: details.releasable_from.map(|_| details.releasable),
        sender_reported_posted_at: details.sender_reported_posted_at.map(|at| at.to_string()),
        sender_reported_cancelled_at: details
            .sender_reported_cancelled_at
            .map(|at| at.to_string()),
        receiver_declined_at: details.receiver_declined_at.map(|at| at.to_string()),
        receive_listing: details.receive_listing.map(|listing| ListingReport {
            service_key: listing.service_key().to_hex(),
            generation: listing.generation(),
        }),
        messages: Some(
            details
                .messages
                .iter()
                .map(|message| MessageReport {
                    role: message.role.as_str().to_owned(),
                    text: message.text.clone(),
                })
                .collect(),
        ),
        origin: Some(match details.origin {
            TxOrigin::Wallet => "wallet",
            TxOrigin::Imported => "imported",
            TxOrigin::FoundByScan => "found-by-scan",
            TxOrigin::OtherWallet => "other-wallet",
        }),
        coinbase: details.coinbase.then_some(true),
        imported: details.imported.as_ref().map(|imported| {
            Box::new(ImportedReport {
                source_id: imported.source_id,
                kind: imported_kind_name(imported.kind),
                input_count: imported.input_count,
                output_count: imported.output_count,
                check: chain_check_name(imported.check),
            })
        }),
        ..tx_report(tx, Some(stages))
    })
}

const fn imported_kind_name(kind: ImportedKind) -> &'static str {
    match kind {
        ImportedKind::Coinbase => "coinbase",
        ImportedKind::Received => "received",
        ImportedKind::Sent => "sent",
        ImportedKind::ReceivedCancelled => "received-cancelled",
        ImportedKind::SentCancelled => "sent-cancelled",
        ImportedKind::SentMempool => "sent-mempool",
        ImportedKind::ReceivedMempool => "received-mempool",
        ImportedKind::SentCreated => "sent-created",
    }
}

const fn chain_check_name(check: ChainCheck) -> &'static str {
    match check {
        ChainCheck::Unchecked => "unchecked",
        ChainCheck::OnChain => "on-chain",
        ChainCheck::CancelledButOnChain => "cancelled-but-on-chain",
        ChainCheck::UnspentNotOnChain => "unspent-not-on-chain",
    }
}

const fn import_status_name(status: LegacyImportStatus) -> &'static str {
    match status {
        LegacyImportStatus::Imported => "imported",
        LegacyImportStatus::AlreadyImported => "already-imported",
        LegacyImportStatus::NoHistory => "no-history",
        LegacyImportStatus::OldFormat => "old-format",
        LegacyImportStatus::Unreadable => "unreadable",
        LegacyImportStatus::SourceBusy => "source-busy",
        LegacyImportStatus::TooLarge => "too-large",
        LegacyImportStatus::OtherWallet => "other-wallet",
        LegacyImportStatus::OtherHistory => "other-history",
    }
}

fn tx_report(tx: &StoredTransaction, stages: Option<Vec<String>>) -> TxReport {
    let entry = &tx.entry;
    TxReport {
        tx_id: tx.id.0,
        direction: match entry.direction {
            TxDirection::Outgoing => "outgoing",
            TxDirection::Incoming => "incoming",
        }
        .to_owned(),
        state: state_name(entry.state).to_owned(),
        amount_credited: format_amount(entry.amount_credited),
        amount_debited: format_amount(entry.amount_debited),
        fee: entry.fee.map(format_fee),
        slate_id: entry.slate_id.map(|id| id.to_string()),
        transport: entry.transport.clone(),
        created_at: entry.created_at.to_string(),
        updated_at: entry.updated_at.to_string(),
        stages,
        kernel_excess: None,
        confirmed_height: None,
        releasable_from: None,
        releasable: None,
        messages: None,
        origin: None,
        coinbase: None,
        imported: None,
        sender_reported_posted_at: None,
        sender_reported_cancelled_at: None,
        receiver_declined_at: None,
        receive_listing: None,
    }
}

const fn stage_name(stage: SlateStage) -> &'static str {
    match stage {
        SlateStage::Standard1 => "S1",
        SlateStage::Standard2 => "S2",
        SlateStage::Standard3 => "S3",
        SlateStage::Invoice1 => "I1",
        SlateStage::Invoice2 => "I2",
        SlateStage::Invoice3 => "I3",
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn with_mode(mode: u32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[test]
    fn refuses_an_existing_data_directory_other_users_can_access() {
        for mode in [0o755, 0o750, 0o701] {
            let dir = with_mode(mode);
            assert!(
                matches!(check_private_dir(dir.path()), Err(CliError::SharedDataDir)),
                "{mode:o}"
            );
        }
        check_private_dir(with_mode(0o700).path()).unwrap();
        check_private_dir(&with_mode(0o700).path().join("missing")).unwrap();
    }

    #[test]
    fn tx_post_json_keeps_the_posted_state_and_flags_a_kernel_on_chain() {
        let json = |posted| {
            let report = Report::Post(post_report(TxId(3), posted));
            let rendered = crate::output::render(&report, OutputFormat::Json);
            serde_json::from_str::<serde_json::Value>(&rendered).unwrap()
        };
        assert_eq!(
            json(Posted::Accepted),
            serde_json::json!({"tx_id": 3, "state": "posted", "already_on_chain": false})
        );
        assert_eq!(
            json(Posted::AlreadyOnChain {
                height: lepic_primitives::amount::Height::new(1124)
            }),
            serde_json::json!({
                "tx_id": 3,
                "state": "posted",
                "already_on_chain": true,
                "height": 1124
            })
        );
        let human = |posted| {
            let report = Report::Post(post_report(TxId(3), posted));
            crate::output::render(&report, OutputFormat::Human).to_string()
        };
        assert_eq!(human(Posted::Accepted), "Transaction 3 is posted.\n");
        assert_eq!(
            human(Posted::AlreadyOnChain {
                height: lepic_primitives::amount::Height::new(1124)
            }),
            "Transaction 3 is posted; its kernel is already on chain at height 1124.\n"
        );
    }

    #[test]
    fn a_received_slate_event_becomes_a_receipt_line() {
        let received = Event::Received(lepic_wallet::event::ReceivedTransaction {
            tx_id: TxId(4),
            slate_id: SlateId::from_bytes([4; 16]),
            account: lepic_store::AccountIndex(0),
            amount: lepic_primitives::amount::Amount::new(150_000_000),
            transport: TRANSPORT_ID,
        });
        assert_eq!(
            receipt_line(&received).as_deref(),
            Some("transaction 4 received 1.50000000 EPIC")
        );
        assert_eq!(
            receipt_line(&Event::Session(lepic_wallet::SessionState::Locked)),
            None
        );
    }

    #[test]
    fn a_slate_answered_again_becomes_its_own_line() {
        let again = Event::AnsweredAgain(lepic_wallet::event::AnsweredSlate {
            tx_id: TxId(4),
            slate_id: lepic_wallet::event::SlateId::from_bytes([7; 16]),
            transport: TRANSPORT_ID,
        });
        assert_eq!(
            receipt_line(&again).as_deref(),
            Some("transaction 4 answered again; nothing new was received")
        );
    }

    #[test]
    fn a_bounced_invoice_names_the_invoice_and_its_peer() {
        let peer = EpicboxAddress::parse(
            "esWpjSHdScqVnFSkbM8mPEpzAGBWWSFg4Pu3sKHnqCsKgjzU4YD6@relay.example.org",
            lepic_epicbox::Network::Mainnet,
        )
        .unwrap();
        let bounced = Event::InvoiceBounced(lepic_wallet::event::BouncedInvoice {
            tx_id: TxId(5),
            slate_id: lepic_wallet::event::SlateId::from_bytes([7; 16]),
            peer: peer.to_string(),
            peer_key: None,
        });
        assert_eq!(
            receipt_line(&bounced).as_deref(),
            Some(
                "invoice 07070707-0707-0707-0707-070707070707 sent back unpaid by \
                 esWpjSHdScqVnFSkbM8mPEpzAGBWWSFg4Pu3sKHnqCsKgjzU4YD6@relay.example.org, which \
                 does not pay invoices; `lepic tx cancel 5` withdraws it"
            )
        );
    }

    #[test]
    fn only_a_refresh_the_chain_outgrew_is_asked_again() {
        let height = lepic_primitives::amount::Height::new;
        for moved in [
            ImplausibleNodeData::OutputAboveTip {
                height: height(43),
                tip: height(42),
            },
            ImplausibleNodeData::TipChanged {
                first: height(42),
                second: height(43),
            },
            ImplausibleNodeData::KernelOutOfRange {
                height: height(43),
                min: height(1),
                tip: height(42),
            },
        ] {
            assert!(
                chain_moved_during(&RefreshError::Implausible(moved)),
                "{moved:?}"
            );
        }
        for impossible in [
            ImplausibleNodeData::TipTooHigh {
                tip: height(9_000),
                limit: height(100),
            },
            ImplausibleNodeData::KernelOutOfRange {
                height: height(0),
                min: height(1),
                tip: height(42),
            },
            ImplausibleNodeData::IndexAboveTip { index: 9, limit: 1 },
        ] {
            assert!(
                !chain_moved_during(&RefreshError::Implausible(impossible)),
                "{impossible:?}"
            );
        }
        assert!(!chain_moved_during(&RefreshError::Node(
            lepic_node::NodeError::Timeout
        )));
    }

    #[test]
    fn creating_the_data_directory_leaves_it_owner_only() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("a/b");
        create_private_dir(&dir).unwrap();
        check_private_dir(&dir).unwrap();
    }
}
