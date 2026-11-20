// SPDX-License-Identifier: Apache-2.0
//! Each command: what it asks the engine and what it reports.

use std::future::Future;
use std::io::{Read as _, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use lepic_epicbox::{ClientSettings, EpicboxAddress, Network as RelayNetwork, TRANSPORT_ID};
use lepic_keychain::KdfParams;
use lepic_keychain::vault::MAX_WALLET_SEED_FILE_LEN;
use lepic_methods::epicbox::Epicbox;
use lepic_methods::http::{
    CoinbaseAccess, Counts, Exposure, Host as ReceiveHost, Http, ListenSettings, ListenerHandle,
    ListenerUrl, PlainHttp, Receiver, Refusal, RpcClient, SocketRoute, refuse, webpki_tls_config,
};
use lepic_methods::registry::Methods;
use lepic_methods::tor::{SocksProxy, Tor, TorProcess, TorSettings, TorState};
use lepic_node::{NodeApi, NodeClient, Propagation, RpcTransport};
use lepic_primitives::amount::{Fee, Height};
use lepic_primitives::params::Network;
use lepic_store::{
    ChainCheck, ContactId, ImportedKind, OutboxStatus, OutputStatus, Recovery, RecoveryState,
    Repositories, SlateStage, StoredTransaction, TxDirection, TxId, TxState, WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::file::{FILE, FileTransport, response_path};
use lepic_transport::transport::{BoxFuture, Destination, Exchange as _, Location, TransportId};
use lepic_wallet::chain::ImplausibleNodeData;
use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};
use lepic_wallet::details::TransactionDetails;
use lepic_wallet::epicbox_invoice::{IncomingInvoice, InvoiceExpiry, InvoiceSweep};
use lepic_wallet::error_text::{display_error_chain, node_text};
use lepic_wallet::event::{Balance, SlateId};
use lepic_wallet::finalize::{FinalizeError, Posted};
use lepic_wallet::inbox::{InboxSummary, ListenHandle};
use lepic_wallet::invoice::{InvoiceError, InvoiceRequest, PayRequest};
use lepic_wallet::legacy_history::{ImportWorkDir, LegacyImportStatus, TxOrigin};
use lepic_wallet::method::{Method, MethodLookup};
use lepic_wallet::refresh::{BalanceCategory, OutputDetails, RefreshError, RefreshOutcome};
use lepic_wallet::relay_cancel::RelayCancelResult;
use lepic_wallet::scan::{ScanCancel, ScanOptions, ScanStart, ScanSummary};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::self_send::SELF;
use lepic_wallet::send::{Delivery, SendError, SendRequest, SentSlate};
use lepic_wallet::slate::WireSlate;
use lepic_wallet::state::{InvalidTransition, state_name};
use lepic_wallet::{
    Event, Password, Ports, ProofKey, ReceiveRequest, Received, SharedRng, Wallet, WalletConfig,
    WalletError, WalletName, WordCount,
};
use lepic_wallet_contacts::{
    DirectHandler, InboxRoute, PaymentPost, PeerDialer, WalletContacts as _,
};
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
    ScanArgs, SelectionArg, SendArgs, SendDestinationArgs, SpendArgs, StartOverArgs,
    TorAddressArgs, TorBinaryArgs, TorCommand, TorListenArgs, TxCommand, UpdateArg, WalletCommand,
    WalletScanArgs, WordsArg,
};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{
    AccountReport, AddressReport, CancelReport, EpicboxStatusReport, ExpiredReport, FinalizeReport,
    HttpListenReport, ImportHistoryReport, ImportedReport, InboxReport, InfoReport, InitReport,
    InvoiceIssueReport, InvoiceListReport, InvoicePayReport, ListingReport, MessageReport,
    NodeStatusReport, OutputReport, OutputsReport, ParkedInvoiceReport, PasswordReport, PostReport,
    ReceiveReport, RecoverReport, Report, ResendReport, RestoreReport, ScanReport, SendReport,
    TorAddressReport, TorListenReport, TxDeliveryReport, TxListReport, TxRecoveryReport, TxReport,
    WalletScanReport, printable, recovery_state_name,
};
use crate::progress::Progress;
use crate::secret::NEW_PASSWORD_FILE_ENV;
use crate::settings::{OutputFormat, Settings};
use crate::stores::{CliStores, SharedStore};
use crate::vault::{FileVault, VAULT_FILE};

mod api_client;
mod backup;
mod consolidate;
mod contact;
mod epic1;
#[cfg(unix)]
pub(crate) mod files;
mod in_person;
mod mailbox;
mod profile;
#[cfg(unix)]
mod serve;
pub(crate) mod shell;

/// The directory inside the data directory that holds the wallet's tor files.
const TOR_DIR: &str = "tor";

/// Every CLI wallet has this name in logs; one data directory holds one wallet.
const WALLET_NAME: &str = "default";

type CliWallet<N> = Wallet<N, CliStores, FileVault>;

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
    /// Holds the answers of Tor sends until they are finalized.
    tor: Arc<Tor>,
    /// Taken by a send over Tor for as long as its tor is attached to [`Self::tor`], which only
    /// one send at a time can use.
    tor_gate: Arc<tokio::sync::Mutex<()>>,
    /// Wakes the watch that puts the mailboxes of pairings serve started on its push sessions.
    pairing_claims: contact::PairingClaims,
    /// Reaches the `tor` entries of links through the relay's tor; `None` with Tor off.
    peer_dialer: Option<Arc<dyn PeerDialer>>,
    /// Why this command makes no connection, from `connection_mode`; `None` when it may.
    offline: Option<crate::settings::OfflineReason>,
    /// Whether a route that would connect directly is refused, as
    /// [`Settings::refuses_direct`] says.
    refuses_direct: bool,
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

    /// The method of a send over `transport`, over HTTP only to the computers `reach` allows.
    fn route(
        &self,
        transport: TransportId,
        reach: HttpReach,
    ) -> Result<&Arc<dyn Method>, SendError> {
        match reach {
            HttpReach::OtherComputers if transport == lepic_methods::http::TRANSPORT_ID => {
                Ok(&self.http_to_other_computers)
            }
            _ => self.send_method(transport),
        }
    }
}

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
    /// What the shell's review showed of the send this run makes.
    reviewed: Option<Reviewed>,
}

/// The amount and fee the shell's review of a send showed. The send checks them again before it
/// stores anything, and refuses one that would take more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reviewed {
    pub(crate) amount: u64,
    pub(crate) fee: u64,
}

impl Reviewed {
    /// Whether a send of `amount` with `fee` is the one reviewed: the same amount, a fee no
    /// higher.
    pub(crate) fn check(self, amount: u64, fee: u64) -> Result<(), CliError> {
        if amount == self.amount && fee <= self.fee {
            return Ok(());
        }
        Err(CliError::ReviewChanged {
            reviewed: self.amount.saturating_add(self.fee),
            total: amount.saturating_add(fee),
        })
    }
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
        reviewed: None,
    };
    // Boxed: every command's state machine is folded into this one future, which would
    // otherwise sit on the caller's stack.
    let result = tokio::select! {
        result = Box::pin(run.dispatch(command)) => result,
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
            Command::Node(NodeCommand::Status) => self.node_status().await,
            Command::Contact(args) => self.contact(args).await,
            Command::InPerson(args) => self.in_person(args).await,
            Command::Epic1(args) => self.epic1(args).await,
            Command::Epictx(command) => self.epictx(command).await,
            Command::Mailbox(command) => self.mailbox(command).await,
            Command::Profile(command) => self.profile(command).await,
            Command::Serve(args) => self.serve(args).await,
            Command::Api(ApiCommand::Client(command)) => self.api_client(command),
            Command::Shell => Err(CliError::Arguments("the shell is open already".to_owned())),
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

    /// With human output, a line on stderr for each invoice event `events` holds: what
    /// `epicbox drain` or `contact collect` finalized or expired.
    fn show_invoice_events(&mut self, mut events: broadcast::Receiver<Event>) {
        if self.settings.output != OutputFormat::Human {
            return;
        }
        while let Ok(event) = events.try_recv() {
            if matches!(
                event,
                Event::InvoiceFinalized(_)
                    | Event::InvoiceExpired(_)
                    | Event::InvoicePosted(_)
                    | Event::InvoiceDeclined(_)
                    | Event::InvoiceWithdrawn(_)
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
            WalletCommand::Info(args) => self.info(&args).await,
            WalletCommand::Scan(args) => self.scan(&args).await,
            WalletCommand::ImportHistory(args) => self.import_history(&args).await,
            WalletCommand::Consolidate(args) => self.consolidate(args).await,
            WalletCommand::StartOver(args) => self.start_over(&args).await,
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
            WalletCommand::Backup(args) => self.backup(&args).await,
            WalletCommand::Address(_) => {
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
                // Cancelling an invoice issued to a paired contact tells that contact it is
                // withdrawn.
                opened.epicbox.attach_wallet(&opened.wallet)?;
                let tx_id = TxId(args.tx.tx_id);
                let relay = if args.local_only {
                    None
                } else {
                    relay_cancel(&opened, tx_id).await
                };
                if let Err(error) = opened.wallet.cancel(tx_id).await {
                    return Err(cancel_error(&opened, tx_id, error).await);
                }
                Ok(Report::Cancel(CancelReport {
                    tx_id: tx_id.0,
                    state: "cancelled".to_owned(),
                    relay: relay.as_ref().map(|outcome| outcome.name().to_owned()),
                    relay_error: relay.and_then(RelayAsk::into_error),
                }))
            }
            TxCommand::Recover(args) => {
                let opened = self.open().await?;
                let recovery = opened.wallet.recover(TxId(args.tx_id)).await?;
                recover_report(recovery).map(Report::Recover)
            }
            TxCommand::List(args) => {
                let opened = self.open().await?;
                if args.refresh.update.update {
                    updated::<H>(&opened).await?;
                } else if args.refresh.refresh {
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
                if args.refresh.update.update {
                    updated::<H>(&opened).await?;
                } else if args.refresh.refresh {
                    refreshed::<H>(&opened).await?;
                }
                let details = match (args.tx_id, slate_id) {
                    (Some(tx_id), _) => opened.wallet.transaction_details(TxId(tx_id)).await?,
                    (None, Some(Ok(slate_id))) => {
                        match opened.wallet.sent_with_slate(slate_id).await? {
                            Some(details) => details,
                            None => return Err(declined_or_none(&opened, slate_id).await?),
                        }
                    }
                    (None, Some(Err(_))) => return Err(CliError::SlateId),
                    (None, None) => return Err(CliError::NoSendWithSlate),
                };
                let post = outbox_post(&opened, &details).await?;
                let report = opened
                    .store()?
                    .read(|repos| show(repos, &details, post.as_ref()))?;
                Ok(Report::Show(report))
            }
        }
    }

    async fn epicbox(&mut self, command: EpicboxCommand) -> Result<Report, CliError> {
        // Offline the listener could only retry a relay it may not reach, until interrupted.
        if matches!(command, EpicboxCommand::Listen)
            && let Some(reason) = self.settings.offline()
        {
            return Err(CliError::Offline { reason });
        }
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
                // A sweep that cancels an invoice issued to a paired contact sends its
                // `withdrawn` notice to that contact's mailbox.
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
                        listen_and_sweep(
                            &opened,
                            opened.epicbox.listen(&opened.wallet, &handle),
                            expiry,
                            &swept,
                        ),
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

    async fn info(&mut self, args: &UpdateArg) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let (outcome, balances) = if args.update {
            updated::<H>(&opened).await?
        } else {
            refreshed::<H>(&opened).await?
        };
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

    #[allow(clippy::too_many_lines)] // One send from its arguments to its report, in order.
    async fn send(&mut self, args: SendArgs) -> Result<Report, CliError> {
        let amount = parse_amount(send_amount(&args)?)?;
        // The default cutoff is kept by this wallet, not in the slate, so the send can still be
        // delivered again over a transport whose format has no TTL (`tx resend`).
        let spend =
            Spend::from_args(&args.spend)?.with_default_local_ttl(self.settings.send_ttl_blocks);
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
            // The fee the review showed binds the send itself, which selects again in its own
            // store transaction: a fee that rose since the check below refuses the send there.
            max_fee: self.reviewed.map(|reviewed| Fee::new(reviewed.fee)),
            ..spend.send_request(account.index, amount, args.message.message)
        };
        if self.reviewed.is_some() || transport == lepic_methods::tor::TRANSPORT_ID {
            // The checks the send makes before it stores anything, before tor takes its time
            // to connect for a send that cannot be made. A reviewed send is checked against its
            // review here.
            let selection = opened
                .wallet
                .estimate_fee(request.amount, request.selection_options())
                .await?;
            if let Some(reviewed) = self.reviewed {
                reviewed.check(selection.amount.value(), selection.fee.value())?;
            }
        }
        let tor = self.tor_for(transport, &args.tor, &opened).await?;
        // From here the send may store its transaction, so an interrupt ends it here and reports
        // the transaction it stored, which the caller can then resend or cancel.
        let sent_slate = request.slate_id;
        self.graceful.store(true, Ordering::SeqCst);
        let mut interrupt = self.interrupt.clone();
        let purpose = args.purpose.map(contact::purpose);
        let sending = async {
            let sent = match &payee {
                Payee::Delivery(_, delivery) => {
                    let method = opened.route(transport, args.reach)?;
                    opened
                        .wallet
                        .send(method, request, delivery.clone())
                        .await?
                }
                Payee::Contact(id) => {
                    contact::send_to_contact(&opened, *id, request, purpose, self.settings).await?
                }
            };
            let state = finalize_direct_reply(
                &opened,
                transport,
                sent.tx_id,
                &sent.slate_id.to_string(),
                args.fluff.fluff,
            )
            .await?;
            Ok::<_, CliError>((sent, state))
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
            // Only a reviewed send has a maximum fee, which is the reviewed fee, on the
            // reviewed amount.
            (Err(CliError::Send(SendError::FeeAboveMaximum { fee, max_fee })), _) => {
                return Err(CliError::ReviewChanged {
                    reviewed: amount.value().saturating_add(max_fee.value()),
                    total: amount.value().saturating_add(fee.value()),
                });
            }
            (sending, _) => sending,
        };
        let (sent, state) = sending?;
        let post = match &payee {
            Payee::Contact(_) => {
                opened
                    .wallet
                    .contact_book()
                    .payment_post(sent.slate_id)
                    .await?
            }
            Payee::Delivery(..) => None,
        };
        Ok(sent_report(
            &sent,
            payee.reported_transport(),
            destination,
            state,
            post,
        ))
    }

    async fn resend(&mut self, args: ResendArgs) -> Result<Report, CliError> {
        let (transport, delivery, destination) = delivery_to(
            self.settings,
            args.destination,
            args.plain_http.allow_plain_http,
        )?;
        let opened = self.open().await?;
        if transport == TRANSPORT_ID {
            opened.epicbox.attach_wallet(&opened.wallet)?;
        }
        let tx_id = TxId(args.tx.tx_id);
        let tor = self.tor_for(transport, &args.tor, &opened).await?;
        let resending = async {
            let method = opened.send_method(transport)?;
            opened.wallet.resend(method, tx_id, delivery).await?;
            if !lepic_methods::http::is_direct(transport) {
                return Ok("sent");
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
                args.fluff.fluff,
            )
            .await?;
            Ok::<_, CliError>(state)
        }
        .await;
        stop_tor(&opened, tor).await;
        Ok(Report::Resend(ResendReport {
            tx_id: tx_id.0,
            transport: transport.to_string(),
            destination,
            state: resending?,
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
        if let Some(reason) = self.settings.offline() {
            return Err(CliError::Offline { reason });
        }
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
        let (transport, delivery, destination) = delivery_to(
            self.settings,
            DestinationArgs { to, to_file },
            allow_plain_http,
        )?;
        Ok((Payee::Delivery(transport, delivery), destination))
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
        files
            .export(&received.reply, &Location::File(reply.clone()))
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
            InvoiceCommand::Pay(args) => self.pay_invoice_file(args).await,
            InvoiceCommand::List => {
                let opened = self.open().await?;
                let invoices = opened
                    .wallet
                    .pending_invoices(self.settings.invoice_expiry)?;
                Ok(Report::InvoiceList(InvoiceListReport {
                    invoices: invoices.into_iter().map(parked_invoice_report).collect(),
                }))
            }
        }
    }

    async fn issue_invoice(&mut self, args: IssueArgs) -> Result<Report, CliError> {
        let amount = parse_amount(&args.amount)?;
        // A classic address carries stock slates only; an invoice goes as a file.
        if args.destination.to.is_some() {
            return Err(CliError::InvoiceToAddress);
        }
        let slate_id = args
            .slate_id
            .slate_id
            .as_deref()
            .map(caller_slate_id)
            .transpose()?;
        let (transport, delivery, destination) =
            delivery_to(self.settings, args.destination, false)?;
        let opened = self.open().await?;
        let account = opened.wallet.account(&args.account.account)?;
        let method = opened
            .methods
            .get(transport)
            .ok_or(InvoiceError::UnknownTransport { transport })?;
        let file = matches!(delivery, Delivery::Export { .. }).then(|| destination.clone());
        let issued = opened
            .wallet
            .issue_invoice_as(
                method,
                InvoiceRequest {
                    account: account.index,
                    amount,
                    message: args.message.message,
                    ttl_blocks: args.ttl_blocks,
                },
                delivery,
                slate_id,
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
        if !args.yes
            && let Some(request) =
                invoice_file_request(&opened, self.settings.network, &file, &wire, amount)
        {
            self.ask_to_pay("invoice pay", &request).await?;
        }
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
        files
            .export(&paid.reply, &Location::File(reply.clone()))
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

    /// Shows `request`, an invoice read from a file, and asks whether to pay it. Without a
    /// terminal it is not paid: `command` fails with [`CliError::InvoicePayUnasked`].
    async fn ask_to_pay(&mut self, command: &'static str, request: &str) -> Result<(), CliError> {
        if !(self.console.secrets.is_terminal() && self.console.stdout_terminal) {
            return Err(CliError::InvoicePayUnasked { command });
        }
        let shown = self
            .console
            .stderr
            .write_all(request.as_bytes())
            .and_then(|()| self.console.stderr.flush());
        shown.map_err(|source| CliError::Io {
            what: "show the invoice",
            source,
        })?;
        if crate::shell::ask::yes("Pay this invoice? [y/N] ".to_owned()).await {
            Ok(())
        } else {
            Err(CliError::InvoicePayDeclined)
        }
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

    /// Opens the wallet with a new, empty database where a damaged one was set aside, then
    /// scans the chain as a restore does.
    async fn start_over(&mut self, args: &StartOverArgs) -> Result<Report, CliError> {
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
        opened.wallet.start_over(password_from(password)).await?;
        self.restored(&opened, &args.scan).await
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
        let http_to_other_computers: Arc<dyn Method> = Arc::new(other_computers);
        let http = Arc::new(http);
        let relay = ClientSettings::new(self.settings.relay.clone(), self.settings.tuning.relay);
        let epicbox = Arc::new(Epicbox::new(
            relay,
            relay_network(self.settings.network),
            self.host.relay(self.settings)?,
        ));
        let tor = Arc::new(Tor::new(lepic_methods::tor::OnionClient::new(
            self.settings.tuning.onion_client(),
        )));
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
            clock: self.host.clock(),
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
                max_open_receipts: self.settings.max_open_receipts,
                max_open_receipts_per_sender: self.settings.max_open_receipts_per_sender,
                refuse_unsolicited_payments: self.settings.refuse_unsolicited_payments,
                refuse_unsolicited_invoices: self.settings.refuse_unsolicited_invoices,
                ..Default::default()
            },
            offline: self.settings.offline().is_some(),
            host_features: self.settings.host_features,
            profile: self.settings.profile,
            domain: self.settings.domain.clone(),
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
            tor,
            tor_gate: Arc::new(tokio::sync::Mutex::new(())),
            pairing_claims: contact::PairingClaims::default(),
            peer_dialer: self.host.peer_dialer(self.settings),
            offline: self.settings.offline(),
            refuses_direct: self.settings.refuses_direct(),
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

/// The amount of `send`, which only a send to an epic1 link may leave out.
fn send_amount(send: &SendArgs) -> Result<&str, CliError> {
    send.amount.as_deref().ok_or_else(|| {
        CliError::Arguments(
            "AMOUNT is required unless --to is an epic1 link that asks an amount".to_owned(),
        )
    })
}

/// A random version-4 slate id, drawn as the engine draws one.
pub(crate) fn drawn_slate_id() -> Result<SlateId, CliError> {
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
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CliError> {
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
pub(crate) fn caller_slate_id(text: &str) -> Result<SlateId, CliError> {
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

    /// The transport a report names: a payment to a contact goes through its mailbox, which no
    /// transport id says.
    fn reported_transport(&self) -> String {
        match self {
            Self::Delivery(transport, _) => transport.to_string(),
            Self::Contact(_) => "contact".to_owned(),
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

/// [`CliError::PaymentDeclined`] when the payee declined the send under `slate_id`, which the
/// wallet erased.
async fn declined_send<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    slate_id: SlateId,
) -> Result<Option<CliError>, CliError> {
    let at = opened.wallet.send_declined_at(slate_id).await?;
    Ok(at.map(|at| CliError::PaymentDeclined {
        slate_id: slate_id.to_string(),
        declined_at: at.to_string(),
    }))
}

/// What `tx show --slate-id` answers when no send is stored under the id: the decline, or none.
async fn declined_or_none<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    slate_id: SlateId,
) -> Result<CliError, CliError> {
    Ok(declined_send(opened, slate_id)
        .await?
        .unwrap_or(CliError::NoSendWithSlate))
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
        // A declined send was erased, but its slate id stays spent.
        if let Some(declined) = declined_send(opened, slate_id).await? {
            return Err(declined);
        }
        return Ok(None);
    };
    let first_contact = contact::contact_of(opened, first.transaction.id).await?;
    let post = outbox_post(opened, &first).await?;
    repeated_send(
        &first,
        post.as_ref(),
        first_contact,
        slate_id,
        account,
        amount,
        payee,
        destination,
    )
    .map(Some)
}

/// How the contact outbox stands for an outgoing send still `sent`; `None` for any other
/// transaction or a send the outbox holds no row of. A send to a contact is queued there, not
/// in the wallet's own outbox, so `TransactionDetails::undelivered` does not see it.
async fn outbox_post<N: lepic_node::NodeApi + 'static>(
    opened: &Opened<N>,
    details: &TransactionDetails,
) -> Result<Option<PaymentPost>, CliError> {
    use lepic_store::{TxDirection, TxState};
    let entry = &details.transaction.entry;
    let (TxDirection::Outgoing, TxState::Sent, Some(slate_id)) =
        (entry.direction, entry.state, entry.slate_id)
    else {
        return Ok(None);
    };
    let slate_id = SlateId::from_bytes(slate_id.into_bytes());
    Ok(opened.wallet.contact_book().payment_post(slate_id).await?)
}

/// What a stored send paid the other party: debited less change and fee.
pub(super) fn amount_sent(first: &TransactionDetails) -> Option<u64> {
    let entry = &first.transaction.entry;
    let fee = entry.fee.map_or(0, lepic_primitives::amount::Fee::value);
    entry
        .amount_debited
        .value()
        .checked_sub(entry.amount_credited.value())
        .and_then(|value| value.checked_sub(fee))
}

#[allow(clippy::too_many_arguments)] // The report names every part of the send it repeats.
fn repeated_send(
    first: &TransactionDetails,
    post: Option<&PaymentPost>,
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
    let sent = amount_sent(first);
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
        transport: payee.reported_transport(),
        destination,
        state: state_name(entry.state),
        repeated: true,
        delivered: !first.undelivered && post.is_none_or(|post| post.delivered),
        reason: post.and_then(|post| post.reason.clone()),
        next_attempt_at: post.and_then(|post| post.next_at).map(|at| at.to_string()),
        format: None,
        slate_bytes: None,
        slate_limit: None,
    }))
}

/// The report of a send this run made. `post` is how the outbox stands for a send to a
/// contact; a send through a method has none and is delivered when it returns. A contact send
/// the outbox holds no row of is taken as delivered: its rows were posted and pruned.
fn sent_report(
    sent: &SentSlate,
    transport: String,
    destination: String,
    state: &'static str,
    post: Option<PaymentPost>,
) -> Report {
    let undelivered = post.filter(|post| !post.delivered);
    Report::Send(SendReport {
        tx_id: sent.tx_id.0,
        slate_id: sent.slate_id.to_string(),
        amount: format_amount(sent.amount),
        fee: format_fee(sent.fee),
        transport,
        destination,
        state,
        repeated: false,
        delivered: undelivered.is_none(),
        reason: undelivered.as_ref().and_then(|post| post.reason.clone()),
        next_attempt_at: undelivered
            .as_ref()
            .and_then(|post| post.next_at)
            .map(|at| at.to_string()),
        format: Some(sent.format.as_str()),
        slate_bytes: sent.slate_bytes,
        slate_limit: sent.slate_limit,
    })
}

/// Where a first slate goes, the method it goes through, and how the report names it. An address is parsed here,
/// before the wallet stores anything: a send to an address that cannot be delivered to
/// would leave a transaction behind with its inputs locked. An address with a scheme is a
/// listening wallet's HTTP endpoint; plain HTTP to another computer needs
/// `allow_plain_http`.
pub(crate) fn delivery_to(
    settings: &Settings,
    destination: DestinationArgs,
    allow_plain_http: bool,
) -> Result<(TransportId, Delivery, String), CliError> {
    // A chat app may have made the address a link; it is still the Epicbox address.
    let destination = DestinationArgs {
        to: destination.to.map(|to| {
            lepic_transport::epicbox_link::epicbox_of_link(&to).map_or(to.clone(), str::to_owned)
        }),
        ..destination
    };
    if destination.to.is_some()
        && let Some(reason) = settings.offline()
    {
        return Err(CliError::Offline { reason });
    }
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
            // ADR 0021: this computer stays direct; any other payee would bypass the tor.
            if settings.refuses_direct() && !lepic_node::is_loopback_host(url.host()) {
                return Err(CliError::TorExpected {
                    route: "the http payee",
                });
            }
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
                relay_network(settings.network),
                &settings.servers.default_epicbox_domain,
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

/// Whether the address the user gave names an onion, valid or not.
pub(crate) fn is_onion(address: &str) -> bool {
    lepic_methods::tor::parse_onion(address).is_ok()
        || address.to_ascii_lowercase().contains(".onion")
}

/// Finalizes the answer of a direct send, the one the transport kept, and posts it. Returns the
/// state the send is reported in: `sent` for a transport whose answer comes later.
async fn finalize_direct_reply<N: NodeApi + 'static>(
    opened: &Opened<N>,
    transport: TransportId,
    tx_id: TxId,
    slate_id: &str,
    fluff: bool,
) -> Result<&'static str, CliError> {
    let reply = if transport == lepic_methods::http::TRANSPORT_ID {
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
    #[cfg(unix)]
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
            Arc::clone(&host),
            Arc::clone(&method),
            ListenerSocket::Web.serves_epic1(settings),
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
            #[cfg(unix)]
            coinbase,
        })
    }

    /// What was answered so far.
    #[cfg(unix)]
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

/// The listeners of `tor listen`: the current onion's, which serves the inbox route as `cli`
/// allows, and with `previous` the previous onion's, which keeps answering the foreign API
/// alone.
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
        Arc::clone(host),
        Arc::clone(&method),
        ListenerSocket::Onion.serves_epic1(cli),
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

/// The two kinds of payment listener socket, each with its own switch for the inbox route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerSocket {
    /// The socket of `http listen` and `serve --http`.
    Web,
    /// The current onion's socket of `tor listen`.
    Onion,
}

impl ListenerSocket {
    /// Whether `settings` let this socket serve the inbox route: `epic1_web_listener` for the
    /// web socket, `epic1_onion_listener` for the onion socket, and nothing else.
    fn serves_epic1(self, settings: &Settings) -> bool {
        match self {
            Self::Web => settings.epic1_web_listener,
            Self::Onion => settings.epic1_onion_listener,
        }
    }
}

/// The inbox route of a listener socket: payments in envelopes sealed to the wallet's epic1
/// addresses, received through `host` over `method` as the socket's foreign API receives them.
/// None unless `epic1` (`epic1_web_listener` or `epic1_onion_listener` for the socket), so the
/// socket answers as a stock listener does.
fn peer_endpoint<N: NodeApi + 'static>(
    opened: &Opened<N>,
    host: Arc<CliHost<N>>,
    method: Arc<dyn Method>,
    epic1: bool,
) -> Result<Option<Arc<dyn SocketRoute>>, CliError> {
    if !epic1 {
        return Ok(None);
    }
    let network = opened.wallet.config().network;
    let epic1_keys = Arc::clone(&host) as Arc<dyn lepic_wallet_contacts::Epic1Keys>;
    let handler = DirectHandler::new(host, method, network, system_rng()?).with_epic1(epic1_keys);
    Ok(Some(Arc::new(InboxRoute::new(Arc::new(handler)))))
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
                if refusal == Refusal::OpenReceipts {
                    tracing::info!(
                        transport = %method.id(),
                        "payment refused at the open receipt cap"
                    );
                } else {
                    tracing::debug!(
                        transport = %method.id(),
                        error = %lepic_telemetry::ErrorChain(&error),
                        "payment refused"
                    );
                }
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

impl<N: NodeApi + 'static> lepic_wallet_contacts::Epic1Keys for CliHost<N> {
    fn epic1_keys(&self) -> BoxFuture<'_, Vec<lepic_wallet::Epic1AccountKeys>> {
        Box::pin(async move {
            match self.opened.wallet.epic1_trial_keys_all().await {
                Ok(keys) => keys,
                Err(error) => {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(&error),
                        "epic1 keys not read"
                    );
                    Vec::new()
                }
            }
        })
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
/// What the Epicbox relay said when `tx cancel` asked it to cancel a transaction.
enum RelayAsk {
    /// The relay answered.
    Answered(RelayCancelResult),
    /// The ask failed; the message says why. The local cancel runs anyway.
    Failed(String),
}

impl RelayAsk {
    /// The outcome as the report names it.
    fn name(&self) -> &'static str {
        match self {
            Self::Answered(RelayCancelResult::Cancelled) => "cancelled",
            Self::Answered(RelayCancelResult::NotFoundOrNotParticipant) => {
                "not_found_or_not_participant"
            }
            Self::Answered(RelayCancelResult::NoRelayId) => "no_relay_id",
            Self::Answered(_) => "unsupported",
            Self::Failed(_) => "failed",
        }
    }

    /// Why the ask failed, when it did.
    fn into_error(self) -> Option<String> {
        match self {
            Self::Answered(_) => None,
            Self::Failed(message) => Some(message),
        }
    }
}

/// Asks the Epicbox relay to cancel `tx_id` for both parties, when the transaction was filed
/// there under a relay id and is still open. `None` when there is nothing to ask: no relay id,
/// already posted or ended, or a transaction this wallet cannot read, whose error the local
/// cancel then reports. A failed ask comes back as [`RelayAsk::Failed`] so the local cancel
/// still runs.
async fn relay_cancel<N: NodeApi + 'static>(opened: &Opened<N>, tx_id: TxId) -> Option<RelayAsk> {
    let details = opened.wallet.transaction_details(tx_id).await.ok()?;
    if !details.relay_cancellable {
        return None;
    }
    Some(
        match opened
            .wallet
            .relay_cancel(&opened.epicbox_method(), tx_id)
            .await
        {
            Ok(result) => RelayAsk::Answered(result),
            Err(error) => RelayAsk::Failed(display_error_chain(&error).join(": ")),
        },
    )
}

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

/// The error of a refused cancel of `tx_id`: a send the node took says so, so its hint can
/// name the recovery; a recovery's own entries and every other refusal keep their error.
async fn cancel_error<N: NodeApi + 'static>(
    opened: &Opened<N>,
    tx_id: TxId,
    error: WalletError,
) -> CliError {
    let posted = matches!(
        error,
        WalletError::Transition(InvalidTransition {
            from: TxState::Posted,
            ..
        })
    );
    if posted
        && let Ok(details) = opened.wallet.transaction_details(tx_id).await
        && details.transaction.entry.direction == TxDirection::Outgoing
        && details.transaction.entry.transport.as_deref() != Some(SELF.as_str())
    {
        return CliError::PostedSend { tx_id: tx_id.0 };
    }
    error.into()
}

/// The report of `recovery` as its push left it; a failed one is an error with its reason, the
/// node's text as [`node_text`] makes it plain.
fn recover_report(recovery: Recovery) -> Result<RecoverReport, CliError> {
    if recovery.state == RecoveryState::Failed {
        return Err(CliError::RecoveryFailed {
            tx_id: recovery.tx_id.0,
            error: node_text(&recovery.last_error.unwrap_or_default()),
        });
    }
    Ok(RecoverReport {
        tx_id: recovery.tx_id.0,
        recovery_tx_id: recovery.sent_tx.0,
        state: recovery_state_name(recovery.state).to_owned(),
    })
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
            "payment {} declined by the receiver: nothing was sent and its inputs are free again",
            declined.slate_id
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

/// Refreshes, runs the short update scan and refreshes again, so what another install of the
/// recovery phrase received or spent is in the balances and the listings that follow. A scan
/// that fails fails the command: the flag asked for it.
async fn updated<H: Host>(
    opened: &Opened<HostNode<H>>,
) -> Result<(RefreshOutcome, Vec<Balance>), CliError> {
    refreshed::<H>(opened).await?;
    opened.wallet.refresh_scan().await?;
    refreshed::<H>(opened).await
}

/// The spending options shared by `tx send`, `invoice pay` and `in-person`.
struct Spend {
    minimum_confirmations: u64,
    change_outputs: NonZeroUsize,
    strategy: SelectionStrategy,
    ttl_blocks: Option<u64>,
    /// The cutoff this wallet keeps for the send, not in its slate.
    local_ttl_blocks: Option<u64>,
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
            local_ttl_blocks: self.local_ttl_blocks,
            message,
            ..SendRequest::new(account, amount)
        }
    }

    /// `self`, with `blocks` as its cutoff when the caller named none: what a send waits for an
    /// answer by default (the `send_ttl_blocks` setting).
    const fn with_default_ttl(mut self, blocks: u64) -> Self {
        if self.ttl_blocks.is_none() {
            self.ttl_blocks = Some(blocks);
        }
        self
    }

    /// `self`, with `blocks` as the cutoff this wallet keeps when the caller named none: the
    /// default of a classic send, which leaves its slate without a TTL.
    const fn with_default_local_ttl(mut self, blocks: u64) -> Self {
        if self.ttl_blocks.is_none() {
            self.local_ttl_blocks = Some(blocks);
        }
        self
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
            local_ttl_blocks: None,
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

/// What `invoice pay` shows before it asks: the invoice in `file`, its amount and its message.
/// `None` for an invoice that does not decode or is for another amount than `amount`: the
/// payment refuses it without a question.
fn invoice_file_request<N: NodeApi + 'static>(
    opened: &Opened<N>,
    network: Network,
    file: &Path,
    wire: &WireSlate,
    amount: lepic_primitives::amount::Amount,
) -> Option<String> {
    let slate = opened.file.decode(network, wire).ok()?;
    if slate.amount() != amount {
        return None;
    }
    let message = slate
        .participants()
        .find_map(|(_, participant)| participant.message.as_ref())
        .map(|message| message.text().to_owned());
    Some(payment_request(
        &format!("Invoice in {}", file.display()),
        amount,
        message.as_deref(),
        None,
    ))
}

/// The lines shown before an invoice read from a file is paid: `title`, the amount, the
/// message and, when it is known, who sent it. The message and the sender's name are a peer's
/// text: their control characters are shown escaped.
pub(crate) fn payment_request(
    title: &str,
    amount: lepic_primitives::amount::Amount,
    message: Option<&str>,
    from: Option<&str>,
) -> String {
    let mut shown = format!(
        "{}\n  Amount:  {} EPIC\n  Message: {}\n",
        printable(title),
        format_amount(amount),
        message.map_or_else(|| "none".to_owned(), printable),
    );
    if let Some(from) = from {
        shown.push_str(&format!("  From:    {}\n", printable(from)));
    }
    shown
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
    // A reply a contact sealed is armored text.
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

pub(crate) const fn relay_network(network: Network) -> RelayNetwork {
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
    #[cfg(not(unix))]
    let _ = dir;
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

/// Runs `listen`, a listen of the wallet of `opened` until its handle stops, and expires unpaid
/// invoices when it starts and every [`SWEEP_INTERVAL`] while it runs. The listen is polled
/// during a sweep, so the relay connection is never left unattended. `swept` collects what every
/// sweep did, and becomes `None` once a sweep fails.
async fn listen_and_sweep<N: NodeApi + 'static>(
    opened: &Opened<N>,
    listen: impl Future<Output = Result<InboxSummary, lepic_wallet::inbox::InboxError>>,
    expiry: InvoiceExpiry,
    swept: &std::sync::Mutex<Option<InvoiceSweep>>,
) -> Result<InboxSummary, lepic_wallet::inbox::InboxError> {
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

fn show(
    repos: &dyn Repositories,
    details: &TransactionDetails,
    post: Option<&PaymentPost>,
) -> Result<TxReport, CliError> {
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
        sender_reported_posted_at: details.sender_reported_posted_at.map(|at| at.to_string()),
        sender_reported_cancelled_at: details
            .sender_reported_cancelled_at
            .map(|at| at.to_string()),
        receiver_declined_at: details.receiver_declined_at.map(|at| at.to_string()),
        payer_declined_at: details.payer_declined_at.map(|at| at.to_string()),
        receive_listing: details.receive_listing.map(|listing| ListingReport {
            service_key: listing.service_key().to_hex(),
            generation: listing.generation(),
        }),
        delivery: (details.undelivered || post.is_some_and(|post| !post.delivered)).then(|| {
            TxDeliveryReport {
                undelivered: true,
                stuck: post.is_some_and(|post| post.stuck),
                stuck_at: post.and_then(|post| post.stuck_at).map(|at| at.to_string()),
                next_attempt_at: post.and_then(|post| post.next_at).map(|at| at.to_string()),
                attempts: post.map_or(0, |post| post.attempts),
                reason: post.and_then(|post| post.reason.clone()),
            }
        }),
        recovery: details.recovery.as_ref().map(|recovery| TxRecoveryReport {
            tx_id: recovery.sent_tx.0,
            state: recovery_state_name(recovery.state).to_owned(),
            confirmations: recovery.confirmations,
            needed: recovery.needed,
            fee: recovery.fee.map(format_fee),
            error: recovery.error.as_deref().map(node_text),
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
        messages: None,
        origin: None,
        coinbase: None,
        imported: None,
        sender_reported_posted_at: None,
        sender_reported_cancelled_at: None,
        receiver_declined_at: None,
        payer_declined_at: None,
        receive_listing: None,
        recovery: None,
        delivery: None,
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

    use jiff::Timestamp;

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

    /// Each socket serves the inbox route by its own switch alone: with neither set, neither
    /// does; with one set, only that socket does; with both set, both do.
    #[test]
    fn each_listener_socket_serves_the_inbox_route_by_its_own_switch_only() {
        const WEB: &str = "LEPIC_EPIC1_WEB_LISTENER";
        const ONION: &str = "LEPIC_EPIC1_ONION_LISTENER";
        for (set, web, onion) in [
            (&[][..], false, false),
            (&[WEB][..], true, false),
            (&[ONION][..], false, true),
            (&[WEB, ONION][..], true, true),
        ] {
            let vars = [("HOME", "/home/test")]
                .into_iter()
                .chain(set.iter().map(|key| (*key, "true")))
                .map(|(key, value)| (key.to_owned(), value.to_owned()));
            let settings = Settings::resolve(
                &crate::cli::GlobalArgs::default(),
                &crate::settings::Env::new(vars),
            )
            .unwrap();
            assert_eq!(ListenerSocket::Web.serves_epic1(&settings), web, "{set:?}");
            assert_eq!(
                ListenerSocket::Onion.serves_epic1(&settings),
                onion,
                "{set:?}"
            );
        }
    }

    #[test]
    fn a_request_shows_the_peers_text_with_its_control_characters_escaped() {
        let shown = payment_request(
            "Invoice in shop.slate",
            lepic_primitives::amount::Amount::new(150_000_000),
            Some("pay\u{1b}[2J now\nFrom:    your bank"),
            Some("Shop\u{7}"),
        );
        assert!(
            !shown.chars().any(|c| c == '\u{1b}' || c == '\u{7}'),
            "{shown}"
        );
        assert_eq!(
            shown,
            "Invoice in shop.slate\n  Amount:  1.50000000 EPIC\n  Message: pay\\u{1b}[2J \
             now\\nFrom:    your bank\n  From:    Shop\\u{7}\n"
        );
    }

    #[test]
    fn a_request_with_no_known_sender_has_no_from_line() {
        let shown = payment_request(
            "Invoice in shop.slate",
            lepic_primitives::amount::Amount::new(150_000_000),
            None,
            None,
        );
        assert_eq!(
            shown,
            "Invoice in shop.slate\n  Amount:  1.50000000 EPIC\n  Message: none\n"
        );
    }

    #[test]
    fn a_refused_recovery_is_an_error_about_its_send() {
        let recovery = |state, last_error: Option<&str>| Recovery {
            tx_id: TxId(3),
            sent_tx: TxId(8),
            received_tx: TxId(9),
            state,
            kernel_height: None,
            last_error: last_error.map(str::to_owned),
            created_at: Timestamp::UNIX_EPOCH,
            updated_at: Timestamp::UNIX_EPOCH,
        };
        let posted = recover_report(recovery(RecoveryState::Posted, None)).unwrap();
        assert_eq!(
            (posted.tx_id, posted.recovery_tx_id, posted.state.as_str()),
            (3, 8, "posted")
        );
        let confirming = recover_report(recovery(RecoveryState::Confirming, None)).unwrap();
        assert_eq!(confirming.state, "confirming");
        let refused =
            recover_report(recovery(RecoveryState::Failed, Some("fee too low"))).unwrap_err();
        assert_eq!(refused.kind(), crate::exit::ErrorKind::Rejected);
        assert_eq!(refused.tx_id(), Some(3));
        assert_eq!(
            refused.to_string(),
            "the recovery of transaction 3 failed: fee too low"
        );
        // The node's text is escaped and capped as the API passes it on.
        let noisy = format!("bad\u{1b}[2J\u{202E}gnol\n{}", "x".repeat(400));
        let refused = recover_report(recovery(RecoveryState::Failed, Some(&noisy))).unwrap_err();
        let CliError::RecoveryFailed { error, .. } = &refused else {
            panic!("{refused:?}");
        };
        assert_eq!(*error, node_text(&noisy));
        assert!(
            error.starts_with("bad\\u{1b}[2J\\u{202e}gnol\\n"),
            "{error}"
        );
        assert_eq!(error.chars().count(), 256, "{error}");
        // A recovery the chain beat is not told as a refusal of the node.
        let mined = recover_report(recovery(
            RecoveryState::Failed,
            Some("the payment was mined first"),
        ))
        .unwrap_err();
        assert_eq!(
            mined.to_string(),
            "the recovery of transaction 3 failed: the payment was mined first"
        );
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
