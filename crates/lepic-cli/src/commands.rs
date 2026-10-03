//! Each command: what it asks the engine and what it reports.

use std::future::Future;
use std::io::{Read as _, Write as _};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use jiff::Timestamp;
use lepic_epicbox::transport::EpicboxTransport;
use lepic_epicbox::{ClientSettings, EpicboxAddress, Network as RelayNetwork, TRANSPORT_ID};
use lepic_keychain::vault::MAX_WALLET_SEED_FILE_LEN;
use lepic_node::{NodeApi, NodeClient, Propagation, RpcTransport};
use lepic_primitives::amount::Height;
use lepic_primitives::params::Network;
use lepic_store::{
    OutboxStatus, Repositories, SlateStage, StoredTransaction, TxDirection, TxId, WalletStore,
};
use lepic_transport::error::TransportError;
use lepic_transport::file::{FILE, FileTransport, response_path};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Exchange as _, Location};
use lepic_wallet::chain::ImplausibleNodeData;
use lepic_wallet::details::TransactionDetails;
use lepic_wallet::event::Balance;
use lepic_wallet::finalize::{FinalizeError, Posted};
use lepic_wallet::inbox::{InboxSummary, ListenHandle};
use lepic_wallet::invoice::{InvoiceError, InvoiceRequest, PayRequest};
use lepic_wallet::refresh::{RefreshError, RefreshOutcome};
use lepic_wallet::scan::{ScanCancel, ScanOptions, ScanSummary};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::state::state_name;
use lepic_wallet::{
    Clock, Event, Password, Ports, ReceiveRequest, SharedRng, Wallet, WalletConfig, WalletError,
    WalletName, WordCount,
};
use rand::SeedableRng as _;
use rand::rngs::{StdRng, SysRng};
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

use crate::Console;
use crate::amount::{format_amount, format_fee, format_units, parse_amount};
use crate::cli::{
    Command, DestinationArgs, EpicboxCommand, FinalizeArgs, ImportSeedArgs, InitArgs,
    InvoiceCommand, NodeCommand, PostArgs, ReceiveArgs, ResendArgs, RestoreArgs, ScanArgs,
    SelectionArg, SendArgs, SpendArgs, TxCommand, WalletCommand, WordsArg,
};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{
    AccountReport, AddressReport, EpicboxStatusReport, FinalizeReport, InboxReport, InfoReport,
    InitReport, InvoiceIssueReport, InvoicePayReport, NodeStatusReport, PostReport, ReceiveReport,
    Report, ResendReport, RestoreReport, ScanReport, SendReport, TxListReport, TxReport,
    TxStateReport,
};
use crate::progress::Progress;
use crate::settings::{OutputFormat, Settings};
use crate::stores::{CliStores, SharedStore};
use crate::vault::{FileVault, VAULT_FILE};

/// Every CLI wallet has this name in logs; one data directory holds one wallet.
const WALLET_NAME: &str = "default";

type CliWallet<N> = Wallet<N, CliStores, FileVault>;

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// One command's wallet handle and the Epicbox transport registered in it.
struct Opened<N: NodeApi + 'static> {
    wallet: CliWallet<N>,
    epicbox: EpicboxTransport,
    /// Held until the command ends; `None` when the data directory does not exist.
    _lock: Option<std::fs::File>,
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
}

struct Run<'a, H: Host> {
    host: &'a H,
    settings: &'a Settings,
    console: &'a mut Console,
    /// Turns true once the user interrupts.
    interrupt: watch::Receiver<bool>,
    /// Set by a command that stops on its own when interrupted and reports what it did.
    graceful: Arc<AtomicBool>,
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
            Command::Node(NodeCommand::Status) => self.node_status().await,
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
            WalletCommand::Address => {
                let opened = self.open().await?;
                let address = opened.wallet.epicbox_attach(&opened.epicbox)?;
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
                let tx_id = TxId(args.tx_id);
                opened.wallet.cancel(tx_id).await?;
                Ok(Report::Cancel(TxStateReport {
                    tx_id: tx_id.0,
                    state: "cancelled".to_owned(),
                }))
            }
            TxCommand::List(args) => {
                let opened = self.open().await?;
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
                let opened = self.open().await?;
                let tx_id = TxId(args.tx_id);
                let details = opened.wallet.transaction_details(tx_id).await?;
                let report = opened.store()?.read(|repos| show(repos, &details))?;
                Ok(Report::Show(report))
            }
        }
    }

    async fn epicbox(&mut self, command: EpicboxCommand) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let summary = match command {
            EpicboxCommand::Drain => opened.wallet.epicbox_drain(&opened.epicbox).await?,
            EpicboxCommand::Listen => {
                let handle = ListenHandle::new();
                self.until_interrupted(
                    opened.wallet.subscribe(),
                    opened.wallet.epicbox_listen(&opened.epicbox, &handle),
                    || handle.stop(),
                )
                .await?
            }
            EpicboxCommand::Status => {
                let address = opened.wallet.epicbox_attach(&opened.epicbox)?;
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
        Ok(Report::Inbox(inbox_report(summary)))
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
        let wallet = self.prepare(true)?;
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
        let opened = self.prepare(true)?;
        opened.wallet.restore(password, phrase.trim()).await?;
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
        let opened = self.prepare(true)?;
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
            let cancel = ScanCancel::new();
            let summary: ScanSummary = self
                .until_interrupted(
                    opened.wallet.subscribe(),
                    opened
                        .wallet
                        .scan(ScanOptions::restore(self.settings.network), &cancel),
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

    async fn info(&mut self) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let mut events = opened.wallet.subscribe();
        let mut attempt = 1;
        let outcome = loop {
            match opened.wallet.refresh().await {
                Err(error) if attempt < REFRESH_ATTEMPTS && chain_moved_during(&error) => {
                    attempt = attempt.saturating_add(1);
                    tracing::debug!(attempt, error = %error, "refresh repeated");
                }
                outcome => break outcome?,
            }
        };
        let mut balances: Vec<Balance> = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let Event::Balance(balance) = event {
                balances.push(balance);
            }
        }
        let (height, node_behind) = match outcome {
            RefreshOutcome::Refreshed(summary) => (summary.height, false),
            RefreshOutcome::NodeBehind { tip, .. } => (tip, true),
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
            accounts,
        }))
    }

    async fn send(&mut self, args: SendArgs) -> Result<Report, CliError> {
        let amount = parse_amount(&args.amount)?;
        let spend = Spend::from_args(&args.spend)?;
        let (delivery, destination) = self.delivery(args.destination)?;
        let opened = self.open().await?;
        let account = opened.wallet.account(&args.account.account)?;
        if delivery.transport() == TRANSPORT_ID {
            opened.wallet.epicbox_attach(&opened.epicbox)?;
        }
        let transport = delivery.transport();
        let request = SendRequest {
            minimum_confirmations: spend.minimum_confirmations,
            change_outputs: spend.change_outputs,
            strategy: spend.strategy,
            ttl_blocks: spend.ttl_blocks,
            message: args.message.message,
            ..SendRequest::new(account.index, amount)
        };
        let sent = opened.wallet.send(request, delivery).await?;
        Ok(Report::Send(SendReport {
            tx_id: sent.tx_id.0,
            slate_id: sent.slate_id.to_string(),
            amount: format_amount(sent.amount),
            fee: format_fee(sent.fee),
            transport: transport.to_string(),
            destination,
        }))
    }

    async fn resend(&mut self, args: ResendArgs) -> Result<Report, CliError> {
        let (delivery, destination) = self.delivery(args.destination)?;
        let opened = self.open().await?;
        if delivery.transport() == TRANSPORT_ID {
            opened.wallet.epicbox_attach(&opened.epicbox)?;
        }
        let transport = delivery.transport().to_string();
        let tx_id = TxId(args.tx.tx_id);
        opened.wallet.resend(tx_id, delivery).await?;
        Ok(Report::Resend(ResendReport {
            tx_id: tx_id.0,
            transport,
            destination,
        }))
    }

    /// Where a first slate goes, and how the report names it. An Epicbox address is parsed
    /// here, before the wallet stores anything: a send to an address that cannot be delivered
    /// to would leave a transaction behind with its inputs locked.
    fn delivery(&self, destination: DestinationArgs) -> Result<(Delivery, String), CliError> {
        match (destination.to, destination.to_file) {
            (Some(address), _) => {
                EpicboxAddress::parse(&address, relay_network(self.settings.network))
                    .map_err(CliError::Address)?;
                Ok((
                    Delivery::Deliver {
                        transport: TRANSPORT_ID,
                        to: Destination::new(address.clone()),
                    },
                    address,
                ))
            }
            (None, Some(path)) => {
                let text = path.display().to_string();
                Ok((
                    Delivery::Export {
                        transport: FILE,
                        to: Location::File(path),
                    },
                    text,
                ))
            }
            (None, None) => Err(CliError::NoDestination),
        }
    }

    async fn receive(&mut self, args: ReceiveArgs) -> Result<Report, CliError> {
        let opened = self.open().await?;
        let files = FileTransport::new();
        let wire = files
            .import(&Location::File(args.slate.file.clone()))
            .await
            .map_err(slate_file(&args.slate.file))?;
        let received = opened
            .wallet
            .receive(
                FILE,
                &wire,
                ReceiveRequest {
                    account: Some(args.account.account),
                    message: args.message.message,
                },
            )
            .await?;
        let reply = args
            .reply
            .reply_file
            .unwrap_or_else(|| response_path(&args.slate.file));
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
        let opened = self.open().await?;
        let wire = FileTransport::new()
            .import(&Location::File(args.slate.file.clone()))
            .await
            .map_err(slate_file(&args.slate.file))?;
        let propagation = propagation(args.fluff.fluff);
        // Which flow the file answers is known only once it is decoded, which the engine does.
        let finalized = match opened.wallet.finalize(FILE, &wire, propagation).await {
            Err(error @ FinalizeError::WrongStage { .. }) => {
                match opened
                    .wallet
                    .finalize_invoice(FILE, &wire, propagation)
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

    async fn invoice(&mut self, command: InvoiceCommand) -> Result<Report, CliError> {
        match command {
            InvoiceCommand::Issue(args) => {
                let amount = parse_amount(&args.amount)?;
                let opened = self.open().await?;
                let account = opened.wallet.account(&args.account.account)?;
                let file = args.to_file.display().to_string();
                let issued = opened
                    .wallet
                    .issue_invoice(
                        InvoiceRequest {
                            account: account.index,
                            amount,
                            message: args.message.message,
                        },
                        Delivery::Export {
                            transport: FILE,
                            to: Location::File(args.to_file),
                        },
                    )
                    .await?;
                Ok(Report::InvoiceIssue(InvoiceIssueReport {
                    tx_id: issued.tx_id.0,
                    slate_id: issued.slate_id.to_string(),
                    amount: format_amount(issued.amount),
                    file,
                }))
            }
            InvoiceCommand::Pay(args) => {
                let amount = parse_amount(&args.amount)?;
                let spend = Spend::from_args(&args.spend)?;
                let opened = self.open().await?;
                let account = opened.wallet.account(&args.account.account)?;
                let files = FileTransport::new();
                let wire = files
                    .import(&Location::File(args.slate.file.clone()))
                    .await
                    .map_err(slate_file(&args.slate.file))?;
                let request = PayRequest {
                    minimum_confirmations: spend.minimum_confirmations,
                    change_outputs: spend.change_outputs,
                    strategy: spend.strategy,
                    ttl_blocks: spend.ttl_blocks,
                    message: args.message.message,
                    ..PayRequest::new(account.index, amount)
                };
                let paid = opened.wallet.pay_invoice(FILE, &wire, request).await?;
                let reply = args
                    .reply
                    .reply_file
                    .unwrap_or_else(|| response_path(&args.slate.file));
                files
                    .export(&paid.reply, &Location::File(reply.clone()))
                    .await
                    .map_err(slate_file(&reply))?;
                Ok(Report::InvoicePay(InvoicePayReport {
                    tx_id: paid.tx_id.0,
                    slate_id: paid.slate.id().to_string(),
                    amount: format_amount(paid.slate.amount()),
                    fee: format_fee(paid.slate.fee()),
                    reply_file: reply.display().to_string(),
                }))
            }
        }
    }

    async fn new_password(&mut self) -> Result<Password, CliError> {
        let password = self
            .console
            .secrets
            .wallet_password(&mut self.console.env, true)
            .await?;
        Ok(password_from(password))
    }

    /// Unlocks the wallet in the data directory. A directory without a vault is reported before
    /// the password is asked for, which would otherwise be typed for nothing.
    async fn open(&mut self) -> Result<Opened<HostNode<H>>, CliError> {
        if !self.settings.data_dir.join(VAULT_FILE).exists() {
            return Err(WalletError::NoWallet.into());
        }
        let password = self
            .console
            .secrets
            .wallet_password(&mut self.console.env, false)
            .await?;
        let opened = self.prepare(false)?;
        opened.wallet.open(password_from(password)).await?;
        start_from_confirmed_tip(&opened.wallet)?;
        Ok(opened)
    }

    /// A locked wallet handle on the data directory, which a new wallet creates.
    fn prepare(&self, create_dir: bool) -> Result<Opened<HostNode<H>>, CliError> {
        if create_dir {
            create_private_dir(&self.settings.data_dir)?;
        }
        check_private_dir(&self.settings.data_dir)?;
        let lock = lock_data_dir(&self.settings.data_dir)?;
        let relay = ClientSettings::new(self.settings.relay.clone());
        let epicbox = EpicboxTransport::new(
            relay,
            relay_network(self.settings.network),
            self.host.relay_connector()?,
        );
        let mut transports = TransportRegistry::new();
        for transport in [
            Box::new(FileTransport::new()) as Box<dyn lepic_transport::transport::Transport>,
            Box::new(epicbox.clone()),
        ] {
            transports.register(transport)?;
        }
        let rng = StdRng::try_from_rng(&mut SysRng).map_err(|error| CliError::Io {
            what: "seed the random number generator",
            source: std::io::Error::other(error),
        })?;
        let ports = Ports {
            node: self.host.node(self.settings)?,
            stores: CliStores::default(),
            secrets: FileVault::new(&self.settings.data_dir, self.host.vault_kdf()),
            transports,
            clock: Arc::new(SystemClock),
            rng: SharedRng::new(rng),
            runtime: tokio::runtime::Handle::current(),
        };
        let config = WalletConfig {
            name: WalletName::new(WALLET_NAME).map_err(WalletError::from)?,
            network: self.settings.network,
            data_dir: self.settings.data_dir.clone(),
            node: self.settings.node.clone(),
            transports: vec![FILE, TRANSPORT_ID],
        };
        Ok(Opened {
            wallet: Wallet::new(config, ports)?,
            epicbox,
            _lock: lock,
        })
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

/// The line for a transaction a received slate created.
fn receipt_line(event: &Event) -> Option<String> {
    match event {
        Event::Received(received) => Some(format!(
            "transaction {} received {} EPIC",
            received.tx_id.0,
            format_amount(received.amount)
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

/// How often `wallet info` asks for a refresh the chain outgrew while it ran.
const REFRESH_ATTEMPTS: u32 = 3;

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

/// The spending options shared by `tx send` and `invoice pay`.
struct Spend {
    minimum_confirmations: u64,
    change_outputs: NonZeroUsize,
    strategy: SelectionStrategy,
    ttl_blocks: Option<u64>,
}

impl Spend {
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

/// The file in a data directory that holds the directory lock, the same one the mobile binding
/// takes, so a CLI command and an app never open one database at once. It stays when the lock
/// is released: removing it would let two openers lock different files.
const LOCK_FILE: &str = ".lepic.lock";

/// An exclusive OS lock on [`LOCK_FILE`], released when the file is closed. A missing data
/// directory holds no wallet to protect and is left to the wallet to report. A symbolic link in
/// place of the lock file is refused rather than followed, so the lock never creates a file
/// elsewhere. Any failure other than another holder fails closed.
fn lock_data_dir(dir: &Path) -> Result<Option<std::fs::File>, CliError> {
    let mut options = std::fs::File::options();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(lepic_transport::file::O_NOFOLLOW);
    }
    let file = match options.open(dir.join(LOCK_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CliError::io("open the data directory lock")(error)),
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(CliError::DataDirInUse),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(CliError::io("lock the data directory")(error))
        }
    }
}

fn inbox_report(summary: InboxSummary) -> InboxReport {
    InboxReport {
        received: summary.received,
        finalized: summary.finalized,
        repeated: summary.repeated,
        rejected: summary.rejected,
        held: summary.held,
    }
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
        ..tx_report(tx, Some(stages))
    })
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
