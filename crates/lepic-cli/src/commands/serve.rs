// SPDX-License-Identifier: Apache-2.0
//! `lepic serve`: holds one unlocked wallet, does what `epicbox listen` does, and answers other
//! commands that arrive on a local socket.

use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::future::Future;
use std::io::{BufReader, Write};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;
use std::time::Duration;

use clap::Parser as _;
use jiff::Timestamp;
use lepic_epicbox::RelayEndpoint;
use lepic_foreign::CoinbaseAccess;
use lepic_node::NodeApi;
use lepic_primitives::params::Network;
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet_contacts::CollectTrigger;
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use super::{
    HttpListener, InvoiceSweep, Opened, Run, abort_on, contact, finish_listen, inbox_report,
    listen_and_sweep,
};
use crate::Console;
use crate::cli::{
    Cli, Command, ContactArgs, ContactCommand, EpicboxCommand, HttpCommand, NetworkArg, OutputArg,
    ServeArgs, ServeCommand, TorCommand, WalletCommand,
};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{
    MaintenanceReport, Report, ServeHttpStatus, ServeReport, ServeStatusReport, render,
};
use crate::secret::SecretInput;
use crate::service::{self, Listening, Reply, Request};
use crate::settings::{Env, OutputFormat, Settings};

/// Output a request's command wrote, read back for the reply.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// The commands that cannot run through serve, and the options that would change what it opened.
/// `--data-dir`, `--config` and `--settings` only say where a client found the socket, so they are
/// ignored; `--network` passes when it names the network serve opened.
fn refusal(cli: &Cli, settings: &Settings) -> Option<CliError> {
    let global = &cli.global;
    let other_network = global.network.is_some_and(|network| {
        let network = match network {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Floonet => Network::Floonet,
        };
        network != settings.network
    });
    let other_profile = crate::settings::profile_flag(global)
        .ok()
        .flatten()
        .is_some_and(|profile| profile != settings.profile);
    let option = [
        (other_network, "--network"),
        (other_profile, "--profile"),
        (global.service.is_some(), "--service"),
    ]
    .into_iter()
    .find_map(|(given, name)| given.then_some(name));
    if let Some(option) = option {
        return Some(CliError::ServiceOption { option });
    }
    let what = match &cli.command {
        Command::Wallet(WalletCommand::Init(_)) => "wallet init",
        Command::Wallet(WalletCommand::Restore(_)) => "wallet restore",
        Command::Wallet(WalletCommand::ImportSeed(_)) => "wallet import-seed",
        Command::Wallet(WalletCommand::Password) => "wallet password",
        Command::Serve(ServeArgs { command: None, .. }) => "serve",
        Command::Epicbox(EpicboxCommand::Listen) => "epicbox listen",
        Command::Http(HttpCommand::Listen(_)) => "http listen",
        Command::Tor(TorCommand::Listen(_)) => "tor listen",
        // Reads the standard input of serve, not of the request.
        Command::Contact(ContactArgs {
            command: ContactCommand::OpenSealed(args),
            ..
        }) if args.input == "-" => "contact open-sealed -",
        _ => return None,
    };
    Some(CliError::ServiceRefused { what })
}

/// How one maintenance task went since serve started, for `serve status`.
#[derive(Default)]
struct TaskStatus {
    failures: u32,
    error: Option<String>,
    succeeded_at: Option<Timestamp>,
}

impl TaskStatus {
    fn record<E: std::error::Error + 'static>(&mut self, result: Result<(), E>, now: Timestamp) {
        match result {
            Ok(()) => {
                self.failures = 0;
                self.succeeded_at = Some(now);
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                self.error = Some(lepic_telemetry::ErrorChain(&error).to_string());
            }
        }
    }

    fn report(&self) -> MaintenanceReport {
        MaintenanceReport {
            consecutive_failures: self.failures,
            last_error: self.error.clone(),
            last_success: self.succeeded_at.map(|at| at.to_string()),
        }
    }
}

#[derive(Default)]
struct Maintenance {
    refresh: TaskStatus,
    collect: TaskStatus,
}

/// The wallet serve holds, and what a request needs to run a command on it.
struct Service<'a, H: Host> {
    host: &'a H,
    settings: &'a Settings,
    held: Arc<Opened<HostNode<H>>>,
    /// Turns true when serve stops, which interrupts every request as Ctrl-C interrupts a command.
    interrupt: watch::Receiver<bool>,
    maintenance: RefCell<Maintenance>,
    /// The HTTP listener, when serve runs with `--http`.
    http: Option<&'a HttpListener>,
}

impl<H: Host> Service<'_, H> {
    /// Reads one request from `stream`, runs it and sends the reply.
    async fn connection(&self, mut stream: UnixStream, served: &Cell<u32>) {
        let mut interrupt = self.interrupt.clone();
        let request = tokio::select! {
            request = service::read_request(&mut stream) => request,
            Ok(_) = interrupt.wait_for(|stopped| *stopped) => return,
        };
        let reply = match request {
            Ok(Request { args }) => self.answer(args).await,
            Err(error) => {
                let stderr = Capture::default();
                let mut console = self.console(Capture::default(), stderr.clone());
                let code = crate::report_error(&mut console, OutputFormat::Human, &error, None);
                Reply {
                    code,
                    stdout: String::new(),
                    stderr: stderr.text(),
                }
            }
        };
        served.set(served.get().saturating_add(1));
        if let Err(error) = service::write_reply(&mut stream, &reply).await {
            tracing::warn!(error = %lepic_telemetry::ErrorChain(&error), "reply not delivered");
        }
    }

    /// A console with empty standard input, so a command that asks for a secret fails.
    fn console(&self, stdout: Capture, stderr: Capture) -> Console {
        Console {
            env: Env::new(std::iter::empty()),
            secrets: SecretInput::new(
                Box::new(BufReader::new(std::io::empty())),
                false,
                Box::new(std::io::sink()),
            ),
            stdout: Box::new(stdout),
            stderr: Box::new(stderr),
            ansi: false,
        }
    }

    async fn answer(&self, args: Vec<String>) -> Reply {
        let stdout = Capture::default();
        let stderr = Capture::default();
        let mut console = self.console(stdout.clone(), stderr.clone());
        let code = self.run(args, &mut console).await;
        Reply {
            code,
            stdout: stdout.text(),
            stderr: stderr.text(),
        }
    }

    /// Runs the command line `args` as `run` does and returns its exit code.
    async fn run(&self, args: Vec<String>, console: &mut Console) -> u8 {
        let cli = match Cli::try_parse_from(std::iter::once("lepic".to_owned()).chain(args)) {
            Ok(cli) => cli,
            Err(error) => {
                let (text, code) = crate::usage_text(&error);
                let stream = if code == 0 {
                    &mut console.stdout
                } else {
                    &mut console.stderr
                };
                let _ = stream.write_all(text.as_bytes());
                return code;
            }
        };
        let mut settings = self.settings.clone();
        match cli.global.output {
            Some(OutputArg::Human) => settings.output = OutputFormat::Human,
            Some(OutputArg::Json) => settings.output = OutputFormat::Json,
            None => {}
        }
        let result = match refusal(&cli, self.settings) {
            Some(error) => Err(error),
            None => self.command(cli.command, &settings, console).await,
        };
        match result {
            Ok(report) => {
                let text = render(&report, settings.output);
                let _ = console.stdout.write_all(text.as_bytes());
                let _ = console.stdout.flush();
                0
            }
            Err(error) => crate::report_error(console, settings.output, &error, Some(&settings)),
        }
    }

    async fn command(
        &self,
        command: Command,
        settings: &Settings,
        console: &mut Console,
    ) -> Result<Report, CliError> {
        if let Command::Serve(ServeArgs {
            command: Some(ServeCommand::Status),
            ..
        }) = command
        {
            let maintenance = self.maintenance.borrow();
            return Ok(Report::ServeStatus(ServeStatusReport {
                refresh: maintenance.refresh.report(),
                collect: maintenance.collect.report(),
                http: self.http.map(|http| ServeHttpStatus {
                    listener: http.report(),
                    coinbase: match http.coinbase {
                        CoinbaseAccess::Off => "off",
                        CoinbaseAccess::LocalOnly => "local",
                        CoinbaseAccess::Remote => "remote",
                    },
                }),
            }));
        }
        let graceful = Arc::new(AtomicBool::new(false));
        let mut run = Run {
            host: self.host,
            settings,
            console,
            interrupt: self.interrupt.clone(),
            graceful: Arc::clone(&graceful),
            held: Some(Arc::clone(&self.held)),
        };
        tokio::select! {
            result = run.dispatch(command) => result,
            () = abort_on(self.interrupt.clone(), &graceful) => Err(CliError::Interrupted),
        }
    }
}

/// Requests in flight, polled together in the task that polls serve.
struct Connections<'a>(Vec<Pin<Box<dyn Future<Output = ()> + 'a>>>);

impl<'a> Connections<'a> {
    fn push(&mut self, connection: impl Future<Output = ()> + 'a) {
        self.0.push(Box::pin(connection));
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Completes when a request has ended; pending while there is none.
    async fn next(&mut self) {
        std::future::poll_fn(|cx| {
            let before = self.0.len();
            self.0
                .retain_mut(|connection| connection.as_mut().poll(cx).is_pending());
            if self.0.len() < before {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

/// Collects the contact mailboxes and refreshes the wallet, each every `every` and once at start,
/// and records how each went in `status`. Relay backoff and outbox retry times are kept between
/// collects; the first, at start, tries everything at once. A failure is logged and the next
/// tick tries again.
async fn maintain<N: NodeApi + 'static>(
    opened: &Opened<N>,
    meeting: &[RelayEndpoint],
    every: Duration,
    status: &RefCell<Maintenance>,
) -> Infallible {
    let mut collect = tokio::time::interval(every);
    collect.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut refresh = tokio::time::interval(every);
    refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut trigger = CollectTrigger::Open;
    loop {
        tokio::select! {
            _ = collect.tick() => {
                let cycle = contact::collect_online(opened, meeting, trigger).await;
                trigger = CollectTrigger::Foreground;
                if let Err(error) = &cycle {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(error),
                        "contact collect failed"
                    );
                }
                let now = opened.wallet.ports().clock.now();
                status.borrow_mut().collect.record(cycle, now);
            }
            _ = refresh.tick() => {
                let refreshed = opened.wallet.refresh().await.map(drop);
                if let Err(error) = &refreshed {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(error),
                        "wallet refresh failed"
                    );
                }
                let now = opened.wallet.ports().clock.now();
                status.borrow_mut().refresh.record(refreshed, now);
            }
        }
    }
}

/// Listens, maintains the wallet and answers requests until `stop` turns true and the listener
/// and the requests have ended. The stop interrupts the requests, and a failed listener sets it.
async fn serving<H: Host>(
    service: &Service<'_, H>,
    listening: &Listening,
    handle: &ListenHandle,
    swept: &Mutex<Option<InvoiceSweep>>,
    stop: &watch::Sender<bool>,
    served: &Cell<u32>,
) -> Result<InboxSummary, InboxError> {
    let opened = &*service.held;
    let listener = listen_and_sweep(opened, handle, service.settings.invoice_expiry, swept);
    let maintenance = maintain(
        opened,
        &service.settings.servers.meeting_relays,
        service.host.maintenance_interval(),
        &service.maintenance,
    );
    tokio::pin!(listener, maintenance);
    let mut connections = Connections(Vec::new());
    let mut stopped = stop.subscribe();
    let mut ended = None;
    loop {
        match ended {
            Some(result) if connections.is_empty() => return result,
            _ => {}
        }
        let stopping = *stop.borrow();
        tokio::select! {
            result = &mut listener, if ended.is_none() => {
                ended = Some(result);
                stop.send_replace(true);
            }
            never = &mut maintenance, if !stopping => match never {},
            Ok(_) = stopped.wait_for(|stopped| *stopped), if !stopping => {}
            accepted = listening.accept(), if !stopping => match accepted {
                Ok(stream) if listening.is_this_user(&stream) => {
                    connections.push(service.connection(stream, served));
                }
                Ok(_) => tracing::debug!("connection from another user dropped"),
                Err(error) => {
                    tracing::warn!(error = %error, "accepting a connection failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            () = connections.next(), if !connections.is_empty() => {}
        }
    }
}

impl<H: Host> Run<'_, H> {
    pub(super) async fn serve(&mut self, args: ServeArgs) -> Result<Report, CliError> {
        if let Some(ServeCommand::Status) = args.command {
            return Err(CliError::ServiceOnly {
                what: "serve status",
            });
        }
        let path = args
            .socket
            .unwrap_or_else(|| service::default_socket(&self.settings.data_dir));
        service::check_socket_path(&path)?;
        let opened = self.open().await?;
        let http = if args.http {
            Some(HttpListener::start(&opened, self.settings, &args.listen).await?)
        } else {
            None
        };
        let listening = service::bind(&path)?;
        opened.wallet.epicbox_attach(&opened.epicbox)?;
        let handle = ListenHandle::new();
        let swept = Mutex::new(Some(InvoiceSweep::default()));
        let stop = watch::Sender::new(false);
        let served = Cell::new(0);
        let service = Service {
            host: self.host,
            settings: self.settings,
            held: Arc::clone(&opened),
            interrupt: stop.subscribe(),
            maintenance: RefCell::default(),
            http: http.as_ref(),
        };
        let result = self
            .until_interrupted(
                opened.wallet.subscribe(),
                serving(&service, &listening, &handle, &swept, &stop, &served),
                || {
                    finish_listen(&handle);
                    stop.send_replace(true);
                },
            )
            .await;
        drop(service);
        let http = match http {
            Some(http) => Some(http.shutdown().await),
            None => None,
        };
        drop(listening);
        opened.wallet.lock();
        let summary = result?;
        let expired = swept.into_inner().unwrap_or_else(PoisonError::into_inner);
        Ok(Report::Serve(ServeReport {
            socket: path.display().to_string(),
            requests: served.get(),
            inbox: inbox_report(summary, expired),
            http,
        }))
    }
}
