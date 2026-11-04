// SPDX-License-Identifier: Apache-2.0
//! `lepic serve`: holds one unlocked wallet, does what `epicbox listen` does, and answers other
//! commands that arrive on a local socket.

use std::cell::Cell;
use std::convert::Infallible;
use std::future::Future;
use std::io::{BufReader, Write};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;
use std::time::Duration;

use clap::Parser as _;
use lepic_epicbox::RelayEndpoint;
use lepic_node::NodeApi;
use lepic_primitives::params::Network;
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet_contacts::CollectTrigger;
use tokio::net::UnixStream;
use tokio::sync::{Notify, watch};
use tokio::time::{Instant, MissedTickBehavior};

use super::{
    InvoiceSweep, LISTEN_GRACE, Opened, Run, contact, finish_listen, inbox_report, listen_and_sweep,
};
use crate::Console;
use crate::cli::{
    Cli, Command, ContactArgs, ContactCommand, EpicboxCommand, HttpCommand, NetworkArg, OutputArg,
    ServeArgs, TorCommand, WalletCommand,
};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{Report, ServeReport, render};
use crate::secret::SecretInput;
use crate::service::{self, Listening, Reply, Request};
use crate::settings::{Env, OutputFormat, Settings};

/// How often serve collects the contact mailboxes, as the app's foreground tick does: relay
/// backoff and outbox retry times are kept. The first cycle, at start, tries everything at once.
const COLLECT_INTERVAL: Duration = Duration::from_secs(60);

/// How often serve refreshes the wallet against the node, and once when it starts.
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

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
    let option = [
        (other_network, "--network"),
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
        Command::Serve(_) => "serve",
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

/// The wallet serve holds, and what a request needs to run a command on it.
struct Service<'a, H: Host> {
    host: &'a H,
    settings: &'a Settings,
    held: Arc<Opened<HostNode<H>>>,
}

impl<H: Host> Service<'_, H> {
    /// Reads one request from `stream`, runs it and sends the reply.
    async fn connection(&self, mut stream: UnixStream, served: &Cell<u32>) {
        let reply = match service::read_request(&mut stream).await {
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
        // Kept so the request's interrupt never fires: serve ends a request only by dropping it.
        let (_hold, interrupt) = watch::channel(false);
        let mut run = Run {
            host: self.host,
            settings,
            console,
            interrupt,
            graceful: Arc::new(AtomicBool::new(false)),
            held: Some(Arc::clone(&self.held)),
        };
        run.dispatch(command).await
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

    fn clear(&mut self) {
        self.0.clear();
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

/// Collects the contact mailboxes and refreshes the wallet, each on its interval. A failure is
/// logged and the next tick tries again.
async fn maintain<N: NodeApi + 'static>(
    opened: &Opened<N>,
    meeting: &[RelayEndpoint],
) -> Infallible {
    let mut collect = tokio::time::interval(COLLECT_INTERVAL);
    collect.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut trigger = CollectTrigger::Open;
    loop {
        tokio::select! {
            _ = collect.tick() => {
                let cycle = contact::collect_online(opened, meeting, trigger).await;
                trigger = CollectTrigger::Foreground;
                if let Err(error) = cycle {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(&error),
                        "contact collect failed"
                    );
                }
            }
            _ = refresh.tick() => {
                if let Err(error) = opened.wallet.refresh().await {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(&error),
                        "wallet refresh failed"
                    );
                }
            }
        }
    }
}

/// Listens, maintains the wallet and answers requests until `stop` is notified and the listener
/// and the requests have ended. Requests still running [`LISTEN_GRACE`] after the stop are
/// dropped. Ends early, with the listener's result, when the listener fails.
async fn serving<H: Host>(
    service: &Service<'_, H>,
    listening: &Listening,
    handle: &ListenHandle,
    swept: &Mutex<Option<InvoiceSweep>>,
    stop: &Notify,
    served: &Cell<u32>,
) -> Result<InboxSummary, InboxError> {
    let opened = &*service.held;
    let listener = listen_and_sweep(opened, handle, service.settings.invoice_expiry, swept);
    let maintenance = maintain(opened, &service.settings.servers.meeting_relays);
    tokio::pin!(listener, maintenance);
    let mut connections = Connections(Vec::new());
    let mut ended = None;
    let mut interrupted = false;
    let mut deadline: Option<Instant> = None;
    loop {
        match ended {
            Some(result) if connections.is_empty() => return result,
            _ => {}
        }
        if deadline.is_none() && (interrupted || ended.is_some()) {
            deadline = Some(
                Instant::now()
                    .checked_add(LISTEN_GRACE)
                    .unwrap_or_else(Instant::now),
            );
        }
        let stopping = deadline.is_some();
        tokio::select! {
            result = &mut listener, if ended.is_none() => ended = Some(result),
            never = &mut maintenance, if !stopping => match never {},
            () = stop.notified(), if !interrupted => interrupted = true,
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
            () = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)),
                if stopping && !connections.is_empty() =>
            {
                tracing::warn!("requests still running at shutdown dropped");
                connections.clear();
            }
        }
    }
}

impl<H: Host> Run<'_, H> {
    pub(super) async fn serve(&mut self, args: ServeArgs) -> Result<Report, CliError> {
        let path = args
            .socket
            .unwrap_or_else(|| service::default_socket(&self.settings.data_dir));
        service::check_socket_path(&path)?;
        let opened = self.open().await?;
        let listening = service::bind(&path)?;
        opened.wallet.epicbox_attach(&opened.epicbox)?;
        let handle = ListenHandle::new();
        let swept = Mutex::new(Some(InvoiceSweep::default()));
        let stop = Notify::new();
        let served = Cell::new(0);
        let service = Service {
            host: self.host,
            settings: self.settings,
            held: Arc::clone(&opened),
        };
        let result = self
            .until_interrupted(
                opened.wallet.subscribe(),
                serving(&service, &listening, &handle, &swept, &stop, &served),
                || {
                    finish_listen(&handle);
                    stop.notify_one();
                },
            )
            .await;
        drop(service);
        drop(listening);
        opened.wallet.lock();
        let summary = result?;
        let expired = swept.into_inner().unwrap_or_else(PoisonError::into_inner);
        Ok(Report::Serve(ServeReport {
            socket: path.display().to_string(),
            requests: served.get(),
            inbox: inbox_report(summary, expired),
        }))
    }
}
