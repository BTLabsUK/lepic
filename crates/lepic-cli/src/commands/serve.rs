// SPDX-License-Identifier: Apache-2.0
//! `lepic serve`: holds one unlocked wallet, does what `epicbox listen` does, and answers the
//! wallet API on a local socket, and with `--owner-tls` over TLS too.

mod cli;
mod v1;

use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::future::Future;
use std::io::BufReader;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::future::LocalBoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt as _, StreamExt as _};
use jiff::Timestamp;
use lepic_epicbox::RelayEndpoint;
use lepic_node::NodeApi;
use lepic_wallet::ApiTlsKey;
use lepic_wallet::event::Event;
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet_contacts::CollectTrigger;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, watch};
use tokio::time::MissedTickBehavior;

use super::{
    HttpListener, InvoiceSweep, Opened, Run, abort_on, contact, finish_listen, inbox_report,
    listen_and_sweep,
};
use crate::Console;
use crate::api::{Api, Listener, OwnerTls, Shaken, epicbox_state};
use crate::cli::{Command, ServeArgs};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{Report, ServeReport};
use crate::secret::SecretInput;
use crate::service::{self, Listening};
use crate::settings::{Env, Settings};

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
    /// The owner TLS listener, when serve runs with `--owner-tls`.
    owner_tls: Option<&'a OwnerTls>,
    started: Instant,
    /// The Epicbox listener's latest state.
    epicbox: Cell<Option<&'static str>>,
    /// The API's event log.
    log: v1::Log,
    scans: v1::Scans,
}

impl<H: Host> Service<'_, H> {
    /// Runs `command` as `lepic` runs it, with a console that has no input and discards output,
    /// so a command that asks for a secret fails. A handler may run one to reuse its work.
    async fn command(&self, command: Command) -> Result<Report, CliError> {
        let mut console = Console {
            env: Env::new(std::iter::empty()),
            secrets: SecretInput::new(
                Box::new(BufReader::new(std::io::empty())),
                false,
                Box::new(std::io::sink()),
            ),
            stdout: Box::new(std::io::sink()),
            stderr: Box::new(std::io::sink()),
            ansi: false,
        };
        let graceful = Arc::new(AtomicBool::new(false));
        let mut run = Run {
            host: self.host,
            settings: self.settings,
            console: &mut console,
            interrupt: self.interrupt.clone(),
            graceful: Arc::clone(&graceful),
            held: Some(Arc::clone(&self.held)),
            reviewed: None,
        };
        // Boxed: a command's future is too large for the stack of the handler that awaits it.
        tokio::select! {
            result = Box::pin(run.dispatch(command)) => result,
            () = abort_on(self.interrupt.clone(), &graceful) => Err(CliError::Interrupted),
        }
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

/// How long a listener stops accepting after an accept failed, as when serve is out of file
/// descriptors, so a failure that repeats does not spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// Listens, maintains the wallet and answers the API until `stop` turns true and the listener
/// and the connections have ended. The stop closes each connection once its answer is out, and
/// a failed listener sets it. The socket and the owner TLS listener each have their own cap on
/// connections, so connections from the network cannot use up the socket's. A TLS connection
/// takes its slot once its handshake ends; handshakes have a cap of the same size of their own,
/// so connections that never finish one do not hold the slots of listed clients.
async fn serving<H: Host>(
    service: &Service<'_, H>,
    api: &Api<'_, Service<'_, H>>,
    listening: &Listening,
    handle: &ListenHandle,
    swept: &Mutex<Option<InvoiceSweep>>,
    stop: &watch::Sender<bool>,
) -> Result<InboxSummary, InboxError> {
    let opened = &*service.held;
    let listener = listen_and_sweep(opened, handle, service.settings.invoice_expiry, swept);
    let maintenance = maintain(
        opened,
        &service.settings.servers.meeting_relays,
        service.host.maintenance_interval(),
        &service.maintenance,
    );
    let writer = v1::event_writer(service);
    let scanner = v1::scan_driver(service);
    tokio::pin!(listener, maintenance, writer, scanner);
    let tls = service.owner_tls;
    let mut sockets = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut tls_connections = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut handshakes = FuturesUnordered::<LocalBoxFuture<'_, Option<Shaken>>>::new();
    let mut events = Some(opened.wallet.subscribe());
    let mut stopped = stop.subscribe();
    let mut ended = None;
    // Until when each listener's accept waits, after a failed accept.
    let mut socket_pause = None;
    let mut tls_pause = None;
    loop {
        match ended {
            Some(result)
                if sockets.is_empty() && tls_connections.is_empty() && handshakes.is_empty() =>
            {
                return result;
            }
            _ => {}
        }
        let stopping = *stop.borrow();
        tokio::select! {
            result = &mut listener, if ended.is_none() => {
                ended = Some(result);
                stop.send_replace(true);
            }
            never = &mut maintenance, if !stopping => match never {},
            never = &mut writer, if !stopping => match never {},
            never = &mut scanner, if !stopping => match never {},
            Ok(_) = stopped.wait_for(|stopped| *stopped), if !stopping => {}
            event = recv(events.as_mut()), if events.is_some() => match event {
                Ok(event) => {
                    if let Some(state) = epicbox_state(&event) {
                        service.epicbox.set(Some(state));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => events = None,
            },
            accepted = after(socket_pause, listening.accept()), if !stopping => match accepted {
                Ok(stream)
                    if listening.is_this_user(&stream)
                        && sockets.len() < api.limits().max_connections =>
                {
                    sockets.push(api.connection(stream, Listener::Socket, None).boxed_local());
                }
                Ok(_) => api.refuse(),
                Err(error) => {
                    tracing::warn!(error = %error, "accepting a connection failed");
                    socket_pause = tokio::time::Instant::now().checked_add(ACCEPT_PAUSE);
                }
            },
            accepted = after(tls_pause, accept_tls(tls)), if !stopping => match accepted {
                Ok((tls, stream)) if handshakes.len() < api.limits().max_connections => {
                    handshakes.push(api.tls_handshake(tls, stream).boxed_local());
                }
                Ok(_) => api.refuse(),
                Err(error) => {
                    tracing::warn!(error = %error, "accepting a tls connection failed");
                    tls_pause = tokio::time::Instant::now().checked_add(ACCEPT_PAUSE);
                }
            },
            Some(()) = sockets.next(), if !sockets.is_empty() => {}
            Some(()) = tls_connections.next(), if !tls_connections.is_empty() => {}
            Some(shaken) = handshakes.next(), if !handshakes.is_empty() => match shaken {
                Some(shaken)
                    if !*stop.borrow()
                        && tls_connections.len() < api.limits().max_connections =>
                {
                    tls_connections.push(api.tls_connection(shaken).boxed_local());
                }
                Some(_) => api.refuse(),
                None => {}
            },
        }
    }
}

/// `accept`, once `pause` has passed: the pause holds this one arm of serve's loop.
async fn after<T>(pause: Option<tokio::time::Instant>, accept: impl Future<Output = T>) -> T {
    if let Some(pause) = pause {
        tokio::time::sleep_until(pause).await;
    }
    accept.await
}

async fn accept_tls(tls: Option<&OwnerTls>) -> std::io::Result<(&OwnerTls, TcpStream)> {
    match tls {
        Some(tls) => tls.accept().await.map(|stream| (tls, stream)),
        None => std::future::pending().await,
    }
}

/// The key of the owner TLS certificate. Chosen here alone, so a serve that holds other wallets,
/// or none, changes one function.
fn owner_tls_key<N: NodeApi + 'static>(opened: &Opened<N>) -> Result<ApiTlsKey, CliError> {
    Ok(opened.wallet.api_tls_key()?)
}

async fn recv(
    events: Option<&mut broadcast::Receiver<Event>>,
) -> Result<Event, broadcast::error::RecvError> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

impl<H: Host> Run<'_, H> {
    pub(super) async fn serve(&mut self, args: ServeArgs) -> Result<Report, CliError> {
        let path = args
            .socket
            .clone()
            .unwrap_or_else(|| service::default_socket(&self.settings.data_dir));
        service::check_socket_path(&path)?;
        let owner_tls_address = args
            .owner_tls
            .then(|| {
                self.settings
                    .servers
                    .owner_tls
                    .ok_or(CliError::OwnerTlsNotConfigured)
            })
            .transpose()?;
        let borrowed = self.held.is_some();
        let opened = self.open().await?;
        let report = self
            .serve_opened(
                &opened,
                &path,
                owner_tls_address,
                &args,
                std::future::pending(),
            )
            .await;
        // Serve locks only a wallet it opened itself.
        if !borrowed {
            opened.wallet.lock();
        }
        report
    }

    /// Serves the API, owner TLS, Epicbox and maintenance on the open wallet `opened`, at the
    /// socket `path`, until `stop` completes or the run's interrupt fires, then drains the
    /// connections, shuts the listeners down and returns the report. Called by `lepic serve`
    /// and by the interactive shell's `serve start`. It never locks the wallet: the caller
    /// decides. Its future is not `Send` and needs a tokio runtime with time and net enabled.
    pub(crate) async fn serve_opened(
        &mut self,
        opened: &Arc<Opened<HostNode<H>>>,
        path: &std::path::Path,
        owner_tls_address: Option<std::net::SocketAddr>,
        args: &ServeArgs,
        stop_when: impl Future<Output = ()>,
    ) -> Result<Report, CliError> {
        let http = if args.http {
            Some(HttpListener::start(opened, self.settings, &args.listen).await?)
        } else {
            None
        };
        let owner_tls = match owner_tls_address {
            Some(address) => Some(
                OwnerTls::bind(address, &owner_tls_key(opened)?, &self.settings.data_dir).await?,
            ),
            None => None,
        };
        let listening = service::bind(path, &self.settings.data_dir)?;
        opened.epicbox.attach_wallet(&opened.wallet)?;
        let handle = ListenHandle::new();
        let swept = Mutex::new(Some(InvoiceSweep::default()));
        let stop = watch::Sender::new(false);
        let service = Service {
            host: self.host,
            settings: self.settings,
            held: Arc::clone(opened),
            interrupt: stop.subscribe(),
            maintenance: RefCell::default(),
            http: http.as_ref(),
            owner_tls: owner_tls.as_ref(),
            started: Instant::now(),
            epicbox: Cell::new(None),
            log: v1::Log::new(opened.wallet.api_event_last_id()?),
            scans: v1::Scans::default(),
        };
        let api = Api::new(
            &service,
            self.host.api_limits(self.settings.tuning.api),
            stop.subscribe(),
            self.settings.data_dir.clone(),
            crate::api::Caller::of(self.settings),
        );
        // The external stop ends serve as the interrupt does, then waits for the drain.
        let external = async {
            stop_when.await;
            finish_listen(&handle);
            stop.send_replace(true);
            std::future::pending::<Infallible>().await
        };
        let work = async {
            tokio::select! {
                result = serving(&service, &api, &listening, &handle, &swept, &stop) => result,
                never = external => match never {},
            }
        };
        let result = self
            .until_interrupted(opened.wallet.subscribe(), work, || {
                finish_listen(&handle);
                stop.send_replace(true);
            })
            .await;
        let requests = api.context().requests().served;
        drop(api);
        drop(service);
        let http = match http {
            Some(http) => Some(http.shutdown().await),
            None => None,
        };
        drop(owner_tls);
        drop(listening);
        let summary = result?;
        let expired = swept.into_inner().unwrap_or_else(PoisonError::into_inner);
        Ok(Report::Serve(ServeReport {
            socket: path.display().to_string(),
            requests,
            inbox: inbox_report(summary, expired),
            http,
        }))
    }
}

/// The integration tests' support, which the unit test of serve reuses.
#[cfg(test)]
#[path = "../../tests/support/mod.rs"]
mod support;

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use clap::Parser as _;

    use super::*;
    use crate::cli::Cli;
    use crate::commands::serve::support;

    /// Serve on a wallet the caller holds open ends on the external stop, reports, and leaves
    /// the wallet unlocked and the socket removed.
    #[test]
    fn serve_on_a_held_wallet_stops_on_the_signal_and_keeps_the_wallet_unlocked() {
        let (host, wallet) = support::funded();
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("s.sock");
        let socket_arg = socket.to_str().unwrap().to_owned();
        let cli = Cli::try_parse_from(["lepic", "serve", "--socket", &socket_arg]).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("not serve");
        };
        let env = Env::new(wallet.env());
        let settings = Settings::resolve(&cli.global, &env).unwrap();
        let mut console = Console {
            env,
            secrets: SecretInput::new(
                Box::new(BufReader::new(std::io::empty())),
                false,
                Box::new(std::io::sink()),
            ),
            stdout: Box::new(std::io::sink()),
            stderr: Box::new(std::io::sink()),
            ansi: false,
        };
        let (_keep, interrupt) = watch::channel(false);
        let report = std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let mut run = Run {
                        host: &host,
                        settings: &settings,
                        console: &mut console,
                        interrupt,
                        graceful: Arc::new(AtomicBool::new(false)),
                        held: None,
                        reviewed: None,
                    };
                    let opened = run.open().await.unwrap();
                    run.held = Some(Arc::clone(&opened));
                    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
                    let serve = run.serve_opened(&opened, &socket, None, &args, async {
                        let _ = stopped.await;
                    });
                    let driver = async {
                        while !socket.exists() {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        stop.send(()).unwrap();
                    };
                    let (report, ()) = tokio::join!(serve, driver);
                    assert!(opened.wallet.is_unlocked());
                    assert!(!socket.exists());
                    report.unwrap()
                })
            })
            .unwrap()
            .join()
            .unwrap();
        let Report::Serve(report) = report else {
            panic!("not a serve report");
        };
        assert_eq!(report.requests, 0);
        assert_eq!(report.socket, socket_arg);
    }
}
