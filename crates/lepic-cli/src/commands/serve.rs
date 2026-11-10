// SPDX-License-Identifier: Apache-2.0
//! `lepic serve`: holds one unlocked wallet, does what `epicbox listen` does, and answers the
//! wallet API on a local socket, and with `--owner-tls` over TLS too.

use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::future::Future;
use std::io::BufReader;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::future::LocalBoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt as _, StreamExt as _};
use jiff::Timestamp;
use lepic_epicbox::RelayEndpoint;
use lepic_methods::http::CoinbaseAccess;
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_transport::method::Method;
use lepic_wallet::ApiTlsKey;
use lepic_wallet::event::Event;
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet_contacts::CollectTrigger;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, watch};
use tokio::time::MissedTickBehavior;

use super::{
    HttpListener, InvoiceSweep, Opened, Run, abort_on, contact, finalize_slate, finish_listen,
    inbox_report, listen_and_sweep, profile, receive_slate, rekey,
};
use crate::Console;
use crate::amount::format_amount;
use crate::api::{Api, Call, Listener, Owner, OwnerTls, epicbox_state};
use crate::cli::{Command, ServeArgs};
use crate::exit::CliError;
use crate::host::{Host, HostNode};
use crate::output::{
    CarriesReport, ContactBackupReport, MaintenanceReport, MethodReport, MethodsReport,
    OwnerTlsStatus, Report, RequestsReport, ServeHttpStatus, ServeReport, ServeStatusReport,
    SlateReceiveReport,
};
use crate::secret::{SecretError, SecretInput};
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
    /// The owner TLS listener, when serve runs with `--owner-tls`.
    owner_tls: Option<&'a OwnerTls>,
    started: Instant,
    socket: String,
    /// The Epicbox listener's latest state.
    epicbox: Cell<Option<&'static str>>,
}

impl<H: Host> Service<'_, H> {
    /// Runs `command` as `lepic` runs it, with a console that has no input and discards output,
    /// so a command that asks for a secret fails.
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
        };
        tokio::select! {
            result = run.dispatch(command) => result,
            () = abort_on(self.interrupt.clone(), &graceful) => Err(CliError::Interrupted),
        }
    }

    async fn answer(&self, call: Call) -> Result<Report, CliError> {
        match call {
            Call::Command(command) => self.command(command).await,
            Call::Receive {
                wire,
                account,
                message,
            } => {
                let received = receive_slate(&self.held, &wire, account, message).await?;
                Ok(Report::SlateReceive(SlateReceiveReport {
                    tx_id: received.tx_id.0,
                    slate_id: received.slate.id().to_string(),
                    amount: format_amount(received.slate.amount()),
                    slate: received.reply.as_text().unwrap_or_default().to_owned(),
                    repeated: received.repeated,
                }))
            }
            Call::Finalize { wire, fluff } => finalize_slate(&self.held, &wire, fluff).await,
            // Serve holds the data directory lock, and `rekey` runs one change at a time, so the
            // vault cannot change under the rekey. Argon2id would hold the runtime thread, and every connection with it.
            Call::Password { current, new } => {
                if new.is_empty() {
                    return Err(SecretError::EmptyNew.into());
                }
                let kdf = self.host.vault_kdf();
                let data_dir = self.settings.data_dir.clone();
                tokio::task::spawn_blocking(move || rekey(kdf, &data_dir, current, new))
                    .await
                    .map_err(|error| CliError::Io {
                        what: "change the password",
                        source: std::io::Error::other(error),
                    })?
            }
            Call::ContactExport => Ok(Report::ContactBackup(ContactBackupReport {
                backup: contact::export_document(&self.held).await?,
            })),
            Call::ContactImport { document } => Ok(Report::ContactImport(
                contact::import_document(&self.held, document).await?,
            )),
            Call::Methods => Ok(Report::Methods(MethodsReport {
                methods: self
                    .held
                    .methods
                    .iter()
                    .map(|method| method_report(method.as_ref(), self.listens_on(method.as_ref())))
                    .collect(),
            })),
            Call::DomainFile { relays } => {
                profile::domain_document(&self.held, self.settings, &relays)
            }
        }
    }
}

/// What `method` can do, from its capabilities and from whether this serve receives slates
/// over it; nothing here connects anywhere.
fn method_report(method: &dyn Method, listens: bool) -> MethodReport {
    MethodReport {
        id: method.id().to_string(),
        delivers: method.outbound().is_some(),
        listens,
        exchanges: method.exchange().is_some(),
        notices: !method.notice_lengths().is_empty(),
        carries: CarriesReport {
            reply_key: method.carries().reply_key,
        },
    }
}

impl<H: Host> Service<'_, H> {
    /// Whether this serve receives slates over `method`: it always runs the Epicbox listener,
    /// and the HTTP listener when it runs with `--http`.
    fn listens_on(&self, method: &dyn Method) -> bool {
        let id = method.id();
        method.inbound().is_some()
            || id == lepic_epicbox::TRANSPORT_ID
            || (id == lepic_methods::http::TRANSPORT_ID && self.http.is_some())
    }
}

impl<H: Host> Owner for Service<'_, H> {
    fn call(&self, call: Call) -> Pin<Box<dyn Future<Output = Result<Report, CliError>> + '_>> {
        Box::pin(self.answer(call))
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.held.wallet.subscribe()
    }

    fn hint(&self, error: &CliError) -> Option<String> {
        crate::hint::hint(error, Some(self.settings))
    }

    fn status(&self, requests: RequestsReport) -> Result<Report, CliError> {
        let wallet = &self.held.wallet;
        let maintenance = self.maintenance.borrow();
        Ok(Report::ServeStatus(ServeStatusReport {
            socket: self.socket.clone(),
            uptime_s: self.started.elapsed().as_secs(),
            requests,
            epicbox: self.epicbox.get(),
            height: wallet.last_confirmed_height()?.map(Height::value),
            node_tip: wallet.confirmed_tip()?.map(|tip| tip.height.value()),
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
            owner_tls: self.owner_tls.map(|tls| OwnerTlsStatus {
                address: tls.address.to_string(),
                fingerprint: tls.fingerprint.to_string(),
            }),
        }))
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
/// connections, so connections from the network cannot use up the socket's.
async fn serving<H: Host>(
    service: &Service<'_, H>,
    api: &Api<'_>,
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
    tokio::pin!(listener, maintenance);
    let tls = service.owner_tls;
    let mut sockets = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut tls_connections = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut events = Some(opened.wallet.subscribe());
    let mut stopped = stop.subscribe();
    let mut ended = None;
    // Until when each listener's accept waits, after a failed accept.
    let mut socket_pause = None;
    let mut tls_pause = None;
    loop {
        match ended {
            Some(result) if sockets.is_empty() && tls_connections.is_empty() => return result,
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
                Ok((tls, stream)) if tls_connections.len() < api.limits().max_connections => {
                    tls_connections.push(api.tls_connection(tls, stream).boxed_local());
                }
                Ok(_) => api.refuse(),
                Err(error) => {
                    tracing::warn!(error = %error, "accepting a tls connection failed");
                    tls_pause = tokio::time::Instant::now().checked_add(ACCEPT_PAUSE);
                }
            },
            Some(()) = sockets.next(), if !sockets.is_empty() => {}
            Some(()) = tls_connections.next(), if !tls_connections.is_empty() => {}
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
        let opened = self.open().await?;
        let http = if args.http {
            Some(HttpListener::start(&opened, self.settings, &args.listen).await?)
        } else {
            None
        };
        let owner_tls = match owner_tls_address {
            Some(address) => Some(
                OwnerTls::bind(address, &owner_tls_key(&opened)?, &self.settings.data_dir).await?,
            ),
            None => None,
        };
        let listening = service::bind(&path, &self.settings.data_dir)?;
        opened.epicbox.attach_wallet(&opened.wallet)?;
        let handle = ListenHandle::new();
        let swept = Mutex::new(Some(InvoiceSweep::default()));
        let stop = watch::Sender::new(false);
        let service = Service {
            host: self.host,
            settings: self.settings,
            held: Arc::clone(&opened),
            interrupt: stop.subscribe(),
            maintenance: RefCell::default(),
            http: http.as_ref(),
            owner_tls: owner_tls.as_ref(),
            started: Instant::now(),
            socket: path.display().to_string(),
            epicbox: Cell::new(None),
        };
        let api = Api::new(
            &service,
            self.host.api_limits(self.settings.tuning.api),
            stop.subscribe(),
            self.settings.data_dir.clone(),
            crate::api::Caller::of(self.settings),
        );
        let result = self
            .until_interrupted(
                opened.wallet.subscribe(),
                serving(&service, &api, &listening, &handle, &swept, &stop),
                || {
                    finish_listen(&handle);
                    stop.send_replace(true);
                },
            )
            .await;
        let requests = api.requests().served;
        drop(api);
        drop(service);
        let http = match http {
            Some(http) => Some(http.shutdown().await),
            None => None,
        };
        drop(owner_tls);
        drop(listening);
        opened.wallet.lock();
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
