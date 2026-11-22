// SPDX-License-Identifier: Apache-2.0
//! `lepic serve`: holds one unlocked wallet, does what `epicbox listen` does, and answers the
//! wallet API on a local socket, and with `--owner-tls` over TLS too.

mod cli;
mod v1;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
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
use lepic_epicbox::sessions::{Owner, PushedConfig, PushedSessions, SessionEvent};
use lepic_epicbox::{MuxOptions, MuxState};
use lepic_node::NodeApi;
use lepic_primitives::amount::Height;
use lepic_wallet::ApiTlsKey;
use lepic_wallet::boost::Poller;
use lepic_wallet::event::Event;
use lepic_wallet::inbox::{InboxError, InboxSummary, ListenHandle};
use lepic_wallet::ports::Clock;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet_contacts::CollectTrigger;
use tokio::net::TcpStream;
use tokio::sync::{Notify, broadcast, watch};

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
use crate::settings::{Env, RelaySockets, RelayTor, Settings};
use crate::settings_file::Mailboxes;

/// How one maintenance task went since serve started, for `serve status`.
#[derive(Default)]
struct TaskStatus {
    /// Runs that failed in a row.
    failures: u32,
    /// Runs that failed since serve started.
    failures_total: u64,
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
                self.failures_total = self.failures_total.saturating_add(1);
                self.error = Some(lepic_telemetry::ErrorChain(&error).to_string());
            }
        }
    }
}

#[derive(Default)]
struct Maintenance {
    refresh: TaskStatus,
    collect: TaskStatus,
    /// The node's tip as the last refresh that reached the node saw it; none before the first.
    tip: Option<NodeTip>,
}

/// The node's tip, and when serve first saw it at that height.
#[derive(Clone, Copy)]
struct NodeTip {
    height: Height,
    changed_at: Timestamp,
}

impl Maintenance {
    fn saw_tip(&mut self, height: Height, now: Timestamp) {
        if self.tip.is_none_or(|tip| tip.height != height) {
            self.tip = Some(NodeTip {
                height,
                changed_at: now,
            });
        }
    }
}

/// What this serve saw of a push session since it started.
#[derive(Clone, Copy, Default)]
struct RelaySeen {
    /// When the session last attached; none while it is not attached.
    connected_since: Option<Timestamp>,
    last_mail_at: Option<Timestamp>,
}

/// [`RelaySeen`] for each push session, by relay and group.
type RelaysSeen = Mutex<BTreeMap<(String, String), RelaySeen>>;

/// Notes the change `event` reports in `seen`, at `now`.
fn saw_session(seen: &RelaysSeen, event: &SessionEvent, now: Timestamp) {
    let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
    match event {
        SessionEvent::State {
            relay,
            group,
            state,
        } => {
            let entry = seen.entry((relay.clone(), group.clone())).or_default();
            entry.connected_since = match state {
                MuxState::Attached => Some(entry.connected_since.unwrap_or(now)),
                _ => None,
            };
        }
        SessionEvent::MailQueued { relay, group } => {
            seen.entry((relay.clone(), group.clone()))
                .or_default()
                .last_mail_at = Some(now);
        }
        // An event added later says nothing this serve notes.
        _ => {}
    }
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
    relays: Arc<RelaysSeen>,
    /// The API's event log.
    log: v1::Log,
    scans: v1::Scans,
    /// The payment creates with an id, which serve makes even when their caller leaves.
    creates: v1::Creates,
    /// Whether `GET /api/v1/metrics` answers, from `--metrics`.
    metrics: bool,
    /// What the metrics count since serve started.
    counters: v1::Counters,
    /// The direct routes in-person codes name, from `--public-url`; empty, none.
    public_routes: Vec<lepic_wallet_contacts::RouteEntry>,
    /// The locks over this serve's checkout requests.
    checkout: v1::CheckoutLocks,
}

/// The variable `--public-url` falls back to, comma-separated.
const PUBLIC_URL_ENV: &str = "LEPIC_SERVE_PUBLIC_URL";

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
            stdout_terminal: false,
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

/// Runs the delivery layer's tick every `collect_every` and refreshes the wallet every
/// `refresh_every`, each once at start, records how each went in `status`, and tells
/// `wallet_refreshed` after each refresh that worked. Mail is read as the push sessions push
/// it: `pushed` runs a tick at once, or [`PUSH_FLOOR`] after the last one ended, which claims
/// new mailboxes on the sessions and handles the mail they queued. A tick that completed a
/// pairing is followed by another as soon, which claims the new contact's mailboxes. The first
/// tick, at start, and each tick of the timer also ask each push session how much waits, which
/// ends the pairings whose mailboxes were read after their deadline, counts the wait of contacts
/// not heard from and reports relays that do not answer. Every tick ends what expired and posts the
/// outbox rows and replies that are due; the first tries every row and relay at once. A boost of
/// the wallet (ADR 0058) shortens either interval while it lasts. A failure is logged and the next
/// run tries again.
async fn maintain<N: NodeApi + 'static>(
    opened: &Opened<N>,
    mailboxes: &Mailboxes,
    collect_every: Duration,
    refresh_every: Duration,
    status: &RefCell<Maintenance>,
    wallet_refreshed: &Notify,
    pushed: &Notify,
) -> Infallible {
    let boosts = opened.wallet.boosts();
    let mut boosted = boosts.changed();
    let after = |last: tokio::time::Instant, poller, base| {
        last.checked_add(boosts.interval(poller, base))
            .unwrap_or(last)
    };
    let start = tokio::time::Instant::now();
    let (mut collected, mut refreshed) = (start, start);
    let (mut next_collect, mut next_refresh) = (start, start);
    let mut trigger = CollectTrigger::Open;
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(next_collect) => {
                let cycle = contact::collect_online(opened, &mailboxes.current(), trigger).await;
                trigger = CollectTrigger::Foreground;
                if let Err(error) = &cycle {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(error),
                        "contact collect failed"
                    );
                }
                let paired = cycle.as_ref().is_ok_and(|paired| *paired > 0);
                let now = opened.wallet.ports().clock.now();
                status.borrow_mut().collect.record(cycle.map(drop), now);
                redeliver_classic(opened, now).await;
                collected = tokio::time::Instant::now();
                next_collect = after(collected, Poller::Relays, collect_every);
                if paired {
                    // A pairing that completed has mailboxes the sessions do not hold yet: the
                    // next tick claims them.
                    trigger = CollectTrigger::Push;
                    next_collect = next_collect.min(push_due(collected));
                }
            }
            () = tokio::time::sleep_until(next_refresh) => {
                let result = opened.wallet.refresh().await;
                if matches!(result, Ok(RefreshOutcome::Refreshed(_))) {
                    update_scan(opened).await;
                }
                let tip = result.as_ref().ok().map(|outcome| match outcome {
                    RefreshOutcome::Refreshed(summary) => summary.height,
                    RefreshOutcome::NodeBehind { tip, .. } => *tip,
                });
                let result = result.map(drop);
                if let Err(error) = &result {
                    tracing::warn!(
                        error = %lepic_telemetry::ErrorChain(error),
                        "wallet refresh failed"
                    );
                }
                if result.is_ok() {
                    wallet_refreshed.notify_one();
                }
                let now = opened.wallet.ports().clock.now();
                let mut maintenance = status.borrow_mut();
                maintenance.refresh.record(result, now);
                if let Some(tip) = tip {
                    maintenance.saw_tip(tip, now);
                }
                drop(maintenance);
                refreshed = tokio::time::Instant::now();
                next_refresh = after(refreshed, Poller::Node, refresh_every);
            }
            () = mailboxes.changed() => {
                // The next tick claims the changed list on the push sessions.
                if trigger != CollectTrigger::Open {
                    trigger = CollectTrigger::Push;
                }
                next_collect = next_collect.min(push_due(collected));
            }
            () = pushed.notified() => {
                // The first tick, still to come, reads everything anyway.
                if trigger != CollectTrigger::Open {
                    trigger = CollectTrigger::Push;
                }
                next_collect = next_collect.min(push_due(collected));
            }
            Ok(()) = boosted.changed() => {
                next_collect = next_collect.min(after(collected, Poller::Relays, collect_every));
                next_refresh = next_refresh.min(after(refreshed, Poller::Node, refresh_every));
            }
        }
    }
}

/// The wait before serve posts a send that did not reach its receiver the first time, and the
/// longest it grows to. Each failed attempt doubles it.
const REDELIVER_BASE: Duration = Duration::from_secs(60);
const REDELIVER_CAP: Duration = Duration::from_secs(3600);

/// How long after its last attempt serve tries an outbox row again: [`REDELIVER_BASE`] for the
/// first, twice that for the next, up to [`REDELIVER_CAP`].
fn redeliver_wait(attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(16);
    REDELIVER_BASE
        .saturating_mul(2u32.saturating_pow(doublings))
        .min(REDELIVER_CAP)
}

/// Posts again the classic sends over Epicbox whose slate no attempt got to the receiver, as
/// `POST /payments/{id}/deliver` does by hand, for each outbox row that waited out its back-off.
/// A row whose send is no longer waiting for its answer is left alone. A failure is logged; the
/// attempt is counted on the row, so the next try waits longer.
async fn redeliver_classic<N: NodeApi + 'static>(opened: &Opened<N>, now: Timestamp) {
    let Ok(store) = opened.store() else {
        return;
    };
    let pending = match lepic_store::WalletStore::read(&store, |repos| {
        repos.outbox(lepic_store::OutboxStatus::Pending)
    }) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(
                error = %lepic_telemetry::ErrorChain(&error),
                "outbox read for a repost failed"
            );
            return;
        }
    };
    for row in pending {
        let entry = row.entry;
        if entry.stage != lepic_store::SlateStage::Standard1
            || entry.transport != lepic_epicbox::TRANSPORT_ID.as_str()
        {
            continue;
        }
        let due = entry
            .updated_at
            .checked_add(redeliver_wait(entry.attempts))
            .unwrap_or(entry.updated_at);
        if now < due {
            continue;
        }
        if let Err(error) = redeliver_one(opened, &entry).await {
            tracing::warn!(
                error = %lepic_telemetry::ErrorChain(&error),
                slate_id = %entry.slate_id,
                attempts = entry.attempts,
                "repost of an undelivered send failed"
            );
        }
    }
}

/// Resends the send of one outbox row when it still waits for its answer undelivered.
async fn redeliver_one<N: NodeApi + 'static>(
    opened: &Opened<N>,
    entry: &lepic_store::OutboxEntry,
) -> Result<(), CliError> {
    let slate = lepic_wallet::event::SlateId::parse(&entry.slate_id.to_string())
        .map_err(|_| CliError::SlateId)?;
    let Some(details) = opened.wallet.sent_with_slate(slate).await? else {
        return Ok(());
    };
    if !details.undelivered {
        return Ok(());
    }
    let method = opened.send_method(lepic_epicbox::TRANSPORT_ID)?;
    let to = lepic_transport::transport::Destination::new(entry.destination.clone());
    opened
        .wallet
        .resend(
            method,
            details.transaction.id,
            lepic_wallet::send::Delivery::Deliver { to },
        )
        .await?;
    Ok(())
}

/// The least time between the end of one tick and a tick a push starts. Pushes come in bursts,
/// and with `relay_sockets = "shared"` a payment's mail wakes the contacts too, so pushes may
/// not run the tick back to back. Short, since a pairing takes several round trips that each
/// wait for a tick.
const PUSH_FLOOR: Duration = Duration::from_secs(1);

/// When a tick a push asks for may run: now, or [`PUSH_FLOOR`] after the last one ended.
fn push_due(collected: tokio::time::Instant) -> tokio::time::Instant {
    let floor = collected.checked_add(PUSH_FLOOR).unwrap_or(collected);
    floor.max(tokio::time::Instant::now())
}

/// Runs the short update scan after a refresh, as the app does: it records what another install
/// of the recovery phrase received as incoming entries from another wallet. A failure is logged
/// and the next refresh tries again.
pub(super) async fn update_scan<N: NodeApi + 'static>(opened: &Opened<N>) {
    if let Err(error) = opened.wallet.refresh_scan().await {
        tracing::warn!(
            error = %lepic_telemetry::ErrorChain(&error),
            "update scan after a refresh failed"
        );
    }
}

/// The mux/1 groups serve reads its payments and its contacts through, by `relay_sockets`: one
/// session a relay for both, or one for each. Warns when the sockets are split but all come from
/// one address, without tor.
fn mail_groups(settings: &Settings) -> (&'static str, &'static str) {
    match settings.relay_sockets {
        RelaySockets::Shared => ("wallet", "wallet"),
        RelaySockets::Split => {
            if settings.relay_tor == RelayTor::Off {
                tracing::warn!(
                    "relay_sockets is split but the relays are reached without tor: every socket \
                     comes from the same address, so the split hides little"
                );
            }
            ("payments", "contacts")
        }
    }
}

/// Makes the contacts collect read pushed mail through sessions of `group` while it lives, and
/// lets go of the sessions when it is dropped, as serve ends.
struct ContactsPushed<'a>(&'a PushedSessions);

impl<'a> ContactsPushed<'a> {
    fn start(pushed: &'a PushedSessions, group: &str) -> Self {
        pushed.set_contacts(Some(PushedConfig {
            group: group.to_owned(),
            options: MuxOptions::default(),
        }));
        Self(pushed)
    }
}

impl Drop for ContactsPushed<'_> {
    fn drop(&mut self) {
        self.0.set_contacts(None);
        self.0.release(Owner::Contacts);
    }
}

/// Wakes `wake` each time a contacts session of `group` attaches, at start and after each
/// reconnect, and each time its relay pushes mail. The collect that follows reads the mail, and
/// after a reconnect it catches up on what came while the socket was down. Notes every
/// session's changes in `seen`, for `GET /status`.
async fn follow_pushes(
    pushed: &PushedSessions,
    group: &str,
    wake: &Arc<Notify>,
    seen: &Arc<RelaysSeen>,
    clock: &Arc<dyn Clock>,
) -> Infallible {
    let (group, wake, seen, clock) = (
        group.to_owned(),
        Arc::clone(wake),
        Arc::clone(seen),
        Arc::clone(clock),
    );
    pushed
        .watch(move |event| {
            saw_session(&seen, &event, clock.now());
            match event {
                SessionEvent::MailQueued { group: of, .. }
                | SessionEvent::State {
                    group: of,
                    state: MuxState::Attached,
                    ..
                } if of == group => wake.notify_one(),
                _ => {}
            }
        })
        .await;
    // The sessions outlive serve, so the watch does not end first.
    std::future::pending().await
}

/// How long a listener stops accepting after an accept failed, as when serve is out of file
/// descriptors, so a failure that repeats does not spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// What serve runs beside the listener and the API until it stops, none of which ends: the
/// wallet's refresh and the delivery layer's tick, the push sessions of `contacts` that start a
/// tick and the claims they hold for pairings, and the event log's writer, scans and webhook.
async fn upkeep<H: Host>(service: &Service<'_, H>, contacts: &str) -> Infallible {
    let opened = &*service.held;
    let mailboxes = &service.settings.servers.mailboxes;
    let wake = Arc::new(Notify::new());
    tokio::select! {
        never = maintain(
            opened,
            mailboxes,
            service.host.collect_interval(),
            service.host.maintenance_interval(),
            &service.maintenance,
            service.log.refreshed(),
            &wake,
        ) => never,
        never = follow_pushes(
            opened.epicbox.pushed(),
            contacts,
            &wake,
            &service.relays,
            &opened.wallet.ports().clock,
        ) => never,
        never = contact::claim_pairings(opened, mailboxes) => never,
        never = v1::event_writer(service) => never,
        never = v1::scan_driver(service) => never,
        never = v1::webhook_driver(service) => never,
        never = v1::checkout_driver(service) => never,
    }
}

/// Listens, maintains the wallet and answers the API until `stop` turns true and the listener,
/// the connections and the payment creates with an id have ended, or until the host's drain
/// deadline after the stop has passed or a second stop signal comes, which drops what is left. The stop closes each
/// connection once its answer is out, and a failed listener sets it. The socket and the owner
/// TLS listener each have their own cap on connections, so connections from the network cannot
/// use up the socket's. A TLS connection takes its slot once its handshake ends; handshakes have
/// a cap of the same size of their own, so connections that never finish one do not hold the
/// slots of listed clients. A connection over a cap is answered 503 `busy` with `Retry-After`,
/// up to as many again as the cap; past that it is closed unanswered.
#[allow(clippy::too_many_lines)] // One select loop over every listener serve holds.
async fn serving<H: Host>(
    service: &Service<'_, H>,
    api: &Api<'_, Service<'_, H>>,
    listening: &Listening,
    handle: &ListenHandle,
    swept: &Mutex<Option<InvoiceSweep>>,
    stop: &watch::Sender<bool>,
) -> Result<InboxSummary, InboxError> {
    let opened = &*service.held;
    let (payments, contacts) = mail_groups(service.settings);
    let _contacts_pushed = ContactsPushed::start(opened.epicbox.pushed(), contacts);
    // Both are large futures: on the heap, so serve's own frame stays small on the thread's stack.
    let mut listener = Box::pin(listen_and_sweep(
        opened,
        opened
            .epicbox
            .listen_via(&opened.wallet, handle, payments, MuxOptions::default()),
        service.settings.invoice_expiry,
        swept,
    ));
    let mut upkeep = Some(upkeep(service, contacts).boxed_local());
    let tls = service.owner_tls;
    let mut sockets = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut tls_connections = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut handshakes = FuturesUnordered::<LocalBoxFuture<'_, Option<Shaken>>>::new();
    let mut creates = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    // Connections over a cap, answered 503 `busy`; as many again as the cap, past which they
    // are closed unanswered.
    let mut socket_busy = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut tls_busy = FuturesUnordered::<LocalBoxFuture<'_, ()>>::new();
    let mut events = Some(opened.wallet.subscribe());
    let mut stopped = stop.subscribe();
    let mut ended = None;
    // Set once the stop is seen: when the drain gives up.
    let mut leaving: Option<LocalBoxFuture<'_, ()>> = None;
    // Until when each listener's accept waits, after a failed accept.
    let mut socket_pause = None;
    let mut tls_pause = None;
    loop {
        match ended {
            Some(result)
                if sockets.is_empty()
                    && tls_connections.is_empty()
                    && handshakes.is_empty()
                    && service.creates.idle() =>
            {
                return result;
            }
            _ => {}
        }
        let stopping = *stop.borrow();
        if stopping {
            // Nothing of the upkeep is polled from here, and a half-done cycle may hold a turn of
            // the wallet that a request in the drain waits for: dropping it frees them.
            upkeep = None;
            if leaving.is_none() {
                leaving = Some(leave(service.host).boxed_local());
            }
        }
        tokio::select! {
            result = &mut listener, if ended.is_none() => {
                ended = Some(result);
                stop.send_replace(true);
            }
            never = keeping(upkeep.as_mut()) => match never {},
            () = waiting(leaving.as_mut()) => {
                // What is left is dropped with this function: the connections close, and a
                // create with an id is made by its repeat, as after a crash.
                return ended.unwrap_or_else(|| Ok(InboxSummary::default()));
            }
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
                Ok(stream) if listening.is_this_user(&stream) => {
                    let max = api.limits().max_connections;
                    if sockets.len() < max {
                        sockets.push(api.connection(stream, Listener::Socket, None).boxed_local());
                    } else if socket_busy.len() < max {
                        socket_busy.push(api.busy_connection(stream).boxed_local());
                    } else {
                        api.refuse();
                    }
                }
                Ok(_) => api.refuse(),
                Err(error) => {
                    tracing::warn!(error = %error, "accepting a connection failed");
                    socket_pause = tokio::time::Instant::now().checked_add(ACCEPT_PAUSE);
                }
            },
            accepted = after(tls_pause, accept_tls(tls)), if !stopping => match accepted {
                Ok((tls, stream)) => {
                    let max = api.limits().max_connections;
                    if handshakes.len() < max {
                        handshakes.push(api.tls_handshake(tls, stream).boxed_local());
                    } else if tls_busy.len() < max {
                        tls_busy.push(api.tls_busy_handshake(tls, stream).boxed_local());
                    } else {
                        api.refuse();
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "accepting a tls connection failed");
                    tls_pause = tokio::time::Instant::now().checked_add(ACCEPT_PAUSE);
                }
            },
            jobs = service.creates.next() => {
                for job in jobs {
                    creates.push(v1::make_queued(service, job).boxed_local());
                }
            }
            Some(()) = creates.next(), if !creates.is_empty() => {}
            Some(()) = sockets.next(), if !sockets.is_empty() => {}
            Some(()) = tls_connections.next(), if !tls_connections.is_empty() => {}
            Some(shaken) = handshakes.next(), if !handshakes.is_empty() => match shaken {
                Some(shaken) if !*stop.borrow() => {
                    let max = api.limits().max_connections;
                    if tls_connections.len() < max {
                        tls_connections.push(api.tls_connection(shaken).boxed_local());
                    } else if tls_busy.len() < max {
                        tls_busy.push(api.tls_busy(shaken).boxed_local());
                    } else {
                        api.refuse();
                    }
                }
                Some(_) => api.refuse(),
                None => {}
            },
            Some(()) = socket_busy.next(), if !socket_busy.is_empty() => {}
            Some(()) = tls_busy.next(), if !tls_busy.is_empty() => {}
        }
    }
}

/// The upkeep, polled while there is one; never ends.
async fn keeping(upkeep: Option<&mut LocalBoxFuture<'_, Infallible>>) -> Infallible {
    match upkeep {
        Some(upkeep) => upkeep.await,
        None => std::future::pending().await,
    }
}

/// `leaving`, once there is one.
async fn waiting(leaving: Option<&mut LocalBoxFuture<'_, ()>>) {
    match leaving {
        Some(leaving) => leaving.await,
        None => std::future::pending().await,
    }
}

/// Ends when a stopping serve should stop waiting for its connections: after the host's drain
/// deadline, or at the next stop signal, whichever comes first.
async fn leave<H: Host>(host: &H) {
    let mut hurried = host.hurried();
    tokio::select! {
        () = tokio::time::sleep(host.drain_deadline()) => {
            tracing::warn!("serve stopped waiting for its connections after the drain deadline");
        }
        () = &mut hurried => {
            tracing::warn!("serve stopped waiting for its connections at a second stop signal");
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
        // A route every payer refuses is refused before the wallet opens.
        self.public_routes(&args)?;
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

    /// The direct routes of `--public-url`, or of [`PUBLIC_URL_ENV`] when the option is not
    /// given: the flag wins over the variable, as clap's own `env` would have it. Fails on an
    /// address every payer refuses.
    fn public_routes(
        &self,
        args: &ServeArgs,
    ) -> Result<Vec<lepic_wallet_contacts::RouteEntry>, CliError> {
        let from_env: Vec<String> = match self.console.env.get(PUBLIC_URL_ENV) {
            Some(urls) if args.public_url.is_empty() => vec![urls.to_owned()],
            _ => Vec::new(),
        };
        v1::public_routes(if from_env.is_empty() {
            &args.public_url
        } else {
            &from_env
        })
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
        let public_routes = self.public_routes(args)?;
        let http = if args.http {
            Some(
                HttpListener::start(
                    opened,
                    self.settings,
                    &args.listen,
                    !public_routes.is_empty(),
                )
                .await?,
            )
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
            relays: Arc::default(),
            log: v1::Log::new(opened.wallet.api_event_last_id()?),
            scans: v1::Scans::default(),
            creates: v1::Creates::default(),
            metrics: args.metrics,
            counters: v1::Counters::default(),
            public_routes,
            checkout: v1::CheckoutLocks::default(),
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

/// The integration tests' support, which the unit tests of serve and the shell reuse.
#[cfg(test)]
#[path = "../../tests/cli/support/mod.rs"]
pub(crate) mod support;

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
        let settings = Settings::resolve(&cli.global, &env)
            .unwrap()
            .on_host_network(crate::host::Host::network(&host));
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
            stdout_terminal: false,
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
