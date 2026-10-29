// SPDX-License-Identifier: Apache-2.0
//! The wallet's tor (ADR 0018): one tor per session, with a listener of its own on
//! `127.0.0.1` that the onion forwards to, and sends to other wallets' onions.

use std::error::Error as StdError;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use lepic_epicbox::RelayStream;
use lepic_epicbox::tunnel::Tunnel;
use lepic_foreign::ListenerHandle;
use lepic_store::TxId;
use lepic_tor::{
    FailureKind, OnionAddress, RelayTor, SendFailure, SocksProxy, TRANSPORT_ID, TorProcess,
    TorSendError, TorSettings, TorState, TorTransport,
};
use lepic_transport::transport::{BoxFuture, Destination};
use lepic_wallet::OnionKey;
use lepic_wallet::send::{Delivery, SendError};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::http::HttpReport;
use super::{DEFAULT_ACCOUNT, Session, invalid, lock};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::http::{HttpListenerEvent, HttpListenerEventKind, HttpResentTx, HttpSentTx};
use crate::api::tor::{
    OnionRoute, TorEvent, TorEventKind, TorFailureKind, TorStatus, TorStatusKind,
};

/// More onion routes than any signed list holds.
const MAX_ONION_ROUTES: usize = 256;
use crate::api::types::SendOptions;

/// Where the tor events of a session go.
pub(crate) type TorReport = Arc<dyn Fn(TorEvent) + Send + Sync>;

/// The directory inside the wallet's data directory that holds its tor's files.
const TOR_DIR: &str = "tor";

/// The file inside the wallet's data directory that says tor was expected and not stopped
/// since: the next session waits for tor from its first connection.
const TOR_EXPECTED_FILE: &str = "tor-expected";

/// The relay connection and node requests of a session on `data_dir`. They wait for tor from
/// the start when the last session there expected one and the app did not stop it, so a
/// connection made before the app calls [`Session::expect_tor`] never goes directly; else
/// they go directly until tor is expected or started.
pub(super) fn session_routes(data_dir: &std::path::Path) -> (RelayTor, RelayTor) {
    let expected = !cfg!(target_os = "ios") && data_dir.join(TOR_EXPECTED_FILE).exists();
    let routes = if expected {
        RelayTor::new
    } else {
        RelayTor::direct
    };
    (routes(true), routes(true))
}

/// `routes` after checking every one: a host name, an onion v3 host and two ports that are not
/// 0, and at most [`MAX_ONION_ROUTES`] of them.
pub(super) fn checked_onion_routes(
    routes: Vec<OnionRoute>,
) -> Result<Vec<lepic_epicbox::tunnel::OnionRoute>, WalletError> {
    if routes.len() > MAX_ONION_ROUTES {
        return Err(invalid("too many onion routes"));
    }
    routes
        .into_iter()
        .map(|route| {
            let domain = lepic_epicbox::Domain::parse(&route.host)
                .map_err(|_| invalid("onion route host is not a host name"))?;
            let onion = lepic_tor::parse_onion(&route.onion)
                .map_err(|_| invalid("onion route onion is not an onion v3 address"))?;
            if route.port == 0 || route.onion_port == 0 {
                return Err(invalid("onion route port is 0"));
            }
            Ok(lepic_epicbox::tunnel::OnionRoute {
                domain,
                port: route.port,
                onion: onion.host(),
                onion_port: route.onion_port,
            })
        })
        .collect()
}

/// How long a start waits for the tor that is stopping to be down: the tor it stops shares
/// the data directory with the new one.
const STOPPING_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The tor of a session.
#[derive(Default)]
pub(super) enum TorSlot {
    #[default]
    Idle,
    /// Starting; the number tells this start from a later one.
    Starting(u64),
    Running(Box<TorRun>),
    /// Stopped, with tor and its listener going down; `true` once both are, or when the
    /// task that stops them ended without saying so.
    Stopping(watch::Receiver<bool>),
}

impl TorSlot {
    /// Idle when it was stopping and that is done.
    fn settle(&mut self) {
        if let Self::Stopping(down) = self
            && (*down.borrow() || down.has_changed().is_err())
        {
            *self = Self::Idle;
        }
    }
}

pub(super) struct TorRun {
    generation: u64,
    tor: Arc<TorProcess>,
    listener: ListenerHandle,
    report: TorReport,
    /// Forwards tor's states to `report` and publishes the onion.
    driver: JoinHandle<()>,
    /// Why the onion could not be published while tor still runs for sends.
    publish_failure: Arc<std::sync::Mutex<Option<TorFailureKind>>>,
}

/// The wallet's tor as the way to its Epicbox relay.
pub(super) struct RelayTunnel(pub(super) Arc<RelayTor>);

/// Where the relay connection goes after a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Routes {
    /// Directly: tor is no longer expected.
    Direct,
    /// Through the next tor, which the app starts.
    Waiting,
    /// As before: the stop found nothing to stop.
    Unchanged,
}

impl Tunnel for RelayTunnel {
    fn active(&self) -> watch::Receiver<bool> {
        self.0.active()
    }

    fn open<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, std::io::Result<Box<dyn RelayStream>>> {
        Box::pin(async move {
            let stream = self
                .0
                .open(host, port)
                .await
                .map_err(std::io::Error::other)?;
            Ok(Box::new(stream) as Box<dyn RelayStream>)
        })
    }

    fn is_onion(&self, host: &str) -> bool {
        RelayTor::is_onion(host)
    }
}

pub(super) fn tor_transport() -> TorTransport {
    TorTransport::new(lepic_tor::OnionClient::default())
}

const fn failure_kind(kind: FailureKind) -> TorFailureKind {
    match kind {
        FailureKind::Missing => TorFailureKind::Missing,
        FailureKind::Network => TorFailureKind::Network,
        FailureKind::Clock => TorFailureKind::Clock,
        FailureKind::Listener => TorFailureKind::Listener,
        FailureKind::Stopped => TorFailureKind::Stopped,
        FailureKind::Publish => TorFailureKind::Publish,
        FailureKind::Keys => TorFailureKind::Keys,
        _ => TorFailureKind::Start,
    }
}

fn failed(kind: TorFailureKind) -> TorEvent {
    TorEvent {
        failure: Some(kind),
        ..TorEvent::of(TorEventKind::Failed)
    }
}

/// The event for a state of tor, if the app hears of it. `Off` is reported as `Stopped` once
/// the listener is down too.
fn state_event(state: &TorState) -> Option<TorEvent> {
    Some(match state {
        TorState::Starting { progress, .. } => TorEvent {
            progress: Some(*progress),
            ..TorEvent::of(TorEventKind::Starting)
        },
        TorState::Bootstrapped => TorEvent::of(TorEventKind::Bootstrapped),
        TorState::Publishing => TorEvent::of(TorEventKind::Publishing),
        TorState::Ready { onion } => TorEvent {
            onion: Some(onion.host()),
            ..TorEvent::of(TorEventKind::Ready)
        },
        TorState::Failed(failure) => failed(failure_kind(failure.kind)),
        _ => return None,
    })
}

/// How far tor got, in the order the app hears of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Starting,
    Bootstrapped,
    Publishing,
    Ready,
}

const fn phase(state: &TorState) -> Option<Phase> {
    match state {
        TorState::Starting { .. } => Some(Phase::Starting),
        TorState::Bootstrapped => Some(Phase::Bootstrapped),
        TorState::Publishing => Some(Phase::Publishing),
        TorState::Ready { .. } => Some(Phase::Ready),
        _ => None,
    }
}

/// The events for a new state of tor. The state is watched, so steps that follow each other
/// quickly are seen as their last one; a phase passed that way is still reported, before the
/// state's own event, so the app always hears `Bootstrapped` before `Publishing` and
/// `Publishing` before `Ready`.
fn state_events(reported: &mut Phase, state: &TorState) -> Vec<TorEvent> {
    let mut events = Vec::new();
    if let Some(now) = phase(state) {
        for (passed, kind) in [
            (Phase::Bootstrapped, TorEventKind::Bootstrapped),
            (Phase::Publishing, TorEventKind::Publishing),
        ] {
            if *reported < passed && passed < now {
                events.push(TorEvent::of(kind));
            }
        }
        *reported = (*reported).max(now);
    }
    events.extend(state_event(state));
    events
}

/// Payments the listener behind the onion handled, as tor events.
fn listener_report(report: &TorReport) -> HttpReport {
    let report = Arc::clone(report);
    Arc::new(move |event: HttpListenerEvent| {
        let kind = match event.kind {
            HttpListenerEventKind::Received => TorEventKind::Received,
            HttpListenerEventKind::Refused => TorEventKind::Refused,
            _ => return,
        };
        report(TorEvent {
            tx_id: event.tx_id,
            amount: event.amount,
            repeated: event.repeated,
            refusal: event.refusal,
            ..TorEvent::of(kind)
        });
    })
}

fn onion(text: &str) -> Result<OnionAddress, WalletError> {
    lepic_tor::parse_onion(text)
        .map_err(|error| WalletError::new(WalletErrorKind::OnionAddressInvalid, error.to_string()))
}

fn delivery(onion: &OnionAddress) -> Delivery {
    Delivery::Deliver {
        transport: TRANSPORT_ID,
        to: Destination::new(onion.host()),
    }
}

/// What a failed send over Tor means for the app: the kind of the Tor failure inside, or the
/// kind every failed delivery has.
fn send_error(error: SendError) -> WalletError {
    let mut tor_kind = None;
    let mut source: Option<&(dyn StdError + 'static)> = Some(&error);
    while let Some(current) = source {
        if let Some(tor) = current.downcast_ref::<TorSendError>() {
            tor_kind = match tor.class() {
                SendFailure::TorOff => Some(WalletErrorKind::TorNotRunning),
                SendFailure::Unreachable => Some(WalletErrorKind::OnionUnreachable),
                _ => None,
            };
            break;
        }
        source = current.source();
    }
    let mut wallet_error = WalletError::from(error);
    if let Some(kind) = tor_kind {
        wallet_error.kind = kind;
        wallet_error.code = kind.code();
    }
    wallet_error
}

impl Session {
    pub(crate) fn onion_address(&self) -> Result<String, WalletError> {
        let key = self.engine.onion_key()?;
        Ok(lepic_tor::onion_address(key.public_key()))
    }

    /// Starts tor and its listener unless tor runs or starts, and reports what they do to
    /// `report`.
    ///
    /// A start while the tor stopped last is still going down waits for it, as both use the
    /// same data directory; one that waits too long reports `Failed` and `Stopped`. iOS runs
    /// no tor: there `Failed` with [`TorFailureKind::Missing`] and `Stopped` are reported at
    /// once. Android runs the tor the app installs as a native library.
    pub(crate) async fn start_tor(
        self: &Arc<Self>,
        tor_binary: String,
        lib_dir: Option<String>,
        report: TorReport,
    ) -> Result<(), WalletError> {
        let key = self.engine.onion_key()?;
        if cfg!(target_os = "ios") {
            report(failed(TorFailureKind::Missing));
            report(TorEvent::of(TorEventKind::Stopped));
            return Ok(());
        }
        let generation = self.tor_starts.fetch_add(1, Ordering::Relaxed);
        loop {
            let mut down = {
                let mut slot = lock(&self.tor_slot);
                // Checked again under the slot lock: a lock that ran since stops only a tor
                // it finds in the slot.
                self.ensure_unlocked()?;
                slot.settle();
                match &*slot {
                    TorSlot::Idle => {
                        *slot = TorSlot::Starting(generation);
                        // The relay connection waits for this tor instead of going directly.
                        self.tor_expected.store(false, Ordering::Relaxed);
                        self.expect_routes();
                        break;
                    }
                    TorSlot::Stopping(down) => down.clone(),
                    TorSlot::Starting(_) | TorSlot::Running(_) => return Ok(()),
                }
            };
            // An error is a stopping task that ended without saying so: settled above.
            let waited = tokio::time::timeout(STOPPING_WAIT, down.wait_for(|down| *down)).await;
            if waited.is_err() {
                debug!(transport = "tor", "the tor stopped last is not down yet");
                report(failed(TorFailureKind::Start));
                report(TorEvent::of(TorEventKind::Stopped));
                return Ok(());
            }
        }
        let receiver = self.http_receiver(listener_report(&report), TRANSPORT_ID);
        let listening = lepic_foreign::listen(lepic_tor::listen_settings(), receiver).await;
        let listener = match listening {
            Ok(listener) => listener,
            Err(error) => {
                let mut slot = lock(&self.tor_slot);
                // The relay connection keeps waiting, as after tor ending on its own.
                if matches!(&*slot, TorSlot::Starting(started) if *started == generation) {
                    *slot = TorSlot::Idle;
                }
                drop(slot);
                debug!(transport = "tor", error = %error, "tor listener not started");
                report(failed(TorFailureKind::Listener));
                report(TorEvent::of(TorEventKind::Stopped));
                return Ok(());
            }
        };
        let mut settings = TorSettings::new(PathBuf::from(tor_binary), self.data_dir.join(TOR_DIR));
        settings.lib_dir = lib_dir.map(PathBuf::from);
        #[cfg(test)]
        if let Some(timings) = *lock(&self.tor_timings) {
            settings.timings = timings;
        }
        let port = listener.local_addr().port();
        let unclaimed = {
            let mut slot = lock(&self.tor_slot);
            if matches!(&*slot, TorSlot::Starting(started) if *started == generation) {
                let tor = Arc::new(TorProcess::start(settings));
                let publish_failure = Arc::default();
                let driver = self.runtime().boundary.handle.spawn(drive(
                    Arc::downgrade(self),
                    generation,
                    Arc::clone(&tor),
                    key,
                    port,
                    Arc::clone(&report),
                    Arc::clone(&publish_failure),
                ));
                self.tor
                    .attach(Arc::clone(&tor) as Arc<dyn SocksProxy + 'static>);
                self.attach_routes(&tor);
                *slot = TorSlot::Running(Box::new(TorRun {
                    generation,
                    tor,
                    listener,
                    report: Arc::clone(&report),
                    driver,
                    publish_failure,
                }));
                None
            } else {
                Some(listener)
            }
        };
        // Stopped or locked while the listener was binding.
        if let Some(listener) = unclaimed {
            listener.shutdown().await;
            report(TorEvent::of(TorEventKind::Stopped));
        }
        Ok(())
    }

    /// Stops tor, then its listener. `Stopped` is reported once both are down; until then the
    /// slot is `Stopping`.
    ///
    /// A stop that lets the relay go directly again also forgets that tor was expected, so
    /// the next session starts direct.
    pub(crate) fn stop_tor(&self) {
        if self.stop_tor_of_start(None) == Routes::Direct {
            self.forget_tor_expected();
        }
    }

    /// Stops tor as a lock does: a session opened later still waits for tor when this one
    /// expected it.
    pub(super) fn stop_tor_for_lock(&self) {
        self.stop_tor_of_start(None);
    }

    /// Stops the tor of start `generation` if it is still the one in the slot.
    fn stop_tor_of(&self, generation: u64) {
        self.stop_tor_of_start(Some(generation));
    }

    /// Stops the tor in the slot, or only the one of start `generation`, and says where the
    /// relay connection goes now.
    fn stop_tor_of_start(&self, generation: Option<u64>) -> Routes {
        let mut slot = lock(&self.tor_slot);
        let run = match &*slot {
            TorSlot::Running(run) if generation.is_none_or(|start| start == run.generation) => {
                std::mem::take(&mut *slot)
            }
            TorSlot::Starting(_) if generation.is_none() => {
                // The start finds the slot changed and stops what it started.
                *slot = TorSlot::Idle;
                return self.end_expectation();
            }
            TorSlot::Idle if generation.is_none() => {
                // Ends what `expect_tor` announced, unless it was announced again for a
                // restart.
                return self.end_expectation();
            }
            _ => return Routes::Unchanged,
        };
        // Under the slot lock, so a start that follows attaches after this detach.
        self.tor.detach();
        // Tor ended on its own, or the app restarts it: the relay connection waits for the
        // next start. Only stopping tor or turning the setting off leads back to a direct
        // connection.
        let routes = if generation.is_some() || self.tor_expected.swap(false, Ordering::Relaxed) {
            self.expect_routes();
            Routes::Waiting
        } else {
            self.detach_routes();
            Routes::Direct
        };
        let (down, down_receiver) = watch::channel(false);
        *slot = TorSlot::Stopping(down_receiver);
        drop(slot);
        if let TorSlot::Running(run) = run {
            // A runtime that is shutting down drops the task, and with it `down`; tor is then
            // killed with the process handle and the listener's socket closes with the
            // runtime.
            drop(self.runtime().boundary.handle.spawn(shut_down(*run, down)));
        }
        routes
    }

    /// No tor runs or starts: the relay connection goes directly, unless tor was expected
    /// again for a restart.
    fn end_expectation(&self) -> Routes {
        if self.tor_expected.swap(false, Ordering::Relaxed) {
            Routes::Waiting
        } else {
            self.detach_routes();
            Routes::Direct
        }
    }

    /// Records that tor is expected, for the sessions opened on this wallet later. Without
    /// the record a later session waits for tor only once the app expects it again.
    fn remember_tor_expected(&self) {
        if let Err(error) = std::fs::write(self.data_dir.join(TOR_EXPECTED_FILE), []) {
            warn!(transport = "tor", error = %error, "tor expectation not recorded");
        }
    }

    fn forget_tor_expected(&self) {
        match std::fs::remove_file(self.data_dir.join(TOR_EXPECTED_FILE)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(transport = "tor", error = %error, "tor expectation not removed"),
        }
    }

    pub(crate) fn tor_status(&self) -> TorStatus {
        let off = TorStatus {
            kind: TorStatusKind::Off,
            progress: None,
            onion: None,
            socks_port: None,
            failure: None,
        };
        let mut slot = lock(&self.tor_slot);
        slot.settle();
        let run = match &*slot {
            TorSlot::Idle | TorSlot::Stopping(_) => return off,
            TorSlot::Starting(_) => {
                return TorStatus {
                    kind: TorStatusKind::Starting,
                    progress: Some(0),
                    ..off
                };
            }
            TorSlot::Running(run) => run,
        };
        let failure = *lock(&run.publish_failure);
        let socks_port = run.tor.socks_address().map(|address| address.port());
        match run.tor.state() {
            TorState::Starting { progress, .. } => TorStatus {
                kind: TorStatusKind::Starting,
                progress: Some(progress),
                ..off
            },
            TorState::Bootstrapped => TorStatus {
                kind: TorStatusKind::Bootstrapped,
                socks_port,
                failure,
                ..off
            },
            TorState::Publishing => TorStatus {
                kind: TorStatusKind::Publishing,
                socks_port,
                ..off
            },
            TorState::Ready { onion } => TorStatus {
                kind: TorStatusKind::Ready,
                onion: Some(onion.host()),
                socks_port,
                ..off
            },
            _ => off,
        }
    }

    /// Wakes the running tor after a pause and, when `network_changed`, has it build new
    /// connections. Nothing to do while tor is still being started.
    pub(crate) async fn refresh_tor(&self, network_changed: bool) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let tor = {
            let mut slot = lock(&self.tor_slot);
            slot.settle();
            match &*slot {
                TorSlot::Running(run) => Arc::clone(&run.tor),
                TorSlot::Starting(_) => return Ok(()),
                TorSlot::Idle | TorSlot::Stopping(_) => return Err(tor_not_running()),
            }
        };
        // A tor that failed the refresh has ended; its stream reports `Failed` and `Stopped`.
        tor.refresh(network_changed).await.map_err(|failure| {
            debug!(transport = "tor", error = %failure, "tor not refreshed");
            tor_not_running()
        })
    }

    /// Turns the running tor's network off until the next [`Session::refresh_tor`]. Nothing to
    /// do without a running tor, locked or not, or while it is still being started.
    pub(crate) async fn tor_network_lost(&self) -> Result<(), WalletError> {
        let tor = {
            let mut slot = lock(&self.tor_slot);
            slot.settle();
            match &*slot {
                TorSlot::Running(run) => Arc::clone(&run.tor),
                TorSlot::Starting(_) | TorSlot::Idle | TorSlot::Stopping(_) => return Ok(()),
            }
        };
        // A tor that failed to answer has ended; its stream reports `Failed` and `Stopped`.
        tor.network_lost().await.map_err(|failure| {
            debug!(transport = "tor", error = %failure, "tor network not turned off");
            tor_not_running()
        })
    }

    /// Where the `Sending` of a send goes, once tor can send; checked before anything is
    /// stored.
    fn tor_send_report(&self) -> Result<TorReport, WalletError> {
        let slot = lock(&self.tor_slot);
        let TorSlot::Running(run) = &*slot else {
            return Err(tor_not_running());
        };
        if run.tor.socks_address().is_none() {
            return Err(tor_not_running());
        }
        Ok(Arc::clone(&run.report))
    }

    pub(crate) async fn send_tor(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        to: &str,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<HttpSentTx, WalletError> {
        let request = Self::send_request_with(amount, minimum_confirmations, message, options)?;
        let onion = onion(to)?;
        let report = self.tor_send_report()?;
        // The checks the send makes before it stores anything, so a send that cannot be
        // made reports no `Sending`.
        self.engine
            .estimate_fee(request.amount, request.selection_options())
            .await?;
        report(TorEvent::of(TorEventKind::Sending));
        let sent = self
            .engine
            .send(request, delivery(&onion))
            .await
            .map_err(send_error)?;
        let slate_id = sent.slate_id.to_string();
        let posted = self
            .finalize_direct_reply(TRANSPORT_ID, self.tor.take_reply(&slate_id))
            .await?;
        Ok(HttpSentTx {
            tx_id: sent.tx_id.0,
            slate_id,
            amount: sent.amount.value(),
            fee: sent.fee.value(),
            posted,
        })
    }

    pub(crate) async fn resend_tor(
        &self,
        tx_id: u32,
        to: &str,
    ) -> Result<HttpResentTx, WalletError> {
        let onion = onion(to)?;
        let details = self.engine.transaction_details(TxId(tx_id)).await?;
        let entry = &details.transaction.entry;
        let slate_id = match entry.slate_id {
            Some(slate_id) if entry.account == DEFAULT_ACCOUNT => slate_id.to_string(),
            _ => {
                return Err(invalid(
                    "the transaction is not a send waiting for its answer",
                ));
            }
        };
        let report = self.tor_send_report()?;
        report(TorEvent::of(TorEventKind::Sending));
        self.engine
            .resend(TxId(tx_id), delivery(&onion))
            .await
            .map_err(send_error)?;
        let posted = self
            .finalize_direct_reply(TRANSPORT_ID, self.tor.take_reply(&slate_id))
            .await?;
        Ok(HttpResentTx {
            tx_id,
            slate_id,
            posted,
        })
    }

    /// Whether the relay connection goes through the wallet's tor while it runs. A held
    /// connection that would now go another way is replaced.
    pub(crate) fn set_epicbox_over_tor(&self, enabled: bool) {
        self.relay_tor.set_enabled(enabled);
    }

    pub(crate) fn epicbox_over_tor(&self) -> bool {
        self.relay_tor.enabled()
    }

    /// Replaces the onion routes of the session after checking every one, as
    /// [`checked_onion_routes`] does. Nothing changes when one is invalid.
    pub(crate) fn set_onion_routes(&self, routes: Vec<OnionRoute>) -> Result<(), WalletError> {
        self.onion_routes.replace(checked_onion_routes(routes)?);
        Ok(())
    }

    /// Whether node requests go through the wallet's tor while it runs.
    pub(crate) fn set_node_over_tor(&self, enabled: bool) {
        self.node_tor.set_enabled(enabled);
    }

    pub(crate) fn node_over_tor(&self) -> bool {
        self.node_tor.enabled()
    }

    /// The relay connection and node requests wait for a tor that is being started.
    fn expect_routes(&self) {
        self.relay_tor.expect();
        self.node_tor.expect();
    }

    fn attach_routes(&self, tor: &Arc<TorProcess>) {
        self.relay_tor.attach(Arc::clone(tor));
        self.node_tor.attach(Arc::clone(tor));
    }

    fn detach_routes(&self) {
        self.relay_tor.detach();
        self.node_tor.detach();
    }

    /// The app is about to start tor: until it does, relay connections wait for it instead of
    /// going directly, and the next [`Session::stop_tor`] keeps them waiting, as for a restart.
    /// A stop after that, or a lock, ends the wait.
    pub(crate) fn expect_tor(&self) -> Result<(), WalletError> {
        if cfg!(target_os = "ios") {
            return Ok(());
        }
        let mut slot = lock(&self.tor_slot);
        self.ensure_unlocked()?;
        slot.settle();
        self.tor_expected.store(true, Ordering::Relaxed);
        if matches!(&*slot, TorSlot::Idle | TorSlot::Stopping(_)) {
            self.expect_routes();
        }
        drop(slot);
        self.remember_tor_expected();
        Ok(())
    }

    /// Takes the relay connection through the SOCKS proxy at `socks`, as a running tor would.
    #[cfg(test)]
    pub(crate) fn attach_relay_socks(&self, socks: std::net::SocketAddr) {
        self.relay_tor.attach_socks(lepic_tor::FixedSocks(socks));
    }

    /// Takes node requests through the SOCKS proxy at `socks`, as a running tor would.
    #[cfg(test)]
    pub(crate) fn attach_node_socks(&self, socks: std::net::SocketAddr) {
        self.node_tor.attach_socks(lepic_tor::FixedSocks(socks));
    }

    #[cfg(test)]
    pub(crate) fn relay_through_tor(&self) -> bool {
        *self.relay_tor.active().borrow()
    }

    #[cfg(test)]
    pub(crate) fn node_through_tor(&self) -> bool {
        *self.node_tor.active().borrow()
    }

    #[cfg(test)]
    pub(crate) fn set_tor_timings(&self, timings: lepic_tor::TorTimings) {
        *lock(&self.tor_timings) = Some(timings);
    }
}

fn tor_not_running() -> WalletError {
    WalletError::new(
        WalletErrorKind::TorNotRunning,
        "tor is not running or not connected to the tor network",
    )
}

/// Forwards tor's states to `report`, publishes the onion once tor has bootstrapped, and
/// stops tor and its listener when tor ends on its own.
async fn drive(
    session: Weak<Session>,
    generation: u64,
    tor: Arc<TorProcess>,
    key: OnionKey,
    port: u16,
    report: TorReport,
    publish_failure: Arc<std::sync::Mutex<Option<TorFailureKind>>>,
) {
    let mut states = tor.subscribe();
    let forward = async {
        let mut reported = Phase::Starting;
        loop {
            let state = states.borrow_and_update().clone();
            let socks_port = tor.socks_address().map(|address| address.port());
            for mut event in state_events(&mut reported, &state) {
                if matches!(
                    event.kind,
                    TorEventKind::Bootstrapped | TorEventKind::Publishing | TorEventKind::Ready
                ) {
                    event.socks_port = socks_port;
                }
                report(event);
            }
            if matches!(state, TorState::Failed(_) | TorState::Off) {
                return;
            }
            if states.changed().await.is_err() {
                return;
            }
        }
    };
    let publish = async {
        if tor.wait_bootstrapped().await.is_err() {
            return;
        }
        match tor.publish_onion(key.expose_seed(), port).await {
            Ok(_) => info!(transport = "tor", "onion published"),
            Err(failure) => {
                // A failure that ended tor reaches the app through its state.
                if tor.state().can_send() {
                    let kind = failure_kind(failure.kind);
                    *lock(&publish_failure) = Some(kind);
                    debug!(transport = "tor", error = %failure, "onion not published");
                    report(failed(kind));
                }
            }
        }
        drop(key);
    };
    tokio::join!(forward, publish);
    drop(tor);
    if let Some(session) = session.upgrade() {
        session.stop_tor_of(generation);
    }
}

async fn stop_tor_process(tor: Arc<TorProcess>) {
    // Dropping the last handle kills tor at once instead.
    if let Ok(tor) = Arc::try_unwrap(tor) {
        tor.stop().await;
    }
}

async fn shut_down(run: TorRun, down: watch::Sender<bool>) {
    let TorRun {
        tor,
        listener,
        report,
        driver,
        ..
    } = run;
    driver.abort();
    let _ = driver.await;
    stop_tor_process(tor).await;
    listener.shutdown().await;
    info!(transport = "tor", "tor stopped");
    down.send_replace(true);
    report(TorEvent::of(TorEventKind::Stopped));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(events: Vec<TorEvent>) -> Vec<TorEventKind> {
        events.into_iter().map(|event| event.kind).collect()
    }

    #[test]
    fn a_phase_merged_into_a_later_state_is_still_reported_in_order() {
        let onion = OnionAddress::from_public_key(&[1; 32]);
        let mut reported = Phase::Starting;
        let starting = TorState::Starting {
            progress: 10,
            tag: String::new(),
        };
        assert_eq!(
            kinds(state_events(&mut reported, &starting)),
            [TorEventKind::Starting]
        );
        assert_eq!(
            kinds(state_events(&mut reported, &TorState::Ready { onion })),
            [
                TorEventKind::Bootstrapped,
                TorEventKind::Publishing,
                TorEventKind::Ready
            ]
        );

        let mut reported = Phase::Starting;
        assert_eq!(
            kinds(state_events(&mut reported, &TorState::Publishing)),
            [TorEventKind::Bootstrapped, TorEventKind::Publishing]
        );
        let failure = lepic_tor::TorFailure {
            kind: FailureKind::Stopped,
            detail: String::new(),
        };
        assert_eq!(
            kinds(state_events(&mut reported, &TorState::Failed(failure))),
            [TorEventKind::Failed]
        );
    }
}
