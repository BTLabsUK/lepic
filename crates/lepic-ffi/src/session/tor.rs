//! The wallet's tor (ADR 0018): one tor per session, with a listener of its own on
//! `127.0.0.1` that the onion forwards to, and sends to other wallets' onions.

use std::error::Error as StdError;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use lepic_foreign::{Exposure, ListenSettings, ListenerHandle};
use lepic_store::TxId;
use lepic_tor::{
    FailureKind, OnionAddress, SendFailure, SocksProxy, TRANSPORT_ID, TorProcess, TorSendError,
    TorSettings, TorState, TorTransport,
};
use lepic_transport::transport::Destination;
use lepic_wallet::OnionKey;
use lepic_wallet::send::{Delivery, SendError};
use tokio::task::JoinHandle;
use tracing::{debug, info};

use super::http::HttpReport;
use super::{DEFAULT_ACCOUNT, Session, invalid, lock};
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::http::{HttpListenerEvent, HttpListenerEventKind, HttpResentTx, HttpSentTx};
use crate::api::tor::{TorEvent, TorEventKind, TorFailureKind, TorStatus, TorStatusKind};

/// Where the tor events of a session go.
pub(crate) type TorReport = Arc<dyn Fn(TorEvent) + Send + Sync>;

/// The directory inside the wallet's data directory that holds its tor's files.
const TOR_DIR: &str = "tor";

/// The tor of a session.
#[derive(Default)]
pub(super) enum TorSlot {
    #[default]
    Idle,
    /// Starting; the number tells this start from a later one.
    Starting(u64),
    Running(Box<TorRun>),
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
    pub(crate) async fn start_tor(
        self: &Arc<Self>,
        tor_binary: String,
        lib_dir: Option<String>,
        report: TorReport,
    ) -> Result<(), WalletError> {
        let key = self.engine.onion_key()?;
        let generation = self.tor_starts.fetch_add(1, Ordering::Relaxed);
        {
            let mut slot = lock(&self.tor_slot);
            // Checked again under the slot lock: a lock that ran since stops only a tor it
            // finds in the slot.
            self.ensure_unlocked()?;
            if !matches!(&*slot, TorSlot::Idle) {
                return Ok(());
            }
            *slot = TorSlot::Starting(generation);
        }
        let receiver = self.http_receiver(listener_report(&report));
        let listening =
            lepic_foreign::listen(ListenSettings::new(Exposure::LocalOnly, 0), receiver).await;
        let listener = match listening {
            Ok(listener) => listener,
            Err(error) => {
                let mut slot = lock(&self.tor_slot);
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

    /// Stops tor, then its listener. `Stopped` is reported once both are down.
    pub(crate) fn stop_tor(&self) {
        self.stop_tor_of_start(None);
    }

    /// Stops the tor of start `generation` if it is still the one in the slot.
    fn stop_tor_of(&self, generation: u64) {
        self.stop_tor_of_start(Some(generation));
    }

    /// Stops the tor in the slot, or only the one of start `generation`.
    fn stop_tor_of_start(&self, generation: Option<u64>) {
        let mut slot = lock(&self.tor_slot);
        let run = match &*slot {
            TorSlot::Running(run) if generation.is_none_or(|start| start == run.generation) => {
                std::mem::take(&mut *slot)
            }
            TorSlot::Starting(_) if generation.is_none() => {
                // The start finds the slot changed and stops what it started.
                *slot = TorSlot::Idle;
                return;
            }
            _ => return,
        };
        // Under the slot lock, so a start that follows attaches after this detach.
        self.tor.detach();
        drop(slot);
        if let TorSlot::Running(run) = run {
            // A runtime that is shutting down drops the task; tor is then killed with the
            // process handle and the listener's socket closes with the runtime.
            drop(self.runtime().boundary.handle.spawn(shut_down(*run)));
        }
    }

    pub(crate) fn tor_status(&self) -> TorStatus {
        let off = TorStatus {
            kind: TorStatusKind::Off,
            progress: None,
            onion: None,
            failure: None,
        };
        let slot = lock(&self.tor_slot);
        let run = match &*slot {
            TorSlot::Idle => return off,
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
        match run.tor.state() {
            TorState::Starting { progress, .. } => TorStatus {
                kind: TorStatusKind::Starting,
                progress: Some(progress),
                ..off
            },
            TorState::Bootstrapped => TorStatus {
                kind: TorStatusKind::Bootstrapped,
                failure,
                ..off
            },
            TorState::Publishing => TorStatus {
                kind: TorStatusKind::Publishing,
                ..off
            },
            TorState::Ready { onion } => TorStatus {
                kind: TorStatusKind::Ready,
                onion: Some(onion.host()),
                ..off
            },
            _ => off,
        }
    }

    /// Reports `Sending` and checks that tor can send, before anything is stored.
    fn begin_tor_send(&self) -> Result<(), WalletError> {
        let slot = lock(&self.tor_slot);
        let TorSlot::Running(run) = &*slot else {
            return Err(tor_not_running());
        };
        if run.tor.socks_address().is_none() {
            return Err(tor_not_running());
        }
        (run.report)(TorEvent::of(TorEventKind::Sending));
        Ok(())
    }

    pub(crate) async fn send_tor(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        to: &str,
        message: Option<String>,
    ) -> Result<HttpSentTx, WalletError> {
        let onion = onion(to)?;
        self.begin_tor_send()?;
        let sent = self
            .engine
            .send(
                Self::send_request(amount, minimum_confirmations, message),
                delivery(&onion),
            )
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
        self.begin_tor_send()?;
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
        loop {
            let state = states.borrow_and_update().clone();
            if let Some(event) = state_event(&state) {
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

async fn shut_down(run: TorRun) {
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
    report(TorEvent::of(TorEventKind::Stopped));
}
