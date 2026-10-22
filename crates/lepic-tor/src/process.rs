//! The wallet's own tor: one child process per open wallet, on private `auto` ports, driven over
//! its control port so the wallet knows when it can send and receive, and why it cannot.
//!
//! `Off → Starting → Bootstrapped → Publishing → Ready`, or `Failed` from any of them. Sending
//! needs `Bootstrapped`; receiving needs `Ready`, the first upload of the onion's descriptor.
//! Republishing is tor's own job. A failure ends the process; restarting is the host's choice.

use std::collections::VecDeque;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, sleep_until, timeout};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::control::{ControlConnection, ControlError, Event, HsDescAction, parse_control_file};
use crate::onion::{OnionAddress, expanded_secret, public_key_of_seed};

const TORRC: &str = "torrc";
const DEFAULTS_TORRC: &str = "torrc-defaults";
const CONTROL_FILE: &str = "control.txt";
const COOKIE_FILE: &str = "control.cookie";
const DATA_DIR: &str = "data";
const MAX_DETAIL_LEN: usize = 300;
const MAX_LOG_LINE_LEN: usize = 1024;
const RECENT_UPLOADS: usize = 8;
const IDLE_WAKE: Duration = Duration::from_secs(24 * 3600);
const LOG_DRAIN: Duration = Duration::from_secs(1);
const CONTROL_FILE_POLL: Duration = Duration::from_millis(100);
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long each step may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TorTimings {
    /// From the start until tor writes its control port file.
    pub control_file: Duration,
    /// Each control command.
    pub command: Duration,
    /// Bootstrap progress unchanged this long is a network failure.
    pub stall: Duration,
    /// No full bootstrap this long after the start is a network failure.
    pub bootstrap: Duration,
    /// Bootstrapped with the onion added, but no descriptor uploaded this long.
    pub publish: Duration,
    /// For the polite shutdown, and again for the exit after the kill.
    pub stop: Duration,
    /// Connecting to the wallet's listener before the onion is added.
    pub listener_check: Duration,
}

impl Default for TorTimings {
    fn default() -> Self {
        Self {
            control_file: Duration::from_secs(30),
            command: Duration::from_secs(15),
            stall: Duration::from_secs(60),
            bootstrap: Duration::from_secs(120),
            publish: Duration::from_secs(180),
            stop: Duration::from_secs(5),
            listener_check: Duration::from_secs(3),
        }
    }
}

/// Where tor is and where this wallet's tor keeps its files.
#[derive(Debug, Clone)]
pub struct TorSettings {
    pub tor_binary: PathBuf,
    /// Put on `LD_LIBRARY_PATH` on Linux, for the libraries the Tor Expert Bundle ships.
    pub lib_dir: Option<PathBuf>,
    /// This wallet's tor directory, created with mode 0700. Never shared between wallets.
    pub data_dir: PathBuf,
    pub timings: TorTimings,
}

impl TorSettings {
    pub fn new(tor_binary: PathBuf, data_dir: PathBuf) -> Self {
        Self {
            tor_binary,
            lib_dir: None,
            data_dir,
            timings: TorTimings::default(),
        }
    }
}

/// Why tor is not working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailureKind {
    /// No tor binary at the configured path.
    Missing,
    /// Tor did not start, or its control port did not answer as expected.
    Start,
    /// No bootstrap progress for a while, or no full bootstrap in time.
    Network,
    /// Tor reported the computer's clock as wrong before it could bootstrap.
    Clock,
    /// The wallet's listener does not answer, so the onion would lead nowhere.
    Listener,
    /// Tor exited or closed its control port after the bootstrap.
    Stopped,
    /// The onion was added, but its descriptor was not uploaded in time.
    Publish,
    /// Tor refused the onion key, or published another onion than the wallet's.
    Keys,
}

impl FailureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Start => "start",
            Self::Network => "network",
            Self::Clock => "clock",
            Self::Listener => "listener",
            Self::Stopped => "stopped",
            Self::Publish => "publish",
            Self::Keys => "keys",
        }
    }
}

/// A failure and a short detail for the log or a support request. The detail never holds a
/// key or the cookie.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("tor failed ({}): {detail}", kind.as_str())]
pub struct TorFailure {
    pub kind: FailureKind,
    pub detail: String,
}

impl TorFailure {
    fn new(kind: FailureKind, detail: impl fmt::Display) -> Self {
        Self {
            kind,
            detail: detail.to_string().chars().take(MAX_DETAIL_LEN).collect(),
        }
    }
}

/// What the wallet's tor is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TorState {
    Off,
    Starting {
        progress: u8,
        tag: String,
    },
    /// Connected to the Tor network: sending works.
    Bootstrapped,
    /// The onion is added and its descriptor is being uploaded.
    Publishing,
    /// Others can reach the wallet at `onion`.
    Ready {
        onion: OnionAddress,
    },
    Failed(TorFailure),
}

impl TorState {
    /// Whether onion addresses can be reached through this tor.
    pub const fn can_send(&self) -> bool {
        matches!(
            self,
            Self::Bootstrapped | Self::Publishing | Self::Ready { .. }
        )
    }
}

/// Something that can give a SOCKS address for sending to onions.
pub trait SocksProxy: Send + Sync {
    /// The SOCKS5 address to use now, or `None` when sending is not possible.
    fn socks_address(&self) -> Option<SocketAddr>;
}

/// A SOCKS proxy at a fixed address, for a tor the wallet does not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedSocks(pub SocketAddr);

impl SocksProxy for FixedSocks {
    fn socks_address(&self) -> Option<SocketAddr> {
        Some(self.0)
    }
}

enum Request {
    Publish {
        key: Zeroizing<[u8; 64]>,
        expected: OnionAddress,
        listener_port: u16,
        reply: oneshot::Sender<Result<(), TorFailure>>,
    },
    Stop {
        reply: oneshot::Sender<()>,
    },
}

/// A running tor. Dropping it kills the process; [`TorProcess::stop`] shuts it down politely.
#[derive(Debug)]
pub struct TorProcess {
    requests: mpsc::Sender<Request>,
    state: watch::Receiver<TorState>,
    socks: Arc<OnceLock<SocketAddr>>,
    supervisor: JoinHandle<()>,
}

impl Drop for TorProcess {
    fn drop(&mut self) {
        self.supervisor.abort();
    }
}

impl SocksProxy for TorProcess {
    fn socks_address(&self) -> Option<SocketAddr> {
        if self.state.borrow().can_send() {
            self.socks.get().copied()
        } else {
            None
        }
    }
}

impl TorProcess {
    /// Starts tor in the background; follow [`TorProcess::state`] or wait with
    /// [`TorProcess::wait_bootstrapped`]. Needs a Tokio runtime.
    pub fn start(settings: TorSettings) -> Self {
        let (state_tx, state) = watch::channel(TorState::Starting {
            progress: 0,
            tag: String::new(),
        });
        let (requests, requests_rx) = mpsc::channel(4);
        let socks = Arc::new(OnceLock::new());
        let supervisor = tokio::spawn(supervise(settings, state_tx, requests_rx, socks.clone()));
        Self {
            requests,
            state,
            socks,
            supervisor,
        }
    }

    pub fn state(&self) -> TorState {
        self.state.borrow().clone()
    }

    /// A receiver that sees every state change.
    pub fn subscribe(&self) -> watch::Receiver<TorState> {
        self.state.clone()
    }

    /// Waits until sending works and returns the SOCKS address.
    pub async fn wait_bootstrapped(&self) -> Result<SocketAddr, TorFailure> {
        let mut state = self.state.clone();
        loop {
            {
                let current = state.borrow_and_update();
                if current.can_send()
                    && let Some(socks) = self.socks.get()
                {
                    return Ok(*socks);
                }
                if let Some(failure) = ended(&current) {
                    return Err(failure);
                }
            }
            if state.changed().await.is_err() {
                return Err(TorFailure::new(FailureKind::Stopped, "tor stopped"));
            }
        }
    }

    /// Adds the wallet's onion service, port 80 to `127.0.0.1:<listener_port>`, and waits for
    /// its first descriptor upload. `seed` is the wallet's address secret key; it is expanded
    /// in memory and never stored. A [`FailureKind::Listener`] or [`FailureKind::Keys`] error
    /// leaves tor running for sending.
    pub async fn publish_onion(
        &self,
        seed: &[u8; 32],
        listener_port: u16,
    ) -> Result<OnionAddress, TorFailure> {
        let expected = OnionAddress::from_public_key(&public_key_of_seed(seed));
        let (reply, answer) = oneshot::channel();
        let request = Request::Publish {
            key: expanded_secret(seed),
            expected: expected.clone(),
            listener_port,
            reply,
        };
        let stopped = || TorFailure::new(FailureKind::Stopped, "tor stopped");
        self.requests.send(request).await.map_err(|_| stopped())?;
        answer.await.map_err(|_| stopped())??;
        let mut state = self.state.clone();
        loop {
            {
                let current = state.borrow_and_update();
                match &*current {
                    TorState::Ready { onion } if *onion == expected => return Ok(expected),
                    other => {
                        if let Some(failure) = ended(other) {
                            return Err(failure);
                        }
                    }
                }
            }
            if state.changed().await.is_err() {
                return Err(stopped());
            }
        }
    }

    /// Removes the onion, asks tor to exit and kills it if it has not after
    /// [`TorTimings::stop`]. Bounded by about three times that.
    pub async fn stop(self) {
        let (reply, done) = oneshot::channel();
        if self.requests.send(Request::Stop { reply }).await.is_ok() {
            let _ = done.await;
        }
    }
}

fn ended(state: &TorState) -> Option<TorFailure> {
    match state {
        TorState::Failed(failure) => Some(failure.clone()),
        TorState::Off => Some(TorFailure::new(FailureKind::Stopped, "tor stopped")),
        _ => None,
    }
}

/// The paths of one wallet's tor files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorPaths {
    pub dir: PathBuf,
    pub torrc: PathBuf,
    pub defaults: PathBuf,
    pub control_file: PathBuf,
    pub cookie: PathBuf,
    pub data: PathBuf,
}

impl TorPaths {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            torrc: dir.join(TORRC),
            defaults: dir.join(DEFAULTS_TORRC),
            control_file: dir.join(CONTROL_FILE),
            cookie: dir.join(COOKIE_FILE),
            data: dir.join(DATA_DIR),
        }
    }
}

/// The torrc: private `auto` ports, cookie authentication, owned by this process.
pub fn build_torrc(paths: &TorPaths, owner_pid: u32) -> Result<String, TorFailure> {
    let quote = |path: &Path| {
        torrc_quote(path).ok_or_else(|| TorFailure::new(FailureKind::Start, "unusable tor path"))
    };
    Ok(format!(
        "SocksPort auto ExtendedErrors IsolateSOCKSAuth\n\
         ControlPort auto\n\
         ControlPortWriteToFile {}\n\
         CookieAuthentication 1\n\
         CookieAuthFile {}\n\
         DataDirectory {}\n\
         __OwningControllerProcess {owner_pid}\n\
         Log notice stdout\n\
         AvoidDiskWrites 1\n",
        quote(&paths.control_file)?,
        quote(&paths.cookie)?,
        quote(&paths.data)?,
    ))
}

// A torrc value in double quotes with C escapes, so Windows backslashes and spaces survive.
fn torrc_quote(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Some(out)
}

/// The message of a tor `[warn]` or `[err]` log line.
pub fn tor_problem(line: &str) -> Option<String> {
    let at = line.find("[warn]").or_else(|| line.find("[err]"))?;
    let rest = line.get(at..)?;
    let message = rest.split_once(']').map_or("", |(_, m)| m).trim();
    Some(message.chars().take(MAX_DETAIL_LEN).collect())
}

struct Running {
    child: Child,
    control: ControlConnection,
    events: mpsc::Receiver<Event>,
    problem: Arc<Mutex<String>>,
    started: Instant,
}

impl Running {
    fn last_problem(&self, fallback: &str) -> String {
        let problem = self.problem.lock().unwrap_or_else(PoisonError::into_inner);
        if problem.is_empty() {
            fallback.to_owned()
        } else {
            problem.clone()
        }
    }
}

struct Published {
    onion: OnionAddress,
    uploaded: bool,
}

struct Progress {
    progress: u8,
    tag: String,
    bootstrapped: bool,
    published: Option<Published>,
    recent_uploads: VecDeque<String>,
    stall_deadline: Instant,
    bootstrap_deadline: Instant,
    publish_deadline: Option<Instant>,
}

impl Progress {
    fn visible(&self) -> TorState {
        match (&self.published, self.bootstrapped) {
            (_, false) => TorState::Starting {
                progress: self.progress,
                tag: self.tag.clone(),
            },
            (None, true) => TorState::Bootstrapped,
            (
                Some(Published {
                    uploaded: false, ..
                }),
                true,
            ) => TorState::Publishing,
            (
                Some(Published {
                    onion,
                    uploaded: true,
                }),
                true,
            ) => TorState::Ready {
                onion: onion.clone(),
            },
        }
    }
}

async fn supervise(
    settings: TorSettings,
    state: watch::Sender<TorState>,
    mut requests: mpsc::Receiver<Request>,
    socks: Arc<OnceLock<SocketAddr>>,
) {
    let timings = settings.timings;
    let mut running = match launch(&settings, &socks).await {
        Ok(running) => running,
        Err((failure, child)) => {
            if let Some(child) = child {
                kill(*child, timings.stop).await;
            }
            fail(&state, failure, &mut requests).await;
            return;
        }
    };
    let now = Instant::now();
    let mut progress = Progress {
        progress: 0,
        tag: String::new(),
        bootstrapped: false,
        published: None,
        recent_uploads: VecDeque::new(),
        stall_deadline: after(now, timings.stall),
        bootstrap_deadline: after(running.started, timings.bootstrap),
        publish_deadline: None,
    };
    if let Ok(phase) = running.control.bootstrap_phase().await {
        on_bootstrap(&mut progress, phase, timings, running.started);
    }
    state.send_replace(progress.visible());
    let failure = loop {
        let deadline = next_deadline(&progress);
        tokio::select! {
            request = requests.recv() => match request {
                None => {
                    shutdown(running, progress.published.as_ref(), timings).await;
                    return;
                }
                Some(Request::Stop { reply }) => {
                    shutdown(running, progress.published.as_ref(), timings).await;
                    state.send_replace(TorState::Off);
                    info!("tor stopped");
                    let _ = reply.send(());
                    return;
                }
                Some(Request::Publish { key, expected, listener_port, reply }) => {
                    let result =
                        add_onion(&running, &mut progress, &key, expected, listener_port, timings)
                            .await;
                    drop(key);
                    let _ = reply.send(result);
                }
            },
            event = running.events.recv() => match event {
                Some(event) => {
                    if let Some(failure) = on_event(&mut progress, event, timings, running.started) {
                        break failure;
                    }
                }
                None => break exit_failure(&progress, running.last_problem("control connection closed")),
            },
            status = running.child.wait() => {
                let detail = match status {
                    Ok(status) => format!("tor exited ({status})"),
                    Err(error) => format!("tor exited ({})", error.kind()),
                };
                break exit_failure(&progress, running.last_problem(&detail));
            }
            () = sleep_until(deadline) => {
                if let Some(failure) = overdue(&progress) {
                    break failure;
                }
            }
        }
        let visible = progress.visible();
        state.send_if_modified(|current| {
            let changed = *current != visible;
            if changed {
                *current = visible;
            }
            changed
        });
    };
    kill(running.child, timings.stop).await;
    fail(&state, failure, &mut requests).await;
}

fn on_bootstrap(
    progress: &mut Progress,
    phase: crate::control::Bootstrap,
    timings: TorTimings,
    started: Instant,
) {
    if phase.progress != progress.progress {
        progress.progress = phase.progress;
        progress.stall_deadline = after(Instant::now(), timings.stall);
    }
    progress.tag = phase.tag;
    if let Some(warning) = phase.warning {
        debug!(error = %warning, "tor bootstrap warned");
    }
    if phase.progress >= 100 && !progress.bootstrapped {
        progress.bootstrapped = true;
        info!(elapsed_ms = elapsed_ms(started), "tor bootstrapped");
        if progress.published.is_some() {
            progress.publish_deadline = Some(after(Instant::now(), timings.publish));
        }
    }
}

fn on_event(
    progress: &mut Progress,
    event: Event,
    timings: TorTimings,
    started: Instant,
) -> Option<TorFailure> {
    match event {
        Event::Bootstrap(phase) => on_bootstrap(progress, phase, timings, started),
        Event::ClockSkew { skew_seconds } if !progress.bootstrapped => {
            return Some(TorFailure::new(
                FailureKind::Clock,
                format_args!("clock off by {skew_seconds} s"),
            ));
        }
        Event::ClockSkew { skew_seconds } => {
            warn!(error = %format_args!("clock off by {skew_seconds} s"), "tor reported clock skew");
        }
        Event::HsDesc {
            action: HsDescAction::Uploaded,
            service_id,
        } => match &mut progress.published {
            Some(published) if published.onion.service_id() == service_id => {
                if !published.uploaded {
                    published.uploaded = true;
                    progress.publish_deadline = None;
                    info!(elapsed_ms = elapsed_ms(started), "onion published");
                }
            }
            _ => {
                if progress.recent_uploads.len() >= RECENT_UPLOADS {
                    progress.recent_uploads.pop_front();
                }
                progress.recent_uploads.push_back(service_id);
            }
        },
        Event::HsDesc {
            action: HsDescAction::Failed,
            ..
        } => debug!("onion descriptor upload failed at one directory"),
        _ => {}
    }
    None
}

fn next_deadline(progress: &Progress) -> Instant {
    if !progress.bootstrapped {
        return progress.stall_deadline.min(progress.bootstrap_deadline);
    }
    progress
        .publish_deadline
        .unwrap_or_else(|| after(Instant::now(), IDLE_WAKE))
}

fn overdue(progress: &Progress) -> Option<TorFailure> {
    let now = Instant::now();
    if !progress.bootstrapped {
        if now >= progress.bootstrap_deadline {
            return Some(TorFailure::new(
                FailureKind::Network,
                "no bootstrap in time",
            ));
        }
        if now >= progress.stall_deadline {
            return Some(TorFailure::new(
                FailureKind::Network,
                format_args!("stuck at {} %", progress.progress),
            ));
        }
        return None;
    }
    progress
        .publish_deadline
        .filter(|deadline| now >= *deadline)
        .map(|_| TorFailure::new(FailureKind::Publish, "no descriptor upload in time"))
}

fn exit_failure(progress: &Progress, detail: String) -> TorFailure {
    let kind = if progress.bootstrapped {
        FailureKind::Stopped
    } else {
        FailureKind::Start
    };
    TorFailure::new(kind, detail)
}

async fn add_onion(
    running: &Running,
    progress: &mut Progress,
    key: &[u8; 64],
    expected: OnionAddress,
    listener_port: u16,
    timings: TorTimings,
) -> Result<(), TorFailure> {
    if listener_port == 0 || !listener_answers(listener_port, timings.listener_check).await {
        return Err(TorFailure::new(
            FailureKind::Listener,
            "the wallet listener does not answer",
        ));
    }
    if let Some(previous) = progress.published.take() {
        progress.publish_deadline = None;
        let _ = running.control.del_onion(previous.onion.service_id()).await;
    }
    let service_id = running
        .control
        .add_onion(key, listener_port)
        .await
        .map_err(|error| TorFailure::new(FailureKind::Keys, format_args!("add onion: {error}")))?;
    if service_id != expected.service_id() {
        let _ = running.control.del_onion(&service_id).await;
        return Err(TorFailure::new(
            FailureKind::Keys,
            "tor published another onion",
        ));
    }
    let uploaded = progress.recent_uploads.iter().any(|id| *id == service_id);
    progress.published = Some(Published {
        onion: expected,
        uploaded,
    });
    if progress.bootstrapped && !uploaded {
        progress.publish_deadline = Some(after(Instant::now(), timings.publish));
    }
    debug!(transport = "tor", "onion service added");
    Ok(())
}

/// `DEL_ONION` and `SIGNAL SHUTDOWN`, bounded; then the exit, and a kill if it does not come.
async fn shutdown(running: Running, published: Option<&Published>, timings: TorTimings) {
    let Running {
        mut child, control, ..
    } = running;
    let polite = async {
        if let Some(published) = published {
            let _ = control.del_onion(published.onion.service_id()).await;
        }
        let _ = control.signal_shutdown().await;
    };
    let _ = timeout(timings.stop, polite).await;
    drop(control);
    if timeout(timings.stop, child.wait()).await.is_err() {
        kill(child, timings.stop).await;
    }
}

async fn fail(
    state: &watch::Sender<TorState>,
    failure: TorFailure,
    requests: &mut mpsc::Receiver<Request>,
) {
    warn!(transport = "tor", error = %failure, "tor failed");
    state.send_replace(TorState::Failed(failure.clone()));
    while let Some(request) = requests.recv().await {
        match request {
            Request::Publish { reply, .. } => {
                let _ = reply.send(Err(failure.clone()));
            }
            Request::Stop { reply } => {
                let _ = reply.send(());
                return;
            }
        }
    }
}

// The child, when there is one, is killed before the failure is shown.
type LaunchError = (TorFailure, Option<Box<Child>>);

async fn launch(
    settings: &TorSettings,
    socks: &OnceLock<SocketAddr>,
) -> Result<Running, LaunchError> {
    let start_failure =
        |detail: &dyn fmt::Display| (TorFailure::new(FailureKind::Start, detail), None);
    match tokio::fs::metadata(&settings.tor_binary).await {
        Ok(meta) if meta.is_file() => {}
        _ => return Err((TorFailure::new(FailureKind::Missing, "no tor binary"), None)),
    }
    let paths = TorPaths::new(&settings.data_dir);
    prepare_files(&paths)
        .await
        .map_err(|error| start_failure(&format_args!("tor files: {}", error.kind())))?;
    let torrc = build_torrc(&paths, std::process::id()).map_err(|failure| (failure, None))?;
    tokio::fs::write(&paths.torrc, torrc)
        .await
        .map_err(|error| start_failure(&format_args!("torrc: {}", error.kind())))?;

    let mut command = Command::new(&settings.tor_binary);
    command
        .arg("-f")
        .arg(&paths.torrc)
        .arg("--defaults-torrc")
        .arg(&paths.defaults)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(lib_dir) = &settings.lib_dir
        && cfg!(target_os = "linux")
    {
        command.env("LD_LIBRARY_PATH", lib_dir);
    }
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command
        .spawn()
        .map_err(|error| start_failure(&format_args!("spawn: {}", error.kind())))?;
    let started = Instant::now();
    let problem = Arc::new(Mutex::new(String::new()));
    let mut logs = Vec::with_capacity(2);
    if let Some(stdout) = child.stdout.take() {
        logs.push(tokio::spawn(follow_log(stdout, problem.clone())));
    }
    if let Some(stderr) = child.stderr.take() {
        logs.push(tokio::spawn(follow_log(stderr, problem.clone())));
    }
    let last_problem = |fallback: &str| {
        let text = problem.lock().unwrap_or_else(PoisonError::into_inner);
        if text.is_empty() {
            fallback.to_owned()
        } else {
            text.clone()
        }
    };

    let control_address = loop {
        if let Ok(Some(status)) = child.try_wait() {
            // Its last lines may still be in the pipes.
            let _ = timeout(LOG_DRAIN, drain_logs(&mut logs)).await;
            let detail = last_problem(&format!("tor exited ({status})"));
            return Err((TorFailure::new(FailureKind::Start, detail), None));
        }
        if let Ok(text) = tokio::fs::read_to_string(&paths.control_file).await
            && let Some(address) = parse_control_file(&text)
        {
            break address;
        }
        if started.elapsed() > settings.timings.control_file {
            let detail = last_problem("no control port");
            return Err((
                TorFailure::new(FailureKind::Start, detail),
                Some(Box::new(child)),
            ));
        }
        sleep(CONTROL_FILE_POLL).await;
    };

    let connected = connect_control(control_address, &paths, settings.timings.command).await;
    let (control, events, socks_address) = match connected {
        Ok(connected) => connected,
        Err(error) => {
            let detail = last_problem(&error.to_string());
            return Err((
                TorFailure::new(FailureKind::Start, detail),
                Some(Box::new(child)),
            ));
        }
    };
    let _ = socks.set(socks_address);
    debug!(elapsed_ms = elapsed_ms(started), "tor control connected");
    Ok(Running {
        child,
        control,
        events,
        problem,
        started,
    })
}

async fn drain_logs(handles: &mut [JoinHandle<()>]) {
    for handle in handles {
        let _ = handle.await;
    }
}

async fn prepare_files(paths: &TorPaths) -> std::io::Result<()> {
    create_private_dir(&paths.dir).await?;
    create_private_dir(&paths.data).await?;
    for stale in [&paths.control_file, &paths.cookie] {
        match tokio::fs::remove_file(stale).await {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    tokio::fs::write(&paths.defaults, "").await
}

async fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

async fn connect_control(
    address: SocketAddr,
    paths: &TorPaths,
    command_timeout: Duration,
) -> Result<(ControlConnection, mpsc::Receiver<Event>, SocketAddr), ControlError> {
    let (control, events) = ControlConnection::connect(address, command_timeout).await?;
    let cookie = Zeroizing::new(
        tokio::fs::read(&paths.cookie)
            .await
            .map_err(ControlError::Io)?,
    );
    control.authenticate(&cookie).await?;
    control.take_ownership().await?;
    control.follow_events().await?;
    let socks = control.socks_address().await?;
    Ok((control, events, socks))
}

async fn kill(mut child: Child, wait: Duration) {
    let _ = child.start_kill();
    if timeout(wait, child.wait()).await.is_err() {
        warn!("tor did not exit after the kill");
    }
}

/// Reads tor's log output, keeps its last problem line, and never stops draining: a full pipe
/// would block tor.
async fn follow_log<R: AsyncRead + Unpin>(mut output: R, problem: Arc<Mutex<String>>) {
    let mut chunk = [0u8; 4096];
    let mut line: Vec<u8> = Vec::with_capacity(MAX_LOG_LINE_LEN);
    loop {
        let read = match output.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        for &byte in chunk.get(..read).unwrap_or_default() {
            if byte == b'\n' {
                let text = String::from_utf8_lossy(&line);
                if let Some(message) = tor_problem(&text) {
                    debug!(error = %message, "tor reported a problem");
                    *problem.lock().unwrap_or_else(PoisonError::into_inner) = message;
                }
                line.clear();
            } else if line.len() < MAX_LOG_LINE_LEN {
                line.push(byte);
            }
        }
    }
}

// Deadlines never overflow: an absurd duration waits a day instead.
fn after(from: Instant, wait: Duration) -> Instant {
    from.checked_add(wait)
        .or_else(|| from.checked_add(IDLE_WAKE))
        .unwrap_or(from)
}

fn elapsed_ms(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn listener_answers(port: u16, wait: Duration) -> bool {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    matches!(timeout(wait, TcpStream::connect(address)).await, Ok(Ok(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torrc_has_private_ports_cookie_auth_and_an_owner() {
        let paths = TorPaths::new(Path::new("/w/tor"));
        let torrc = build_torrc(&paths, 4242).unwrap();
        assert_eq!(
            torrc,
            "SocksPort auto ExtendedErrors IsolateSOCKSAuth\n\
             ControlPort auto\n\
             ControlPortWriteToFile \"/w/tor/control.txt\"\n\
             CookieAuthentication 1\n\
             CookieAuthFile \"/w/tor/control.cookie\"\n\
             DataDirectory \"/w/tor/data\"\n\
             __OwningControllerProcess 4242\n\
             Log notice stdout\n\
             AvoidDiskWrites 1\n"
        );
    }

    #[test]
    fn torrc_values_escape_quotes_and_backslashes() {
        assert_eq!(
            torrc_quote(Path::new(r#"C:\Users\A "B"\tor"#)).unwrap(),
            r#""C:\\Users\\A \"B\"\\tor""#
        );
        assert_eq!(torrc_quote(Path::new("/a\nControlPort 9051")), None);
    }

    #[test]
    fn reads_problem_lines_from_tor_logs() {
        assert_eq!(
            tor_problem("Oct 21 10:00:00.000 [warn] Could not bind to 127.0.0.1:9050").as_deref(),
            Some("Could not bind to 127.0.0.1:9050")
        );
        assert_eq!(
            tor_problem("Oct 21 10:00:00.000 [err] Reading config failed").as_deref(),
            Some("Reading config failed")
        );
        assert_eq!(
            tor_problem("Oct 21 10:00:00.000 [notice] Bootstrapped 5%"),
            None
        );
    }

    #[test]
    fn visible_state_follows_bootstrap_and_upload() {
        let now = Instant::now();
        let onion = OnionAddress::from_public_key(&[1; 32]);
        let mut progress = Progress {
            progress: 45,
            tag: "loading_descriptors".into(),
            bootstrapped: false,
            published: None,
            recent_uploads: VecDeque::new(),
            stall_deadline: now,
            bootstrap_deadline: now,
            publish_deadline: None,
        };
        assert_eq!(
            progress.visible(),
            TorState::Starting {
                progress: 45,
                tag: "loading_descriptors".into()
            }
        );
        progress.published = Some(Published {
            onion: onion.clone(),
            uploaded: false,
        });
        assert!(matches!(progress.visible(), TorState::Starting { .. }));
        progress.bootstrapped = true;
        assert_eq!(progress.visible(), TorState::Publishing);
        progress.published = None;
        assert_eq!(progress.visible(), TorState::Bootstrapped);
        progress.published = Some(Published {
            onion: onion.clone(),
            uploaded: true,
        });
        assert_eq!(progress.visible(), TorState::Ready { onion });
    }

    #[test]
    fn fixed_socks_always_answers() {
        let address: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        assert_eq!(FixedSocks(address).socks_address(), Some(address));
    }
}
