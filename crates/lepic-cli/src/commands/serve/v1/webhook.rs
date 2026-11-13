// SPDX-License-Identifier: Apache-2.0
//! The webhook: the event log delivered by HTTP POST, one event at a time, in id order, with
//! retries (ADR 0058, section 2), and `GET /webhook` and `POST /webhook/resume`.
//!
//! The state is one record in the wallet store, so a restart carries on with the same event and
//! the same schedule. [`drive`] is the only task that sends. A handler changes the record only
//! with a new `epoch`: a send that ends under another epoch drops its result, so a resume is
//! never overwritten by an answer to the request it replaced.

mod send;

use std::convert::Infallible;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use lepic_node::NodeApi;
use lepic_store::WalletStore as _;
use rand::rngs::{StdRng, SysRng};
use rand::{RngExt as _, SeedableRng as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::super::{Opened, Service};
use super::{Reply, events};
use crate::api::model;
use crate::api::{Context, Problem, Request, ok};
use crate::exit::CliError;
use crate::host::Host;
use crate::settings::Webhook;

/// Where the state is kept.
const KEY: &str = "api.webhook";
/// The wait after each failure, before the next attempt. A failure after the last one disables
/// the webhook.
const SCHEDULE: [Duration; 7] = [
    Duration::from_secs(5),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(2 * 3600),
    Duration::from_secs(5 * 3600),
    Duration::from_secs(10 * 3600),
    Duration::from_secs(10 * 3600),
];
/// The share of a wait a retry may differ by, either way.
const JITTER: f64 = 0.2;
/// How long the driver waits after the store failed it.
const STORE_PAUSE: Duration = Duration::from_secs(5);
/// The `data.object` fields a webhook carries.
const OBJECT_KEYS: [&str; 18] = [
    "id",
    "kind",
    "direction",
    "state",
    "state_reason",
    "account",
    "amount",
    "fee",
    "link_id",
    "message",
    "their_message",
    "purpose",
    "metadata",
    "confirmations",
    "confirmed_height",
    "expires_at_height",
    "created_at",
    "updated_at",
];

/// The waits and limits of the driver; tests shorten them.
#[derive(Debug, Clone, Copy)]
struct Timing {
    schedule: [Duration; 7],
    /// The least time between the starts of two requests.
    gap: Duration,
    /// The wait before the secret file is read again after it could not be used.
    hold: Duration,
    limits: send::Limits,
}

impl Timing {
    const LIVE: Self = Self {
        schedule: SCHEDULE,
        gap: Duration::from_millis(100),
        hold: Duration::from_secs(60),
        limits: send::Limits {
            connect: Duration::from_secs(5),
            total: Duration::from_secs(10),
        },
    };
}

/// What the store keeps of the webhook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct State {
    /// The URL the state is for; another URL starts over.
    url: String,
    /// The id of the last event delivered, or passed over by the types filter.
    cursor: u64,
    /// Failed attempts at the event after the cursor.
    attempts: u32,
    /// When the next attempt is due, in Unix milliseconds.
    next_at: Option<i64>,
    last_error: Option<String>,
    /// Why the secret file cannot be used; nothing is sent and no attempt counts until it can.
    #[serde(default)]
    config_error: Option<String>,
    disabled: bool,
    /// Rises with each change a handler makes.
    epoch: u64,
    /// Drawn with each new state, so `webhook-id` differs between wallets and stores whose
    /// event ids are the same.
    source: u64,
}

impl State {
    fn next_at(&self) -> Option<Timestamp> {
        self.next_at
            .and_then(|ms| Timestamp::from_millisecond(ms).ok())
    }
}

/// The stored state, or a new one at the newest event when there is none for this URL.
fn load<N: NodeApi + 'static>(opened: &Opened<N>, url: &str) -> Result<State, CliError> {
    let store = opened.store()?;
    let stored = store.read(|repos| Ok::<_, CliError>(repos.setting(KEY)?))?;
    let old = stored.and_then(|text| serde_json::from_str::<State>(&text).ok());
    if let Some(state) = old.as_ref().filter(|state| state.url == url) {
        return Ok(state.clone());
    }
    let state = State {
        url: url.to_owned(),
        cursor: opened.wallet.api_event_last_id()?,
        attempts: 0,
        next_at: None,
        last_error: None,
        config_error: None,
        disabled: false,
        epoch: old.map_or(0, |old| old.epoch.saturating_add(1)),
        source: u64::from_le_bytes(crate::commands::random_bytes()?),
    };
    save(opened, &state)?;
    Ok(state)
}

fn save<N: NodeApi + 'static>(opened: &Opened<N>, state: &State) -> Result<(), CliError> {
    let text = serde_json::to_string(state).map_err(|error| CliError::Io {
        what: "write the webhook state",
        source: std::io::Error::other(error),
    })?;
    opened
        .store()?
        .write(|repos| Ok::<_, CliError>(repos.put_setting(KEY, &text)?))
}

/// The wait before the attempt after failure number `failures` (1 is the first), with `unit`
/// in -1 to 1 placing it in the jitter; none after the last wait.
fn delay(schedule: &[Duration; 7], failures: u32, unit: f64) -> Option<Duration> {
    let base = schedule.get(usize::try_from(failures).ok()?.checked_sub(1)?)?;
    Some(base.mul_f64(1.0 + JITTER * unit.clamp(-1.0, 1.0)))
}

fn jitter_unit() -> f64 {
    StdRng::try_from_rng(&mut SysRng).map_or(0.0, |mut rng| rng.random_range(-1.0..=1.0))
}

/// `event` as the webhook sends it: `data.object` reduced to [`OBJECT_KEYS`].
fn payload(mut event: model::Event) -> Result<Vec<u8>, serde_json::Error> {
    if let Some(Value::Object(object)) = event.data.get_mut("object") {
        object.retain(|key, _| OBJECT_KEYS.contains(&key.as_str()));
    }
    serde_json::to_vec(&event)
}

/// The first event after `cursor` the webhook sends: `events.skipped` when the log no longer
/// holds the events after it, else the next one of the types.
fn next_event<N: NodeApi + 'static>(
    opened: &Opened<N>,
    cursor: u64,
    types: &[String],
) -> Result<Option<model::Event>, CliError> {
    if let Some(skipped) = events::skipped_since(opened, cursor)? {
        return Ok(Some(skipped));
    }
    let next = opened.wallet.api_events_after(cursor, 1, types)?;
    Ok(next.into_iter().next().map(events::event))
}

/// Sends the events one by one until the task is dropped.
struct Driver<'a, N: NodeApi + 'static> {
    opened: &'a Opened<N>,
    config: &'a Webhook,
    wake: watch::Receiver<u64>,
    timing: Timing,
    /// When the last request started.
    last: Option<Instant>,
}

impl<N: NodeApi + 'static> Driver<'_, N> {
    /// Waits for what the next send needs, then makes it, and records how it went.
    async fn step(&mut self) -> Result<(), CliError> {
        // Marks the log as seen before it is read, so an event appended meanwhile wakes the wait.
        self.wake.borrow_and_update();
        let state = load(self.opened, &self.config.url)?;
        if state.disabled {
            return self.wait().await;
        }
        let now = self.opened.wallet.ports().clock.now();
        if let Some(due) = state.next_at().filter(|due| *due > now) {
            let wait = Duration::try_from(due.duration_since(now)).unwrap_or_default();
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.wait_ok() => return Ok(()),
            }
        }
        // Read first: an event appended after this is not passed over below.
        let newest = self.opened.wallet.api_event_last_id()?;
        let Some(event) = next_event(self.opened, state.cursor, &self.config.types)? else {
            return self.pass_over(&state, newest).await;
        };
        let secrets = match send::secrets(&self.config.secret_file) {
            Ok(secrets) => secrets,
            Err(error) => return self.hold(&state, error).await,
        };
        if let Some(last) = self.last {
            tokio::time::sleep_until(last.checked_add(self.timing.gap).unwrap_or(last)).await;
        }
        self.last = Some(Instant::now());
        let id = event.id;
        let outcome = self.send(&secrets, state.source, event).await;
        // No wait since the read: the state still has the epoch of this send, or a handler changed it.
        let mut fresh = load(self.opened, &self.config.url)?;
        if fresh.epoch != state.epoch {
            return Ok(());
        }
        let attempt = state.attempts.saturating_add(1);
        fresh.config_error = None;
        match outcome {
            Ok(()) => {
                tracing::debug!(event_id = id, attempt, "webhook delivered");
                fresh.cursor = id;
                fresh.attempts = 0;
                fresh.next_at = None;
                fresh.last_error = None;
            }
            Err(error) => {
                fresh.attempts = attempt;
                fresh.last_error = Some(error.clone());
                match delay(&self.timing.schedule, attempt, jitter_unit()) {
                    Some(wait) => {
                        let due = self.opened.wallet.ports().clock.now();
                        fresh.next_at = SignedDuration::try_from(wait)
                            .ok()
                            .and_then(|wait| due.checked_add(wait).ok())
                            .map(Timestamp::as_millisecond);
                        tracing::warn!(
                            event_id = id,
                            attempt,
                            retry_in_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                            error = %error,
                            "webhook delivery failed"
                        );
                    }
                    None => {
                        fresh.disabled = true;
                        fresh.next_at = None;
                        tracing::error!(
                            event_id = id,
                            attempt,
                            error = %error,
                            "webhook disabled"
                        );
                    }
                }
            }
        }
        save(self.opened, &fresh)
    }

    /// Moves the cursor to `newest` when no event after it is of the types, so the filter does
    /// not hold it back; waits for the log when there is nothing to move.
    async fn pass_over(&mut self, state: &State, newest: u64) -> Result<(), CliError> {
        if newest <= state.cursor {
            return self.wait().await;
        }
        let mut fresh = load(self.opened, &self.config.url)?;
        if fresh.epoch == state.epoch && fresh.cursor == state.cursor {
            fresh.cursor = newest;
            fresh.attempts = 0;
            fresh.next_at = None;
            fresh.last_error = None;
            save(self.opened, &fresh)?;
        }
        Ok(())
    }

    /// Keeps the event while the secret file cannot be used: the reason is stored, no attempt
    /// counts, and the file is read again after [`Timing::hold`] or when the log wakes the driver.
    async fn hold(&mut self, state: &State, error: String) -> Result<(), CliError> {
        let mut fresh = load(self.opened, &self.config.url)?;
        if fresh.epoch == state.epoch && fresh.config_error.as_deref() != Some(error.as_str()) {
            tracing::warn!(error = %error, "the webhook secret file cannot be used");
            fresh.config_error = Some(error);
            save(self.opened, &fresh)?;
        }
        tokio::select! {
            () = tokio::time::sleep(self.timing.hold) => {}
            () = self.wait_ok() => {}
        }
        Ok(())
    }

    /// One request for `event`, with a signature made for this attempt.
    async fn send(
        &self,
        secrets: &[Zeroizing<Vec<u8>>],
        source: u64,
        event: model::Event,
    ) -> Result<(), String> {
        let id = format!("evt_{source:016x}_{}", event.id);
        let body = payload(event).map_err(|_| "the event could not be encoded".to_owned())?;
        let timestamp = self.opened.wallet.ports().clock.now().as_second();
        let headers = [
            ("webhook-id", id.clone()),
            ("webhook-timestamp", timestamp.to_string()),
            (
                "webhook-signature",
                send::signature(secrets, &id, timestamp, &body),
            ),
        ];
        send::post(
            &self.config.url,
            self.config.allow_private,
            &headers,
            body,
            self.timing.limits,
        )
        .await
    }

    /// Ends when the log or a resume wakes the driver; never when serve is gone.
    async fn wait_ok(&mut self) {
        if self.wake.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    async fn wait(&mut self) -> Result<(), CliError> {
        self.wait_ok().await;
        Ok(())
    }
}

/// Sends the API events to the webhook of the settings, when there is one, until serve stops.
pub(in crate::commands::serve) async fn drive<H: Host>(service: &Service<'_, H>) -> Infallible {
    let Some(config) = &service.settings.webhook else {
        return std::future::pending().await;
    };
    let mut driver = Driver {
        opened: &service.held,
        config,
        wake: service.log.subscribe(),
        timing: Timing::LIVE,
        last: None,
    };
    loop {
        if let Err(error) = driver.step().await {
            tracing::warn!(
                error = %lepic_telemetry::ErrorChain(&error),
                "the webhook state was not kept"
            );
            tokio::time::sleep(STORE_PAUSE).await;
        }
    }
}

fn view(config: &Webhook, state: &State) -> model::Webhook {
    let name = if state.disabled {
        "disabled"
    } else if state.config_error.is_some() {
        "config_error"
    } else if state.attempts > 0 {
        "retrying"
    } else {
        "active"
    };
    model::Webhook {
        url: config.url.clone(),
        types: config.types.clone(),
        state: name.to_owned(),
        cursor: state.cursor,
        attempts: state.attempts,
        next_attempt_at: state.next_at().map(|at| at.to_string()),
        last_error: state
            .config_error
            .clone()
            .filter(|_| !state.disabled)
            .or_else(|| state.last_error.clone()),
    }
}

fn configured<'a, H: Host>(service: &'a Service<'_, H>) -> Result<&'a Webhook, Problem> {
    service
        .settings
        .webhook
        .as_ref()
        .ok_or_else(|| Problem::not_found("no webhook is set"))
}

pub(super) async fn get<H: Host>(
    service: &Service<'_, H>,
    _request: Request,
    _context: &Context,
) -> Reply {
    let config = configured(service)?;
    ok(&view(config, &load(&service.held, &config.url)?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeBody {
    #[serde(default)]
    after: Option<u64>,
}

pub(super) async fn resume<H: Host>(
    service: &Service<'_, H>,
    request: Request,
    _context: &Context,
) -> Reply {
    let body: ResumeBody = request.json()?;
    let config = configured(service)?;
    let state = load(&service.held, &config.url)?;
    if let Some(after) = body.after
        && after
            > service
                .held
                .wallet
                .api_event_last_id()
                .map_err(CliError::from)?
    {
        return Err(Problem::invalid(
            "/after",
            "after: an event id the log has reached",
        ));
    }
    let Some(state) = resumed(state, body.after) else {
        return ok(&view(config, &load(&service.held, &config.url)?));
    };
    save(&service.held, &state)?;
    service.log.wake();
    ok(&view(config, &state))
}

/// The state a resume leaves: the cursor at `after`, the failures cleared, a new epoch. None
/// when there is no `after` and nothing is failing, so a send under way is not repeated.
fn resumed(mut state: State, after: Option<u64>) -> Option<State> {
    if after.is_none() && !state.disabled && state.attempts == 0 {
        return None;
    }
    if let Some(after) = after {
        state.cursor = after;
    }
    state.attempts = 0;
    state.next_at = None;
    state.last_error = None;
    state.disabled = false;
    state.epoch = state.epoch.saturating_add(1);
    Some(state)
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::future::Future;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Instant as StdInstant;

    use clap::Parser as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;
    use crate::Console;
    use crate::cli::Cli;
    use crate::commands::Run;
    use crate::commands::serve::support;
    use crate::secret::SecretInput;
    use crate::settings::{Env, Settings};

    const SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

    fn quick() -> Timing {
        Timing {
            schedule: [Duration::from_millis(20); 7],
            gap: Duration::ZERO,
            hold: Duration::from_millis(20),
            limits: send::Limits {
                connect: Duration::from_secs(2),
                total: Duration::from_secs(2),
            },
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Answer {
        Status(u16),
        /// Reads the request, then closes the connection.
        Drop,
        /// Reads the request and says nothing.
        Hang,
    }

    #[derive(Debug, Clone)]
    struct Seen {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        at: StdInstant,
    }

    impl Seen {
        fn header(&self, name: &str) -> &str {
            self.headers
                .iter()
                .find(|(key, _)| key == name)
                .map_or("", |(_, value)| value)
        }
    }

    struct Receiver {
        url: String,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl Receiver {
        fn seen(&self) -> Vec<Seen> {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn ids(&self) -> Vec<String> {
            self.seen()
                .iter()
                .map(|seen| {
                    let id = seen.header("webhook-id");
                    id.rsplit('_').next().unwrap_or(id).to_owned()
                })
                .collect()
        }
    }

    /// A receiver on a loopback port that answers request number n with `script[n]`, and 200
    /// after the script.
    async fn receiver(script: Vec<Answer>) -> Receiver {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut count = 0_usize;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let answer = script.get(count).copied().unwrap_or(Answer::Status(200));
                count = count.saturating_add(1);
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    let (head, body) = loop {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        data.extend_from_slice(&chunk[..read]);
                        let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
                            continue;
                        };
                        let head = String::from_utf8_lossy(&data[..end]).into_owned();
                        let length = head
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        let start = end.saturating_add(4);
                        let stop = start.saturating_add(length);
                        if data.len() >= stop {
                            break (head, data[start..stop].to_vec());
                        }
                    };
                    let headers = head
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                        .collect();
                    log.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(Seen {
                            headers,
                            body,
                            at: StdInstant::now(),
                        });
                    match answer {
                        Answer::Status(code) => {
                            let line = format!(
                                "HTTP/1.1 {code} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                            );
                            let _ = stream.write_all(line.as_bytes()).await;
                        }
                        Answer::Drop => {}
                        Answer::Hang => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        Receiver { url, seen }
    }

    struct Fixture {
        receiver: Receiver,
        config: Webhook,
        _dir: tempfile::TempDir,
    }

    async fn fixture(script: Vec<Answer>, types: &[&str]) -> Fixture {
        let receiver = receiver(script).await;
        let dir = tempfile::tempdir().unwrap();
        let secret_file = dir.path().join("secrets");
        std::fs::write(&secret_file, format!("{SECRET}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = Webhook {
            url: receiver.url.clone(),
            secret_file,
            types: types.iter().map(|kind| (*kind).to_owned()).collect(),
            allow_private: true,
        };
        Fixture {
            receiver,
            config,
            _dir: dir,
        }
    }

    /// Runs `test` on a wallet that is open, in a runtime of its own.
    fn with_wallet<F, Fut>(test: F)
    where
        F: FnOnce(Arc<Opened<crate::host::HostNode<support::TestHost>>>) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let (host, wallet) = support::funded();
        let cli = Cli::try_parse_from(["lepic", "serve"]).unwrap();
        let env = Env::new(wallet.env());
        let settings = Settings::resolve(&cli.global, &env).unwrap();
        let mut console = Console {
            env,
            secrets: SecretInput::new(
                Box::new(std::io::BufReader::new(std::io::empty())),
                false,
                Box::new(std::io::sink()),
            ),
            stdout: Box::new(std::io::sink()),
            stderr: Box::new(std::io::sink()),
            ansi: false,
            stdout_terminal: false,
        };
        let (_keep, interrupt) = watch::channel(false);
        std::thread::Builder::new()
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
                        graceful: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                        held: None,
                        reviewed: None,
                    };
                    let opened = run.open().await.unwrap();
                    test(opened).await;
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn driver<'a>(
        opened: &'a Opened<crate::host::HostNode<support::TestHost>>,
        config: &'a Webhook,
        timing: Timing,
    ) -> Driver<'a, crate::host::HostNode<support::TestHost>> {
        let (_sender, wake) = watch::channel(0_u64);
        Driver {
            opened,
            config,
            wake,
            timing,
            last: None,
        }
    }

    /// Steps until the state satisfies `done`.
    async fn until<N: NodeApi + 'static>(
        driver: &mut Driver<'_, N>,
        done: impl Fn(&State) -> bool,
    ) -> State {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                driver.step().await.unwrap();
                let state = load(driver.opened, &driver.config.url).unwrap();
                if done(&state) {
                    return state;
                }
            }
        })
        .await
        .unwrap()
    }

    const OBJECT: &[u8] = br#"{"object":{"id":"p1","kind":"invoice","state":"paid","address":"epic1xyz","handoff":{"a":1},"amount":"1.0","metadata":{"order":"7"}},"from_state":"awaiting_answer","to_state":"paid"}"#;

    #[test]
    fn a_delivery_is_signed_reduced_and_paced() {
        let script = vec![];
        with_wallet(move |opened| async move {
            let f = fixture(script, &[]).await;
            let timing = Timing {
                gap: Duration::from_millis(150),
                ..quick()
            };
            let mut driver = driver(&opened, &f.config, timing);
            load(&opened, &f.config.url).unwrap();
            opened
                .wallet
                .append_api_event("payment.state_changed", OBJECT)
                .unwrap();
            opened
                .wallet
                .append_api_event("payment.updated", OBJECT)
                .unwrap();
            let state = until(&mut driver, |state| state.cursor == 2).await;
            assert_eq!(
                (state.attempts, state.next_at, state.last_error),
                (0, None, None)
            );
            let seen = f.receiver.seen();
            assert_eq!(f.receiver.ids(), ["1", "2"]);
            assert!(seen[1].at.duration_since(seen[0].at) >= Duration::from_millis(150));
            let first = &seen[0];
            assert_eq!(first.header("content-type"), "application/json");
            let body: Value = serde_json::from_slice(&first.body).unwrap();
            assert_eq!(body["id"], 1);
            assert_eq!(body["type"], "payment.state_changed");
            assert_eq!(
                body["data"]["object"],
                serde_json::json!({
                    "id": "p1", "kind": "invoice", "state": "paid", "amount": "1.0",
                    "metadata": {"order": "7"}
                })
            );
            assert_eq!(body["data"]["from_state"], "awaiting_answer");
            assert_eq!(body["data"]["to_state"], "paid");
            let id = first.header("webhook-id");
            assert!(
                id.starts_with("evt_") && id.len() == "evt_".len() + 16 + 2,
                "{id}"
            );
            let secrets = send::secrets(&f.config.secret_file).unwrap();
            let timestamp: i64 = first.header("webhook-timestamp").parse().unwrap();
            assert_eq!(
                first.header("webhook-signature"),
                send::signature(&secrets, first.header("webhook-id"), timestamp, &first.body)
            );
        });
    }

    #[test]
    fn a_failure_is_retried_with_the_same_event_and_a_new_driver_carries_on() {
        with_wallet(|opened| async move {
            let f = fixture(vec![Answer::Status(500), Answer::Status(500)], &[]).await;
            load(&opened, &f.config.url).unwrap();
            opened
                .wallet
                .append_api_event("payment.created", OBJECT)
                .unwrap();
            let failed = {
                let mut first = driver(&opened, &f.config, quick());
                until(&mut first, |state| state.attempts == 1).await
            };
            assert_eq!(failed.cursor, 0);
            assert!(failed.next_at.is_some());
            assert!(failed.last_error.as_deref().unwrap().contains("500"));
            // The first driver is gone, as after a restart: a new one reads the same record.
            assert_eq!(load(&opened, &f.config.url).unwrap(), failed);
            let mut second = driver(&opened, &f.config, quick());
            let state = until(&mut second, |state| state.attempts == 2).await;
            assert_eq!(state.cursor, 0);
            let state = until(&mut second, |state| state.cursor == 1).await;
            assert_eq!((state.attempts, state.last_error), (0, None));
            assert_eq!(f.receiver.ids(), ["1", "1", "1"]);
        });
    }

    #[test]
    fn a_dropped_connection_and_a_slow_receiver_are_failures() {
        with_wallet(|opened| async move {
            let f = fixture(vec![Answer::Drop, Answer::Hang], &[]).await;
            let timing = Timing {
                limits: send::Limits {
                    connect: Duration::from_secs(2),
                    total: Duration::from_millis(300),
                },
                ..quick()
            };
            load(&opened, &f.config.url).unwrap();
            opened
                .wallet
                .append_api_event("payment.created", OBJECT)
                .unwrap();
            let mut driver = driver(&opened, &f.config, timing);
            let state = until(&mut driver, |state| state.attempts == 1).await;
            assert!(state.last_error.unwrap().contains("dropped"));
            let started = StdInstant::now();
            let state = until(&mut driver, |state| state.attempts == 2).await;
            assert!(started.elapsed() < Duration::from_secs(5));
            assert!(state.last_error.unwrap().contains("in time"));
            let state = until(&mut driver, |state| state.cursor == 1).await;
            assert_eq!(state.attempts, 0);
        });
    }

    #[test]
    fn the_last_failure_disables_the_webhook() {
        with_wallet(|opened| async move {
            let f = fixture(vec![Answer::Status(503); 8], &[]).await;
            load(&opened, &f.config.url).unwrap();
            opened
                .wallet
                .append_api_event("payment.created", OBJECT)
                .unwrap();
            let mut driver = driver(&opened, &f.config, quick());
            let state = until(&mut driver, |state| state.disabled).await;
            assert_eq!((state.attempts, state.next_at, state.cursor), (8, None, 0));
            assert_eq!(f.receiver.seen().len(), 8);
            assert_eq!(view(&f.config, &state).state, "disabled");
            // A resume sets it going again on the same event.
            let again = resumed(state, None).unwrap();
            assert!(!again.disabled);
            assert_eq!(view(&f.config, &again).state, "active");
        });
    }

    #[test]
    fn the_types_filter_and_a_pruned_cursor_decide_what_is_sent() {
        with_wallet(|opened| async move {
            let f = fixture(vec![], &["payment.*"]).await;
            load(&opened, &f.config.url).unwrap();
            let wallet = &opened.wallet;
            wallet.append_api_event("payment.created", OBJECT).unwrap();
            wallet.append_api_event("contact.created", OBJECT).unwrap();
            wallet.append_api_event("payment.updated", OBJECT).unwrap();
            let mut driver = driver(&opened, &f.config, quick());
            until(&mut driver, |state| state.cursor == 3).await;
            assert_eq!(f.receiver.ids(), ["1", "3"]);
            // The log loses the events after the cursor.
            let mut state = load(&opened, &f.config.url).unwrap();
            state.cursor = 0;
            state.epoch += 1;
            save(&opened, &state).unwrap();
            wallet
                .prune_api_events(
                    Timestamp::now()
                        .checked_add(SignedDuration::from_secs(60))
                        .unwrap(),
                )
                .unwrap();
            wallet.append_api_event("payment.created", OBJECT).unwrap();
            until(&mut driver, |state| state.cursor == 4).await;
            let seen = f.receiver.seen();
            let skipped: Value = serde_json::from_slice(&seen[2].body).unwrap();
            assert_eq!(
                (skipped["id"].as_u64(), skipped["type"].as_str()),
                (Some(3), Some("events.skipped"))
            );
            assert_eq!(skipped["data"]["count"], 3);
            assert_eq!(f.receiver.ids(), ["1", "3", "3", "4"]);
        });
    }

    #[test]
    fn the_cursor_moves_past_events_the_types_filter_leaves_out() {
        with_wallet(|opened| async move {
            let f = fixture(vec![], &["payment.*"]).await;
            load(&opened, &f.config.url).unwrap();
            let wallet = &opened.wallet;
            wallet.append_api_event("payment.created", OBJECT).unwrap();
            wallet.append_api_event("contact.created", OBJECT).unwrap();
            wallet.append_api_event("contact.updated", OBJECT).unwrap();
            let mut driver = driver(&opened, &f.config, quick());
            let state = until(&mut driver, |state| state.cursor == 3).await;
            assert_eq!((state.attempts, state.last_error), (0, None));
            assert_eq!(f.receiver.ids(), ["1"]);
            wallet.append_api_event("payment.updated", OBJECT).unwrap();
            until(&mut driver, |state| state.cursor == 4).await;
            assert_eq!(f.receiver.ids(), ["1", "4"]);
        });
    }

    #[test]
    fn a_secret_file_it_cannot_use_holds_the_webhook_without_failing_it() {
        with_wallet(|opened| async move {
            let f = fixture(vec![], &[]).await;
            load(&opened, &f.config.url).unwrap();
            let text = std::fs::read(&f.config.secret_file).unwrap();
            std::fs::remove_file(&f.config.secret_file).unwrap();
            opened
                .wallet
                .append_api_event("payment.created", OBJECT)
                .unwrap();
            let mut driver = driver(&opened, &f.config, quick());
            let held = until(&mut driver, |state| state.config_error.is_some()).await;
            assert_eq!((held.cursor, held.attempts, held.disabled), (0, 0, false));
            assert_eq!(held.last_error, None);
            let shown = view(&f.config, &held);
            assert_eq!(shown.state, "config_error");
            assert!(shown.last_error.unwrap().contains("secret file"));
            // Holding again counts nothing either.
            driver.step().await.unwrap();
            assert_eq!(load(&opened, &f.config.url).unwrap(), held);
            assert!(f.receiver.ids().is_empty());
            std::fs::write(&f.config.secret_file, text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&f.config.secret_file, mode).unwrap();
            }
            let sent = until(&mut driver, |state| state.cursor == 1).await;
            assert_eq!(view(&f.config, &sent).state, "active");
            assert_eq!((sent.attempts, sent.config_error), (0, None));
            assert_eq!(f.receiver.ids(), ["1"]);
        });
    }

    #[test]
    fn a_new_url_starts_at_the_newest_event_and_a_resume_sets_the_cursor() {
        with_wallet(|opened| async move {
            let url = "https://example.test/a";
            let first = load(&opened, url).unwrap();
            opened
                .wallet
                .append_api_event("payment.created", OBJECT)
                .unwrap();
            opened
                .wallet
                .append_api_event("payment.created", OBJECT)
                .unwrap();
            assert_eq!(load(&opened, url).unwrap(), first);
            let moved = load(&opened, "https://example.test/b").unwrap();
            assert_eq!(
                (moved.cursor, moved.attempts, moved.disabled),
                (2, 0, false)
            );
            assert!(moved.epoch > first.epoch);
            let back = resumed(moved.clone(), Some(1)).unwrap();
            assert_eq!((back.cursor, back.epoch), (1, moved.epoch + 1));
            assert_eq!(resumed(moved, None), None);
        });
    }

    #[test]
    fn the_wait_after_a_failure_follows_the_schedule_within_the_jitter() {
        let minutes = |m: u64| Duration::from_secs(m * 60);
        let waits = [
            Duration::from_secs(5),
            minutes(5),
            minutes(30),
            minutes(120),
            minutes(300),
            minutes(600),
            minutes(600),
        ];
        for (index, base) in waits.into_iter().enumerate() {
            let failures = u32::try_from(index + 1).unwrap();
            assert_eq!(delay(&SCHEDULE, failures, 0.0), Some(base));
            assert_eq!(delay(&SCHEDULE, failures, -1.0), Some(base.mul_f64(0.8)));
            assert_eq!(delay(&SCHEDULE, failures, 1.0), Some(base.mul_f64(1.2)));
            assert_eq!(delay(&SCHEDULE, failures, 7.0), Some(base.mul_f64(1.2)));
        }
        assert_eq!(delay(&SCHEDULE, 8, 0.0), None);
        assert_eq!(delay(&SCHEDULE, 0, 0.0), None);
        let unit = jitter_unit();
        assert!((-1.0..=1.0).contains(&unit));
    }
}
