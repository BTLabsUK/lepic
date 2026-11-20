// SPDX-License-Identifier: Apache-2.0
//! CLI instances driven in-process: each has its own data directory and home, and all of them
//! share one mock node and one mock relay, as wallets on one chain do.

// Test helpers may unwrap, index and panic (docs/rules.md); each test binary uses a subset.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lepic_cli::app_config::ApiLimits;
use lepic_cli::exit::CliError;
use lepic_cli::host::Interrupt;
use lepic_cli::secret::SecretInput;
use lepic_cli::settings::{Env, RelayTor, Settings};
use lepic_cli::{Console, Host, run};
use lepic_epicbox::Connector;
use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_keychain::{Identifier, KdfParams, Keychain, ProofBuilder, SwitchCommitment};
use lepic_node::mock::{ChainOutput, ChainState, MockNode};
use lepic_node::{CallPolicy, NodeError, NodeVersion, RetryPolicy, RpcTransport, Tip};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::params::Network;
use lepic_wallet::ports::Clock;
use lepic_wallet_contacts::{PeerDialFuture, PeerDialer};
use serde_json::Value;
use tempfile::TempDir;

pub mod contract;

/// The chain tip of the scripted node: far enough past the funding output for it to be
/// spendable with the default three confirmations.
pub const TIP: u64 = 30;

pub const SENDER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

/// Generous for a loaded machine; every wait ends as soon as its condition holds.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// How long one API call may take: above an epic1 deliver at its worst, 60 s, two routes left
/// each waiting for a connection and an answer, 15 s each by default.
pub const CALL_PATIENCE: Duration = Duration::from_secs(120);

/// 10 EPIC.
pub const FUNDING: u64 = 1_000_000_000;

/// The mailboxes `lepic-config.toml` ships, as `mailbox list` names them.
pub const SHIPPED_MAILBOXES: [&str; 3] = [
    "epicbox.btlabs.uk",
    "epicbox.epiccash.com",
    "epicbox.epicnet.us",
];

/// A public name for a wallet's own relay and only mailbox: a shipped one, as a payer's list
/// must keep one for a payment to an epic1 address. The mock relay answers for any host.
pub const PUBLIC_MAILBOX: &str = SHIPPED_MAILBOXES[0];

/// How often `lepic serve` collects and refreshes under test, so a test sees several cycles.
pub const MAINTENANCE: Duration = Duration::from_millis(100);

pub struct TestHost {
    pub node: MockNode,
    pub relay: MockRelay,
    /// The simulated Ctrl-C comes once this holds; never when `None`.
    pub interrupt_when: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    /// The simulated Ctrl-C comes once this turns true, however long that takes. A caller that
    /// always sets it, as [`serving_with`] does, sets this instead of `interrupt_when`, whose
    /// wait gives up after [`PATIENCE`] and would leave the command running.
    pub stop_when_set: Option<Arc<AtomicBool>>,
    /// A second Ctrl-C comes once this turns true, while serve drains; never when `None`.
    pub hurry_when_set: Option<Arc<AtomicBool>>,
    /// How long serve waits for its connections after a stop; the host's default when `None`.
    pub drain: Option<Duration>,
    /// The bounds of serve's API; the configured ones when `None`.
    pub api_limits: Option<ApiLimits>,
    /// How many invoices serve holds for approval; the host's default when `None`.
    pub max_held: Option<usize>,
    /// A mux/1 relay every socket goes to instead of `relay`, when set.
    pub mux: Option<MuxMockRelay>,
    /// How often serve runs the delivery layer's tick; [`MAINTENANCE`] when `None`.
    pub collect: Option<Duration>,
    /// The wallet's clock, which a test may move ahead.
    pub clock: Arc<MovedClock>,
    /// Stands in for tor to the `tor` entries of links when the settings name a tor.
    pub dialer: Arc<RecordingDialer>,
    /// Holds the node's `get_tip` calls while closed.
    pub tip_gate: Arc<TipGate>,
    /// The chain the host forces on the settings: floonet, the chain of the recorded wallets.
    /// `None` leaves it to the settings, as the shipped binary does.
    pub network: Option<Network>,
}

impl TestHost {
    pub fn new() -> Self {
        Self {
            node: MockNode::from_chain(ChainState::new(
                NodeVersion {
                    node_version: "4.0.4".to_owned(),
                    block_header_version: 6,
                },
                Tip {
                    height: Height::new(TIP),
                    last_block_pushed: Hash::from_slice(&[7; 32]).unwrap(),
                },
            )),
            relay: {
                // The contacts read their mailboxes by push only.
                let relay = MockRelay::new(RelayNetwork::Floonet);
                relay.offer_mux(true);
                relay
            },
            interrupt_when: None,
            stop_when_set: None,
            hurry_when_set: None,
            drain: None,
            api_limits: None,
            max_held: None,
            mux: None,
            collect: None,
            clock: Arc::default(),
            dialer: Arc::default(),
            tip_gate: Arc::default(),
            network: Some(Network::Floonet),
        }
    }

    /// This host, leaving the chain to the settings.
    pub fn network_from_settings(self) -> Self {
        Self {
            network: None,
            ..self
        }
    }

    /// A host whose relay speaks mux/1, with serve's periodic collect `collect` apart.
    pub fn with_mux(collect: Duration) -> Self {
        Self {
            mux: Some(MuxMockRelay::new(RelayNetwork::Floonet)),
            collect: Some(collect),
            ..Self::new()
        }
    }

    /// The same node and relay with no simulated Ctrl-C, for clients of a `lepic serve` whose
    /// host stops it.
    pub fn without_interrupt(&self) -> Self {
        Self {
            node: self.node.clone(),
            relay: self.relay.clone(),
            interrupt_when: None,
            stop_when_set: None,
            hurry_when_set: None,
            drain: self.drain,
            api_limits: self.api_limits,
            max_held: self.max_held,
            mux: self.mux.clone(),
            collect: self.collect,
            clock: Arc::clone(&self.clock),
            dialer: Arc::clone(&self.dialer),
            tip_gate: Arc::clone(&self.tip_gate),
            network: self.network,
        }
    }

    /// Puts an unspent output of `amount` for key `m/0/0/<child>` of `mnemonic` on chain at
    /// height 1, built with the proof scheme LEPIC and epic-wallet use for new outputs.
    pub fn fund(&self, mnemonic: &str, child: u32, amount: u64, mmr_index: u64) {
        let keychain = Keychain::from_mnemonic(mnemonic, Network::Floonet).unwrap();
        let id = Identifier::new(3, [0, 0, child, 0]).unwrap();
        let builder = ProofBuilder::new(&keychain).unwrap();
        let output = lepic_keychain::proof::create_output(
            &keychain,
            &builder,
            amount,
            &id,
            SwitchCommitment::Regular,
        )
        .unwrap();
        self.node.update_chain(|chain| {
            chain.outputs.push(ChainOutput {
                commitment: output.commitment,
                features: output.features,
                proof: output.proof,
                height: Height::new(1),
                mmr_index,
                spent: false,
            });
        });
    }
}

/// Holds every `get_tip` call to the node while closed, so a test can keep a payment's build
/// running for as long as it needs.
#[derive(Debug, Default)]
pub struct TipGate {
    closed: AtomicBool,
    held: AtomicUsize,
}

impl TipGate {
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
    }

    /// How many calls the gate has held so far.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }
}

/// The mock node behind a [`TipGate`].
#[derive(Clone)]
pub struct GatedNode {
    node: MockNode,
    gate: Arc<TipGate>,
}

impl RpcTransport for GatedNode {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        let tip = serde_json::from_slice::<Value>(&body)
            .is_ok_and(|request| request["method"] == "get_tip");
        if tip && self.gate.closed.load(Ordering::SeqCst) {
            self.gate.held.fetch_add(1, Ordering::SeqCst);
            while self.gate.closed.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        self.node.post(endpoint, body).await
    }

    fn node_label(&self) -> &str {
        self.node.node_label()
    }
}

impl Host for TestHost {
    type Transport = GatedNode;

    /// The scripted node, as [`MockNode::client`] calls it, behind the test's gate.
    fn node_transport(&self, _: &Settings) -> Result<(GatedNode, CallPolicy), CliError> {
        Ok((
            GatedNode {
                node: self.node.clone(),
                gate: Arc::clone(&self.tip_gate),
            },
            CallPolicy {
                retry: RetryPolicy::NONE,
                ..lepic_node::testing::call_policy()
            },
        ))
    }

    /// The scripted node, the mock relay and the recorded wallets are on the test chain.
    fn network(&self) -> Option<Network> {
        self.network
    }

    fn relay_connector(&self, _: &Settings) -> Result<Arc<dyn Connector>, CliError> {
        Ok(match &self.mux {
            Some(mux) => mux.connector(),
            None => self.relay.connector(),
        })
    }

    fn vault_kdf(&self) -> KdfParams {
        KdfParams::for_tests(8, 1, 1).unwrap()
    }

    fn interrupted(&self) -> Interrupt {
        if let Some(flag) = self.stop_when_set.clone() {
            return Box::pin(async move {
                while !flag.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
        }
        match self.interrupt_when.clone() {
            Some(condition) => Box::pin(async move {
                let waited = tokio::time::timeout(PATIENCE, async {
                    while !condition() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await;
                assert!(waited.is_ok(), "interrupt condition never held");
            }),
            None => Box::pin(std::future::pending()),
        }
    }

    fn hurried(&self) -> Interrupt {
        match self.hurry_when_set.clone() {
            Some(flag) => Box::pin(async move {
                while !flag.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }),
            None => Box::pin(std::future::pending()),
        }
    }

    fn drain_deadline(&self) -> Duration {
        self.drain.unwrap_or(lepic_cli::host::DRAIN_DEADLINE)
    }

    fn maintenance_interval(&self) -> Duration {
        MAINTENANCE
    }

    fn collect_interval(&self) -> Duration {
        self.collect.unwrap_or(MAINTENANCE)
    }

    fn api_limits(&self, configured: ApiLimits) -> ApiLimits {
        self.api_limits.unwrap_or(configured)
    }

    fn max_held_invoices(&self) -> usize {
        self.max_held.unwrap_or(100)
    }

    fn peer_dialer(&self, settings: &Settings) -> Option<Arc<dyn PeerDialer>> {
        (settings.relay_tor != RelayTor::Off)
            .then(|| Arc::clone(&self.dialer) as Arc<dyn PeerDialer>)
    }

    fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock) as Arc<dyn Clock>
    }
}

/// The system clock, moved ahead by what a test adds.
#[derive(Default)]
pub struct MovedClock(AtomicI64);

impl MovedClock {
    pub fn advance(&self, by: Duration) {
        self.0
            .fetch_add(i64::try_from(by.as_secs()).unwrap(), Ordering::SeqCst);
    }
}

impl Clock for MovedClock {
    fn now(&self) -> jiff::Timestamp {
        let ahead = jiff::SignedDuration::from_secs(self.0.load(Ordering::SeqCst));
        jiff::Timestamp::now().checked_add(ahead).unwrap()
    }
}

/// Records the host and port of each connection asked for and refuses it, as a tor that cannot
/// reach the onion does.
#[derive(Default)]
pub struct RecordingDialer(Mutex<Vec<(String, u16)>>);

impl RecordingDialer {
    pub fn dialed(&self) -> Vec<(String, u16)> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl PeerDialer for RecordingDialer {
    fn dial<'a>(&'a self, host: &'a str, port: u16) -> PeerDialFuture<'a> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((host.to_owned(), port));
        Box::pin(async { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) })
    }
}

#[derive(Clone, Default)]
pub struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    pub fn text(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
        .unwrap()
    }
}

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What one command did.
#[derive(Debug)]
pub struct Outcome {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
}

impl Outcome {
    /// The JSON document a `--output json` command printed.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("stdout is not one json document ({error}): {self:?}"))
    }

    pub fn ok(self) -> Self {
        assert_eq!(self.code, 0, "{self:?}");
        self
    }
}

/// One CLI user: a home directory, a data directory and a password, with JSON output. The
/// chain is the host's.
pub struct Instance {
    pub home: TempDir,
    pub password: String,
    /// The wallet's own relay, `ws://127.0.0.1:80` until [`Instance::on_public_mailbox`].
    relay: std::sync::OnceLock<String>,
}

impl Instance {
    /// `password` must contain a space, so no address, id or amount can contain it and the
    /// leak check in [`Instance::run_with`] means what it says.
    pub fn new(password: &str) -> Self {
        assert!(password.contains(' '), "{password}");
        Self {
            home: tempfile::tempdir().unwrap(),
            password: password.to_owned(),
            relay: std::sync::OnceLock::new(),
        }
    }

    pub fn data_dir(&self) -> PathBuf {
        self.home.path().join("wallet")
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("HOME".to_owned(), self.home.path().display().to_string()),
            (
                "LEPIC_DATA_DIR".to_owned(),
                self.data_dir().display().to_string(),
            ),
            ("LEPIC_OUTPUT".to_owned(), "json".to_owned()),
            (
                "LEPIC_EPICBOX_RELAY".to_owned(),
                self.relay
                    .get()
                    .map_or("ws://127.0.0.1:80", String::as_str)
                    .to_owned(),
            ),
            ("LEPIC_PASSWORD".to_owned(), self.password.clone()),
        ]
    }

    pub fn run(&self, host: &TestHost, args: &[&str]) -> Outcome {
        self.run_with(host, args, self.env(), "")
    }

    pub fn run_with(
        &self,
        host: &TestHost,
        args: &[&str],
        env: Vec<(String, String)>,
        stdin: &str,
    ) -> Outcome {
        let outcome = run_in(host, args, env, stdin);
        for stream in [&outcome.stdout, &outcome.stderr] {
            assert!(
                !stream.contains(&self.password),
                "password printed: {outcome:?}"
            );
        }
        outcome
    }

    pub fn restore(&self, host: &TestHost, mnemonic: &str) -> Value {
        self.run_with(
            host,
            &["wallet", "restore"],
            self.env(),
            &format!("{mnemonic}\n"),
        )
        .ok()
        .json()
    }

    /// Writes the stopped wallet's settings file with `hosts` as its whole mailbox list: the
    /// shipped mailboxes `hosts` leaves out removed, the others added. Without it the list is the
    /// shipped one, whose real host names the mock relay answers too, so native mail goes to
    /// three mailboxes.
    pub fn with_mailboxes(&self, hosts: &[&str]) {
        let quoted = |hosts: Vec<&str>| {
            hosts
                .iter()
                .map(|host| format!("\"{host}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let added = hosts
            .iter()
            .copied()
            .filter(|host| !SHIPPED_MAILBOXES.contains(host))
            .collect();
        let removed = SHIPPED_MAILBOXES
            .into_iter()
            .filter(|host| !hosts.contains(host))
            .collect();
        let dir = self.home.path().join(".lepic");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("settings.toml"),
            format!(
                "[node]\nservers = [\"http://127.0.0.1:3413\"]\n\
                 [mailboxes]\nadded = [{}]\nremoved = [{}]\n",
                quoted(added),
                quoted(removed)
            ),
        )
        .unwrap();
    }

    /// Puts the wallet's own relay at [`PUBLIC_MAILBOX`] and makes that mailbox its whole list,
    /// so the wallet reads and posts on one relay. Call it before the wallet runs a command.
    pub fn on_public_mailbox(&self) {
        self.relay
            .set(format!("wss://{PUBLIC_MAILBOX}"))
            .expect("the own relay is set once");
        self.with_mailboxes(&[PUBLIC_MAILBOX]);
    }
}

pub fn run_in(host: &TestHost, args: &[&str], env: Vec<(String, String)>, stdin: &str) -> Outcome {
    run_reading(
        host,
        args,
        env,
        Box::new(io::Cursor::new(stdin.as_bytes().to_vec())),
    )
}

/// Standard input that never delivers a line while the sender is alive, as from a user who
/// has not pressed Enter.
pub struct SilentInput(pub std::sync::mpsc::Receiver<()>);

impl io::Read for SilentInput {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
}

pub fn run_reading(
    host: &TestHost,
    args: &[&str],
    env: Vec<(String, String)>,
    stdin: Box<dyn io::BufRead + Send>,
) -> Outcome {
    let stdout = Buffer::default();
    let stderr = Buffer::default();
    let mut console = Console {
        env: Env::new(env),
        secrets: SecretInput::new(stdin, false, Box::new(io::sink())),
        stdout: Box::new(stdout.clone()),
        stderr: Box::new(stderr.clone()),
        ansi: false,
        stdout_terminal: false,
    };
    let code = run(
        host,
        std::iter::once("lepic").chain(args.iter().copied()),
        &mut console,
    );
    Outcome {
        code,
        stdout: stdout.text(),
        stderr: stderr.text(),
    }
}

/// Waits until a `lepic serve` binds `socket`.
pub fn wait_for_socket(socket: &Path) {
    let started = std::time::Instant::now();
    while !socket.exists() {
        assert!(
            started.elapsed() < PATIENCE,
            "serve never bound {}",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Waits until `condition` holds, checking it every 20 ms.
pub fn wait_until(what: &str, condition: impl FnMut() -> bool) {
    wait_until_within(what, PATIENCE, condition);
}

/// Waits until `condition` holds, checking it every 20 ms, for at most `patience`.
pub fn wait_until_within(what: &str, patience: Duration, mut condition: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !condition() {
        assert!(started.elapsed() < patience, "never: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not text in {value}"))
}

/// The field names of a JSON object, sorted.
pub fn keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// A response from serve's API.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    /// Header names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|error| panic!("not JSON ({error}): {self:?}"))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body of a 200, as JSON.
    pub fn ok(&self) -> Value {
        assert_eq!(self.status, 200, "{self:?}");
        self.json()
    }
}

/// One HTTP/1.1 request to serve's API on `socket`; the connection closes after the answer.
#[cfg(unix)]
pub fn http(socket: &Path, method: &str, path: &str, body: Option<&str>) -> Reply {
    http_typed(socket, method, path, Some("application/json"), body)
}

/// [`http`] with the request's `Content-Type` as given: `None` sends no such header.
#[cfg(unix)]
pub fn http_typed(
    socket: &Path,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&str>,
) -> Reply {
    use std::io::Read as _;
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    let deadline = std::time::Instant::now() + CALL_PATIENCE;
    let body = body.unwrap_or("");
    let content_type =
        content_type.map_or_else(String::new, |value| format!("Content-Type: {value}\r\n"));
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: lepic\r\n{content_type}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut answer = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !left.is_zero(),
            "{method} {path} took over {CALL_PATIENCE:?}"
        );
        stream.set_read_timeout(Some(left)).unwrap();
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => answer.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                panic!("{method} {path} took over {CALL_PATIENCE:?}")
            }
            Err(error) => panic!("{method} {path}: {error}"),
        }
    }
    let answer = String::from_utf8(answer).unwrap();
    let reply = parse_reply(&answer);
    if let Some(below) = path.strip_prefix("/api/v1") {
        contract::check(method, below, &reply);
    }
    reply
}

/// A response read whole, with a `Content-Length` body.
pub fn parse_reply(answer: &str) -> Reply {
    let (head, body) = answer
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end: {answer:?}"));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    Reply {
        status,
        headers,
        body: body.to_owned(),
    }
}

/// Spawns `serve` in `scope` on a thread with the 8 MiB stack of the main thread `lepic serve`
/// runs on; a test thread has 2 MiB, which a debug build of serve outgrows.
pub fn serve_thread<'scope, T: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    serve: impl FnOnce() -> T + Send + 'scope,
) -> std::thread::ScopedJoinHandle<'scope, T> {
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn_scoped(scope, serve)
        .unwrap()
}

/// Runs `test` against a `lepic serve` of `wallet` on a socket, with `extra` arguments after
/// `serve --socket <path>`, then stops serve.
pub fn serving_with<T: Send>(
    host: TestHost,
    wallet: &Instance,
    extra: &[&str],
    test: impl FnOnce(&Path, &TestHost) -> T + Send,
) -> T {
    serving_with_env(host, wallet, extra, &[], test)
}

/// [`serving_with`] with the settings `env` (`LEPIC_*` names and values) added to the wallet's
/// environment for serve.
pub fn serving_with_env<T: Send>(
    mut host: TestHost,
    wallet: &Instance,
    extra: &[&str],
    env: &[(&str, &str)],
    test: impl FnOnce(&Path, &TestHost) -> T + Send,
) -> T {
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    host.stop_when_set = Some(Arc::clone(&stop));
    let client = host.without_interrupt();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("s.sock");
    let socket_arg = socket.to_str().unwrap();
    let mut args = vec!["serve", "--socket", socket_arg];
    args.extend_from_slice(extra);
    std::thread::scope(|scope| {
        let server = serve_thread(scope, || {
            let mut vars = wallet.env();
            vars.extend(env.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())));
            wallet.run_with(&host, &args, vars, "")
        });
        // Stops serve when the test panics too, or the scope would wait for it forever.
        let stopping = Stop(&stop);
        wait_for_socket(&socket);
        let result = test(&socket, &client);
        drop(stopping);
        server.join().unwrap().ok();
        result
    })
}

/// Runs `test` against a `lepic serve` of `wallet` on a socket, then stops serve.
pub fn serving<T: Send>(
    host: TestHost,
    wallet: &Instance,
    test: impl FnOnce(&Path, &TestHost) -> T + Send,
) -> T {
    serving_with(host, wallet, &[], test)
}

/// The problem document a response carries, checked against the status and code it should
/// have.
pub fn problem(reply: &Reply, status: u16, code: &str) -> Value {
    assert_eq!(reply.status, status, "{reply:?}");
    assert_eq!(
        reply.header("content-type"),
        Some("application/problem+json"),
        "{reply:?}"
    );
    let problem = reply.json();
    assert_eq!(problem["type"], "about:blank", "{problem}");
    assert_eq!(problem["status"], status, "{problem}");
    assert_eq!(problem["code"], code, "{problem}");
    assert!(problem["detail"].is_string(), "{problem}");
    problem
}

/// A restored wallet holding [`FUNDING`] on the mock chain.
pub fn funded() -> (TestHost, Instance) {
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    let wallet = Instance::new("serving password");
    wallet.restore(&host, SENDER_MNEMONIC);
    (host, wallet)
}

/// A wallet created from new entropy on `host`'s chain and relay, not served.
pub fn new_wallet(host: &TestHost, password: &str) -> Instance {
    let wallet = Instance::new(password);
    wallet.run(host, &["wallet", "init"]).ok();
    wallet
}

/// Runs `change` on the settings of the stopped wallet `wallet` restored from `mnemonic`, as
/// another program with the phrase would: a test cuts a create short by taking away what it
/// writes after the object.
pub fn with_settings<T>(
    wallet: &Instance,
    mnemonic: &str,
    change: impl FnOnce(&mut dyn lepic_store::Repositories) -> Result<T, lepic_store::StoreError>,
) -> T {
    use lepic_store::WalletStore as _;
    use lepic_wallet::StoreOpener as _;
    let seed = lepic_keychain::Seed::from_mnemonic(mnemonic).unwrap();
    let store = lepic_wallet::EncryptedSqliteStores
        .open(
            &wallet.data_dir(),
            lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
            &lepic_wallet::store_key(&seed).unwrap(),
        )
        .unwrap();
    store.write(change).unwrap()
}
