// SPDX-License-Identifier: Apache-2.0
//! CLI instances driven in-process: each has its own data directory and home, and all of them
//! share one mock node and one mock relay, as wallets on one chain do.

// Test helpers may unwrap, index and panic (docs/rules.md); each test binary uses a subset.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lepic_cli::exit::CliError;
use lepic_cli::host::Interrupt;
use lepic_cli::secret::SecretInput;
use lepic_cli::settings::{Env, Settings};
use lepic_cli::{Console, Host, run};
use lepic_epicbox::Connector;
use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_keychain::{Identifier, KdfParams, Keychain, ProofBuilder, SwitchCommitment};
use lepic_node::mock::{ChainOutput, ChainState, MockNode};
use lepic_node::{NodeClient, NodeVersion, Tip};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::params::Network;
use serde_json::Value;
use tempfile::TempDir;

/// The chain tip of the scripted node: far enough past the funding output for it to be
/// spendable with the default three confirmations.
pub const TIP: u64 = 30;

pub const SENDER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

/// Generous for a loaded machine; every wait ends as soon as its condition holds.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// 10 EPIC.
pub const FUNDING: u64 = 1_000_000_000;

/// How often `lepic serve` collects and refreshes under test, so a test sees several cycles.
pub const MAINTENANCE: Duration = Duration::from_millis(100);

pub struct TestHost {
    pub node: MockNode,
    pub relay: MockRelay,
    /// The simulated Ctrl-C comes once this holds; never when `None`.
    pub interrupt_when: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
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
            relay: MockRelay::new(RelayNetwork::Floonet),
            interrupt_when: None,
        }
    }

    /// The same node and relay with no simulated Ctrl-C, for clients of a `lepic serve` whose
    /// host stops it.
    pub fn without_interrupt(&self) -> Self {
        Self {
            node: self.node.clone(),
            relay: self.relay.clone(),
            interrupt_when: None,
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

impl Host for TestHost {
    type Transport = MockNode;

    fn node(&self, _: &Settings) -> Result<NodeClient<MockNode>, CliError> {
        Ok(self.node.client())
    }

    fn relay_connector(&self, _: &Settings) -> Result<Arc<dyn Connector>, CliError> {
        Ok(self.relay.connector())
    }

    fn vault_kdf(&self) -> KdfParams {
        KdfParams::for_tests(8, 1, 1).unwrap()
    }

    fn interrupted(&self) -> Interrupt {
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

    fn maintenance_interval(&self) -> Duration {
        MAINTENANCE
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

/// One CLI user: a home directory, a data directory and a password, on floonet with JSON
/// output.
pub struct Instance {
    pub home: TempDir,
    pub password: String,
}

impl Instance {
    /// `password` must contain a space, so no address, id or amount can contain it and the
    /// leak check in [`Instance::run_with`] means what it says.
    pub fn new(password: &str) -> Self {
        assert!(password.contains(' '), "{password}");
        Self {
            home: tempfile::tempdir().unwrap(),
            password: password.to_owned(),
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
            ("LEPIC_NETWORK".to_owned(), "floonet".to_owned()),
            ("LEPIC_OUTPUT".to_owned(), "json".to_owned()),
            (
                "LEPIC_EPICBOX_RELAY".to_owned(),
                "ws://127.0.0.1:80".to_owned(),
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
pub fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !condition() {
        assert!(started.elapsed() < PATIENCE, "never: {what}");
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
