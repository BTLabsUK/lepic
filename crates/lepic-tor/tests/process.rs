//! The tor process and its states against a fake tor: `tests/fixtures/fake-tor.sh` stands in
//! for the binary, and this test serves its control port, answering as tor does. The fake
//! derives the onion from the key `ADD_ONION` carries the way tor does, so the published onion
//! proves the key expansion end to end.
#![cfg(unix)]
// Helpers outside #[test] functions unwrap and index too; a failure there is a test failure.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use lepic_tor::{
    FailureKind, OnionAddress, SocksProxy, TorProcess, TorSettings, TorState, TorTimings,
    public_key_of_seed,
};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const COOKIE: [u8; 32] = [7; 32];
const SEED: [u8; 32] = [9; 32];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bootstrap {
    Completes,
    Stalls,
    ClockSkew,
    CompletesThenCloses,
}

#[derive(Clone, Copy)]
struct Script {
    bootstrap: Bootstrap,
    uploads: bool,
}

struct FakeTor {
    dir: TempDir,
    socks: SocketAddr,
    commands: Arc<Mutex<Vec<String>>>,
}

impl FakeTor {
    async fn start(script: Script) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks: SocketAddr = "127.0.0.1:39111".parse().unwrap();
        std::fs::write(dir.path().join("fake-cookie"), COOKIE).unwrap();
        std::fs::write(
            dir.path().join("fake-control"),
            format!("PORT={}\n", control.local_addr().unwrap()),
        )
        .unwrap();
        let commands = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(serve_control(control, script, socks, commands.clone()));
        Self {
            dir,
            socks,
            commands,
        }
    }

    fn settings(&self, timings: TorTimings) -> TorSettings {
        let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-tor.sh");
        let mut settings = TorSettings::new(binary, self.dir.path().join("tor"));
        settings.timings = timings;
        settings
    }

    fn commands(&self) -> Vec<String> {
        self.commands.lock().unwrap().clone()
    }
}

fn quick() -> TorTimings {
    TorTimings {
        control_file: Duration::from_secs(10),
        command: Duration::from_secs(5),
        stall: Duration::from_secs(10),
        bootstrap: Duration::from_secs(20),
        publish: Duration::from_secs(10),
        stop: Duration::from_millis(500),
        listener_check: Duration::from_millis(500),
    }
}

/// The onion tor would publish for an `ADD_ONION ED25519-V3:<base64>` key.
fn onion_tor_derives(key_base64: &str) -> String {
    let key: [u8; 64] = STANDARD.decode(key_base64).unwrap().try_into().unwrap();
    let public = VerifyingKey::from(&ExpandedSecretKey::from_bytes(&key)).to_bytes();
    OnionAddress::from_public_key(&public)
        .service_id()
        .to_owned()
}

async fn serve_control(
    listener: TcpListener,
    script: Script,
    socks: SocketAddr,
    commands: Arc<Mutex<Vec<String>>>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let mut words = line.split(' ');
        let verb = words.next().unwrap_or_default();
        let recorded = if verb == "ADD_ONION" {
            line.split_once(' ').map_or(String::new(), |(_, rest)| {
                rest.split_once(' ')
                    .map_or(String::new(), |(_, flags)| format!("ADD_ONION {flags}"))
            })
        } else {
            line.clone()
        };
        commands.lock().unwrap().push(recorded);
        let answer = match verb {
            "AUTHENTICATE" => {
                if words.next() == Some(hex(&COOKIE).as_str()) {
                    "250 OK\r\n".to_owned()
                } else {
                    "515 Authentication failed\r\n".to_owned()
                }
            }
            "TAKEOWNERSHIP" | "RESETCONF" | "SETEVENTS" | "DEL_ONION" => "250 OK\r\n".to_owned(),
            "GETINFO" => match words.next() {
                Some("net/listeners/socks") => {
                    format!("250-net/listeners/socks=\"{socks}\"\r\n250 OK\r\n")
                }
                Some("status/bootstrap-phase") => {
                    let mut answer = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=10 TAG=conn_done SUMMARY=\"Connected\"\r\n250 OK\r\n".to_owned();
                    answer.push_str(&match script.bootstrap {
                        Bootstrap::Completes | Bootstrap::CompletesThenCloses => {
                            "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors SUMMARY=\"x\"\r\n650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n".to_owned()
                        }
                        Bootstrap::Stalls => String::new(),
                        Bootstrap::ClockSkew => {
                            "650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=-7200 SOURCE=OR:1.2.3.4:443\r\n".to_owned()
                        }
                    });
                    answer
                }
                _ => "552 Unrecognized key\r\n".to_owned(),
            },
            "ADD_ONION" => {
                let key = words
                    .next()
                    .and_then(|k| k.strip_prefix("ED25519-V3:"))
                    .unwrap();
                let id = onion_tor_derives(key);
                let mut answer = format!("250-ServiceID={id}\r\n250 OK\r\n");
                if script.uploads {
                    answer.push_str(&format!(
                        "650 HS_DESC UPLOADED {id} UNKNOWN $AAAA~relay\r\n"
                    ));
                }
                answer
            }
            "SIGNAL" => {
                write.write_all(b"250 OK\r\n").await.unwrap();
                return;
            }
            _ => "510 Unrecognized command\r\n".to_owned(),
        };
        write.write_all(answer.as_bytes()).await.unwrap();
        if script.bootstrap == Bootstrap::CompletesThenCloses && answer.contains("PROGRESS=100") {
            return;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn wait_for_failure(tor: &TorProcess) -> FailureKind {
    let mut states = tor.subscribe();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let TorState::Failed(failure) = &*states.borrow_and_update() {
                return failure.kind;
            }
            states.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstraps_publishes_the_wallet_onion_and_stops() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Completes,
        uploads: true,
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_port = listener.local_addr().unwrap().port();
    let tor = TorProcess::start(fake.settings(quick()));

    assert_eq!(tor.wait_bootstrapped().await.unwrap(), fake.socks);
    assert_eq!(tor.socks_address(), Some(fake.socks));
    let onion = tor.publish_onion(&SEED, listener_port).await.unwrap();
    assert_eq!(
        onion,
        OnionAddress::from_public_key(&public_key_of_seed(&SEED))
    );
    assert_eq!(
        tor.state(),
        TorState::Ready {
            onion: onion.clone()
        }
    );

    let torrc = std::fs::read_to_string(fake.dir.path().join("tor/torrc")).unwrap();
    assert!(torrc.contains(&format!(
        "__OwningControllerProcess {}\n",
        std::process::id()
    )));
    assert_eq!(mode(&fake.dir.path().join("tor")), 0o700);
    assert_eq!(mode(&fake.dir.path().join("tor/data")), 0o700);

    let started = std::time::Instant::now();
    tor.stop().await;
    assert!(started.elapsed() < Duration::from_secs(3));
    let commands = fake.commands();
    assert_eq!(
        commands,
        [
            format!("AUTHENTICATE {}", hex(&COOKIE)),
            "TAKEOWNERSHIP".to_owned(),
            "RESETCONF __OwningControllerProcess".to_owned(),
            "SETEVENTS STATUS_CLIENT STATUS_GENERAL HS_DESC".to_owned(),
            "GETINFO net/listeners/socks".to_owned(),
            "GETINFO status/bootstrap-phase".to_owned(),
            format!("ADD_ONION Flags=DiscardPK Port=80,127.0.0.1:{listener_port}"),
            format!("DEL_ONION {}", onion.service_id()),
            "SIGNAL SHUTDOWN".to_owned(),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_bootstrap_is_a_network_failure() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Stalls,
        uploads: false,
    })
    .await;
    let tor = TorProcess::start(fake.settings(TorTimings {
        stall: Duration::from_millis(300),
        ..quick()
    }));
    assert_eq!(wait_for_failure(&tor).await, FailureKind::Network);
    assert_eq!(tor.socks_address(), None);
    assert_eq!(
        tor.wait_bootstrapped().await.unwrap_err().kind,
        FailureKind::Network
    );
    assert_eq!(
        tor.publish_onion(&SEED, 1).await.unwrap_err().kind,
        FailureKind::Network
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_skew_before_bootstrap_is_a_clock_failure() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::ClockSkew,
        uploads: false,
    })
    .await;
    let tor = TorProcess::start(fake.settings(quick()));
    assert_eq!(wait_for_failure(&tor).await, FailureKind::Clock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn losing_tor_after_bootstrap_is_stopped() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::CompletesThenCloses,
        uploads: false,
    })
    .await;
    let tor = TorProcess::start(fake.settings(quick()));
    assert_eq!(wait_for_failure(&tor).await, FailureKind::Stopped);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_that_does_not_answer_keeps_tor_for_sending() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Completes,
        uploads: true,
    })
    .await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let tor = TorProcess::start(fake.settings(quick()));
    tor.wait_bootstrapped().await.unwrap();
    let failure = tor.publish_onion(&SEED, port).await.unwrap_err();
    assert_eq!(failure.kind, FailureKind::Listener);
    assert_eq!(tor.state(), TorState::Bootstrapped);
    assert!(fake.commands().iter().all(|c| !c.starts_with("ADD_ONION")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_descriptor_upload_in_time_is_a_publish_failure() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Completes,
        uploads: false,
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor = TorProcess::start(fake.settings(TorTimings {
        publish: Duration::from_millis(300),
        ..quick()
    }));
    tor.wait_bootstrapped().await.unwrap();
    let failure = tor
        .publish_onion(&SEED, listener.local_addr().unwrap().port())
        .await
        .unwrap_err();
    assert_eq!(failure.kind, FailureKind::Publish);
}

#[tokio::test]
async fn a_missing_binary_is_reported_as_missing() {
    let dir = tempfile::tempdir().unwrap();
    let tor = TorProcess::start(TorSettings::new(
        dir.path().join("no-tor-here"),
        dir.path().join("tor"),
    ));
    assert_eq!(wait_for_failure(&tor).await, FailureKind::Missing);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_that_exits_at_once_reports_its_last_warning() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Completes,
        uploads: false,
    })
    .await;
    std::fs::write(fake.dir.path().join("exit-now"), "").unwrap();
    let tor = TorProcess::start(fake.settings(quick()));
    let failure = tor.wait_bootstrapped().await.unwrap_err();
    assert_eq!(failure.kind, FailureKind::Start);
    assert_eq!(failure.detail, "fake tor warning");
}
