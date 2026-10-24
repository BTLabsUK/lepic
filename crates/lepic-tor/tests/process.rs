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
use hmac::{Hmac, KeyInit, Mac};
use lepic_tor::{
    FailureKind, OnionAddress, SocksProxy, TorProcess, TorSettings, TorState, TorTimings,
    public_key_of_seed,
};
use sha2::Sha256;
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

/// How the fake answers `ADD_ONION`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// The onion of the key it was given, as tor does.
    Honest,
    /// Another onion's ServiceID.
    OtherServiceId,
    /// The right ServiceID, but descriptor uploads only for another onion.
    UploadsForOther,
    /// As tor, but an onion added again gets no new upload, only one tor reported for the
    /// earlier add, just before the reply.
    NoUploadOnReadd,
}

#[derive(Clone, Copy)]
struct Script {
    bootstrap: Bootstrap,
    uploads: bool,
    answer: Answer,
    /// Stops answering at `SIGNAL ACTIVE`, as a tor that hangs.
    hangs_on_active: bool,
}

const HONEST: Script = Script {
    bootstrap: Bootstrap::Completes,
    uploads: true,
    answer: Answer::Honest,
    hangs_on_active: false,
};

const ADD_FLAGS: &str = "Flags=DiscardPK,MaxStreamsCloseCircuit MaxStreams=4 \
    PoWDefensesEnabled=1 PoWQueueRate=2 PoWQueueBurst=10";

fn add_onion_command(port: u16) -> String {
    format!("ADD_ONION {ADD_FLAGS} Port=80,127.0.0.1:{port}")
}

/// The SOCKS port the fake reports after `toggles` times `DisableNetwork=0`.
fn socks_after(toggles: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 39111 + toggles))
}

fn other_onion() -> String {
    OnionAddress::from_public_key(&[5; 32])
        .service_id()
        .to_owned()
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
        let socks = socks_after(0);
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
        cold_stall: Duration::from_secs(10),
        cold_bootstrap: Duration::from_secs(20),
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
    let mut nonces = None;
    let mut added = Vec::new();
    let mut socks = socks;
    while let Ok(Some(line)) = lines.next_line().await {
        let mut words = line.split(' ');
        let verb = words.next().unwrap_or_default();
        let recorded = if verb == "ADD_ONION" {
            line.split_once(' ').map_or(String::new(), |(_, rest)| {
                rest.split_once(' ')
                    .map_or(String::new(), |(_, flags)| format!("ADD_ONION {flags}"))
            })
        } else if verb == "AUTHCHALLENGE" || verb == "AUTHENTICATE" {
            // The nonces and hashes differ every time.
            line.rsplit_once(' ')
                .map_or(line.clone(), |(head, _)| head.to_owned())
        } else {
            line.clone()
        };
        commands.lock().unwrap().push(recorded);
        let answer = match verb {
            "AUTHCHALLENGE" => {
                assert_eq!(words.next(), Some("SAFECOOKIE"));
                let client_nonce = unhex(words.next().unwrap());
                let server_nonce = vec![3u8; 32];
                let server_hash = safecookie(SERVER_KEY, &client_nonce, &server_nonce);
                let answer = format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    hex(&server_hash).to_uppercase(),
                    hex(&server_nonce)
                );
                nonces = Some((client_nonce, server_nonce));
                answer
            }
            "AUTHENTICATE" => {
                let expected = nonces
                    .take()
                    .map(|(client, server)| hex(&safecookie(CLIENT_KEY, &client, &server)));
                if expected.is_some() && words.next() == expected.as_deref() {
                    "250 OK\r\n".to_owned()
                } else {
                    "515 Authentication failed\r\n".to_owned()
                }
            }
            "TAKEOWNERSHIP" | "RESETCONF" | "SETEVENTS" | "DEL_ONION" => "250 OK\r\n".to_owned(),
            "SETCONF" => {
                if words.next() == Some("DisableNetwork=0") {
                    socks.set_port(socks.port() + 1);
                }
                "250 OK\r\n".to_owned()
            }
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
                let derived = onion_tor_derives(key);
                let id = match script.answer {
                    Answer::OtherServiceId => other_onion(),
                    Answer::Honest | Answer::UploadsForOther | Answer::NoUploadOnReadd => derived,
                };
                let uploaded = match script.answer {
                    Answer::UploadsForOther => other_onion(),
                    Answer::Honest | Answer::OtherServiceId | Answer::NoUploadOnReadd => id.clone(),
                };
                let readded = added.contains(&id);
                added.push(id.clone());
                let mut answer = String::new();
                if readded && script.answer == Answer::NoUploadOnReadd {
                    answer.push_str(&format!(
                        "650 HS_DESC UPLOADED {uploaded} UNKNOWN $AAAA~relay\r\n"
                    ));
                }
                answer.push_str(&format!("250-ServiceID={id}\r\n250 OK\r\n"));
                if script.uploads && !(readded && script.answer == Answer::NoUploadOnReadd) {
                    answer.push_str(&format!(
                        "650 HS_DESC UPLOADED {uploaded} UNKNOWN $AAAA~relay\r\n"
                    ));
                }
                answer
            }
            "SIGNAL" => match words.next() {
                Some("ACTIVE") if script.hangs_on_active => {
                    std::future::pending::<()>().await;
                    return;
                }
                Some("ACTIVE" | "NEWNYM") => "250 OK\r\n".to_owned(),
                _ => {
                    write.write_all(b"250 OK\r\n").await.unwrap();
                    return;
                }
            },
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

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// As tor computes the `SAFECOOKIE` hashes (control-spec, `AUTHCHALLENGE`).
fn safecookie(key: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(&COOKIE);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().to_vec()
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
        ..HONEST
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
            "AUTHCHALLENGE SAFECOOKIE".to_owned(),
            "AUTHENTICATE".to_owned(),
            "TAKEOWNERSHIP".to_owned(),
            "RESETCONF __OwningControllerProcess".to_owned(),
            "SETEVENTS STATUS_CLIENT STATUS_GENERAL HS_DESC".to_owned(),
            "GETINFO net/listeners/socks".to_owned(),
            "GETINFO status/bootstrap-phase".to_owned(),
            add_onion_command(listener_port),
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
        ..HONEST
    })
    .await;
    let tor = TorProcess::start(fake.settings(TorTimings {
        stall: Duration::from_millis(300),
        cold_stall: Duration::from_millis(300),
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
        ..HONEST
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
        ..HONEST
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
        ..HONEST
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
        ..HONEST
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
        ..HONEST
    })
    .await;
    std::fs::write(fake.dir.path().join("exit-now"), "").unwrap();
    let tor = TorProcess::start(fake.settings(quick()));
    let failure = tor.wait_bootstrapped().await.unwrap_err();
    assert_eq!(failure.kind, FailureKind::Start);
    assert_eq!(failure.detail, "fake tor warning");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_of_the_wrong_size_is_a_start_failure() {
    for length in [31, 33, 0] {
        let fake = FakeTor::start(HONEST).await;
        std::fs::write(fake.dir.path().join("fake-cookie"), vec![7; length]).unwrap();
        let tor = TorProcess::start(fake.settings(quick()));
        assert_eq!(wait_for_failure(&tor).await, FailureKind::Start, "{length}");
        assert!(
            fake.commands().iter().all(|c| !c.starts_with("AUTH")),
            "{length}: nothing derived from the cookie is sent"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upload_for_another_onion_does_not_make_it_ready() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Completes,
        uploads: true,
        answer: Answer::UploadsForOther,
        ..HONEST
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor = Arc::new(TorProcess::start(fake.settings(TorTimings {
        publish: Duration::from_secs(2),
        ..quick()
    })));
    tor.wait_bootstrapped().await.unwrap();
    let publishing = tokio::spawn({
        let tor = tor.clone();
        let port = listener.local_addr().unwrap().port();
        async move { tor.publish_onion(&SEED, port).await }
    });
    let mut states = tor.subscribe();
    tokio::time::timeout(
        Duration::from_secs(5),
        states.wait_for(|state| *state == TorState::Publishing),
    )
    .await
    .unwrap()
    .unwrap();
    // The fake sent the other onion's upload right after ADD_ONION.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(tor.state(), TorState::Publishing);
    let failure = publishing.await.unwrap().unwrap_err();
    assert_eq!(failure.kind, FailureKind::Publish);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn republishing_removes_the_old_onion_first() {
    const OTHER_SEED: [u8; 32] = [10; 32];
    let fake = FakeTor::start(HONEST).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tor = TorProcess::start(fake.settings(quick()));
    tor.wait_bootstrapped().await.unwrap();
    let first = tor.publish_onion(&SEED, port).await.unwrap();
    let second = tor.publish_onion(&OTHER_SEED, port).await.unwrap();
    assert_ne!(first, second);
    assert_eq!(tor.state(), TorState::Ready { onion: second });
    let commands = fake.commands();
    let onion_commands: Vec<&str> = commands
        .iter()
        .map(String::as_str)
        .filter(|c| c.starts_with("ADD_ONION") || c.starts_with("DEL_ONION"))
        .collect();
    let add = add_onion_command(port);
    assert_eq!(
        onion_commands,
        [
            add.as_str(),
            format!("DEL_ONION {}", first.service_id()).as_str(),
            add.as_str()
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_service_id_is_a_keys_failure_that_keeps_sending() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Completes,
        uploads: true,
        answer: Answer::OtherServiceId,
        ..HONEST
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor = TorProcess::start(fake.settings(quick()));
    tor.wait_bootstrapped().await.unwrap();
    let failure = tor
        .publish_onion(&SEED, listener.local_addr().unwrap().port())
        .await
        .unwrap_err();
    assert_eq!(failure.kind, FailureKind::Keys);
    assert!(
        fake.commands()
            .contains(&format!("DEL_ONION {}", other_onion())),
        "the onion tor added is removed"
    );
    assert_eq!(tor.state(), TorState::Bootstrapped);
    assert_eq!(tor.socks_address(), Some(fake.socks));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adding_the_same_onion_again_waits_for_an_upload_after_the_add() {
    let fake = FakeTor::start(Script {
        answer: Answer::NoUploadOnReadd,
        ..HONEST
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tor = TorProcess::start(fake.settings(TorTimings {
        publish: Duration::from_millis(500),
        ..quick()
    }));
    tor.wait_bootstrapped().await.unwrap();
    tor.publish_onion(&SEED, port).await.unwrap();
    let failure = tor.publish_onion(&SEED, port).await.unwrap_err();
    assert_eq!(failure.kind, FailureKind::Publish);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_wakes_tor_and_after_a_network_change_reconnects_it() {
    let fake = FakeTor::start(HONEST).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor = TorProcess::start(fake.settings(quick()));
    tor.wait_bootstrapped().await.unwrap();
    let onion = tor
        .publish_onion(&SEED, listener.local_addr().unwrap().port())
        .await
        .unwrap();
    let ready = TorState::Ready { onion };

    tor.refresh(false).await.unwrap();
    assert_eq!(fake.commands().last().unwrap(), "SIGNAL ACTIVE");
    assert_eq!(tor.state(), ready);
    assert_eq!(tor.socks_address(), Some(socks_after(0)));

    let before = fake.commands().len();
    tor.refresh(true).await.unwrap();
    assert_eq!(
        fake.commands()[before..],
        [
            "SETCONF DisableNetwork=1".to_owned(),
            "SETCONF DisableNetwork=0".to_owned(),
            "GETINFO net/listeners/socks".to_owned(),
            "SIGNAL NEWNYM".to_owned(),
            "SIGNAL ACTIVE".to_owned(),
        ]
    );
    assert_eq!(tor.state(), ready);
    assert_eq!(tor.socks_address(), Some(socks_after(1)));
    assert_eq!(tor.wait_bootstrapped().await.unwrap(), socks_after(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_network_turns_tor_off_until_the_next_refresh() {
    let fake = FakeTor::start(HONEST).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tor = TorProcess::start(fake.settings(quick()));
    tor.wait_bootstrapped().await.unwrap();
    let onion = tor
        .publish_onion(&SEED, listener.local_addr().unwrap().port())
        .await
        .unwrap();
    let ready = TorState::Ready { onion };

    let before = fake.commands().len();
    tor.network_lost().await.unwrap();
    assert_eq!(
        fake.commands()[before..],
        ["SETCONF DisableNetwork=1".to_owned()]
    );
    tor.network_lost().await.unwrap();
    assert_eq!(fake.commands().len(), before + 1, "already off");
    assert_eq!(tor.state(), ready);

    // Any refresh turns it on again, as after a network change.
    let before = fake.commands().len();
    tor.refresh(false).await.unwrap();
    assert_eq!(
        fake.commands()[before..],
        [
            "SETCONF DisableNetwork=1".to_owned(),
            "SETCONF DisableNetwork=0".to_owned(),
            "GETINFO net/listeners/socks".to_owned(),
            "SIGNAL NEWNYM".to_owned(),
            "SIGNAL ACTIVE".to_owned(),
        ]
    );
    assert_eq!(tor.state(), ready);
    assert_eq!(tor.wait_bootstrapped().await.unwrap(), socks_after(1));
    let before = fake.commands().len();
    tor.refresh(false).await.unwrap();
    assert_eq!(fake.commands()[before..], ["SIGNAL ACTIVE".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_network_leaves_a_bootstrapping_tor_alone() {
    let fake = FakeTor::start(Script {
        bootstrap: Bootstrap::Stalls,
        uploads: false,
        ..HONEST
    })
    .await;
    let tor = TorProcess::start(fake.settings(quick()));
    tor.network_lost().await.unwrap();
    assert!(
        !fake
            .commands()
            .iter()
            .any(|command| command.starts_with("SETCONF DisableNetwork")),
        "a network turned off would stall the bootstrap"
    );
    assert!(matches!(tor.state(), TorState::Starting { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tor_that_does_not_answer_a_refresh_is_ended() {
    let fake = FakeTor::start(Script {
        hangs_on_active: true,
        ..HONEST
    })
    .await;
    let tor = TorProcess::start(fake.settings(TorTimings {
        command: Duration::from_millis(300),
        ..quick()
    }));
    tor.wait_bootstrapped().await.unwrap();
    let failure = tor.refresh(false).await.unwrap_err();
    assert_eq!(failure.kind, FailureKind::Stopped);
    assert_eq!(wait_for_failure(&tor).await, FailureKind::Stopped);
    assert_eq!(tor.socks_address(), None);
}

/// A control port, as a tor an earlier run left, behind the files of `fake`'s tor directory.
async fn leave_tor(fake: &FakeTor, cookie: [u8; 32]) -> Arc<Mutex<Vec<String>>> {
    let left = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = fake.dir.path().join("tor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("control.txt"),
        format!("PORT={}\n", left.local_addr().unwrap()),
    )
    .unwrap();
    std::fs::write(dir.join("control.cookie"), cookie).unwrap();
    let commands = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(serve_control(
        left,
        HONEST,
        socks_after(0),
        commands.clone(),
    ));
    commands
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_halts_the_tor_an_earlier_run_left() {
    let fake = FakeTor::start(HONEST).await;
    let left = leave_tor(&fake, COOKIE).await;
    let tor = TorProcess::start(fake.settings(quick()));
    tor.wait_bootstrapped().await.unwrap();
    assert_eq!(
        *left.lock().unwrap(),
        [
            "AUTHCHALLENGE SAFECOOKIE".to_owned(),
            "AUTHENTICATE".to_owned(),
            "SIGNAL HALT".to_owned(),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_that_does_not_know_the_left_cookie_is_not_halted() {
    let fake = FakeTor::start(HONEST).await;
    let left = leave_tor(&fake, [8; 32]).await;
    let tor = TorProcess::start(fake.settings(quick()));
    tor.wait_bootstrapped().await.unwrap();
    assert_eq!(
        *left.lock().unwrap(),
        ["AUTHCHALLENGE SAFECOOKIE".to_owned()]
    );
}
