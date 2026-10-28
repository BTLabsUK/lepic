//! Direct transactions over Tor between two wallets of one runtime on the scripted chain.
//! `tests/fixtures/fake-tor.sh` stands in for tor; each wallet's control port is served here,
//! and one fake SOCKS server stands in for the Tor network: it connects `<onion>:80` to the
//! listener port its wallet's tor added the onion for.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

use super::http::{EPIC, Pair, funded_pair, password, sends};
use super::{eventually, kind};
use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::secret_store::AppSecretStore;
use crate::api::tor::{TorEvent, TorEventKind, TorFailureKind, TorStatusKind};
use crate::api::types::{Chain, TxStatus, WalletConfig};
use crate::session::{SeedOrigin, Session, TorReport};

/// A cookie no other fake tor in this test run has: a start halts a tor that knows the cookie
/// its files hold, and a port a stopped fake used may serve another test's fake by now.
fn fresh_cookie() -> [u8; 32] {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let mut cookie = [7; 32];
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    cookie[..8].copy_from_slice(&n.to_le_bytes());
    cookie
}
const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

fn fake_tor() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fake-tor.sh")
        .to_string_lossy()
        .into_owned()
}

fn quick() -> lepic_tor::TorTimings {
    lepic_tor::TorTimings {
        control_file: Duration::from_secs(10),
        command: Duration::from_secs(5),
        stall: Duration::from_secs(10),
        bootstrap: Duration::from_secs(20),
        cold_stall: Duration::from_secs(10),
        cold_bootstrap: Duration::from_secs(20),
        publish: Duration::from_secs(10),
        stop: Duration::from_secs(2),
        listener_check: Duration::from_secs(2),
    }
}

/// Onion service ids and the listener ports their wallets' tor forwards to.
type Onions = Arc<Mutex<HashMap<String, u16>>>;

/// The fake Tor network: one SOCKS server for every wallet's tor.
struct FakeNetwork {
    socks: SocketAddr,
    onions: Onions,
}

impl FakeNetwork {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks = listener.local_addr().unwrap();
        let onions = Onions::default();
        let routes = Arc::clone(&onions);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_socks(stream, Arc::clone(&routes)));
            }
        });
        Self { socks, onions }
    }

    /// Leaves what the fake tor of the wallet in `wallet_dir` copies, and serves its control
    /// port, publishing the onion `onion` as that wallet's. Returns the commands it receives.
    async fn prepare(&self, wallet_dir: &Path, onion: &str) -> Arc<Mutex<Vec<String>>> {
        let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cookie = fresh_cookie();
        std::fs::write(wallet_dir.join("fake-cookie"), cookie).unwrap();
        std::fs::write(
            wallet_dir.join("fake-control"),
            format!("PORT={}\n", control.local_addr().unwrap()),
        )
        .unwrap();
        let commands = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(serve_control(
            control,
            cookie,
            self.socks,
            Arc::clone(&self.onions),
            onion.trim_end_matches(".onion").to_owned(),
            wallet_dir.to_path_buf(),
            Arc::clone(&commands),
        ));
        commands
    }

    fn listener_port(&self, onion: &str) -> Option<u16> {
        self.onions
            .lock()
            .unwrap()
            .get(onion.trim_end_matches(".onion"))
            .copied()
    }
}

async fn serve_socks(mut stream: TcpStream, onions: Onions) {
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 2], "username and password authentication");
    stream.write_all(&[5, 2]).await.unwrap();
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.unwrap();
    let mut username = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut username).await.unwrap();
    let mut length = [0u8; 1];
    stream.read_exact(&mut length).await.unwrap();
    let mut password = vec![0u8; usize::from(length[0])];
    stream.read_exact(&mut password).await.unwrap();
    stream.write_all(&[1, 0]).await.unwrap();
    let mut request = [0u8; 5];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request[..4], [5, 1, 0, 3], "connect with a domain name");
    let mut host = vec![0u8; usize::from(request[4])];
    stream.read_exact(&mut host).await.unwrap();
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.unwrap();
    assert_eq!(u16::from_be_bytes(port), 80);
    let host = String::from_utf8(host).unwrap();
    let target = onions
        .lock()
        .unwrap()
        .get(host.trim_end_matches(".onion"))
        .copied();
    let Some(target) = target else {
        // Onion descriptor not found, as tor answers for a wallet that is not online.
        stream
            .write_all(&[5, 0xF0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        return;
    };
    stream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut upstream = TcpStream::connect(("127.0.0.1", target)).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
}

/// Answers as tor's control port does for a bootstrap that completes and an onion whose
/// descriptor uploads at once. `SIGNAL SHUTDOWN` makes the fake tor exit.
async fn serve_control(
    listener: TcpListener,
    cookie: [u8; 32],
    socks: SocketAddr,
    onions: Onions,
    service_id: String,
    wallet_dir: PathBuf,
    commands: Arc<Mutex<Vec<String>>>,
) {
    let (stream, _) = listener.accept().await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut nonces = None;
    while let Ok(Some(line)) = lines.next_line().await {
        let mut words = line.split(' ');
        let verb = words.next().unwrap_or_default();
        commands.lock().unwrap().push(match verb {
            // Neither the key nor the hash belongs in the record.
            "ADD_ONION" | "AUTHCHALLENGE" | "AUTHENTICATE" => verb.to_owned(),
            _ => line.clone(),
        });
        let answer = match verb {
            "AUTHCHALLENGE" => {
                assert_eq!(words.next(), Some("SAFECOOKIE"));
                let client_nonce = unhex(words.next().unwrap());
                let server_nonce = vec![3u8; 32];
                let server_hash = safecookie(&cookie, SERVER_KEY, &client_nonce, &server_nonce);
                let answer = format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    hex(&server_hash),
                    hex(&server_nonce)
                );
                nonces = Some((client_nonce, server_nonce));
                answer
            }
            "AUTHENTICATE" => {
                let expected = nonces
                    .take()
                    .map(|(client, server)| hex(&safecookie(&cookie, CLIENT_KEY, &client, &server)));
                if expected.is_some() && words.next() == expected.as_deref() {
                    "250 OK\r\n".to_owned()
                } else {
                    "515 Authentication failed\r\n".to_owned()
                }
            }
            "TAKEOWNERSHIP" | "RESETCONF" | "SETEVENTS" | "SETCONF" => "250 OK\r\n".to_owned(),
            "SIGNAL" if line == "SIGNAL ACTIVE" || line == "SIGNAL NEWNYM" => {
                "250 OK\r\n".to_owned()
            }
            "DEL_ONION" => {
                onions.lock().unwrap().remove(words.next().unwrap());
                "250 OK\r\n".to_owned()
            }
            "GETINFO" => match words.next() {
                Some("net/listeners/socks") => {
                    format!("250-net/listeners/socks=\"{socks}\"\r\n250 OK\r\n")
                }
                Some("status/bootstrap-phase") => concat!(
                    "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=10 TAG=conn_done SUMMARY=\"Connected\"\r\n250 OK\r\n",
                    "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n"
                )
                .to_owned(),
                _ => "552 Unrecognized key\r\n".to_owned(),
            },
            "ADD_ONION" => {
                let target = line
                    .split(' ')
                    .find_map(|word| word.strip_prefix("Port=80,127.0.0.1:"))
                    .unwrap();
                onions
                    .lock()
                    .unwrap()
                    .insert(service_id.clone(), target.parse().unwrap());
                format!(
                    "250-ServiceID={service_id}\r\n250 OK\r\n650 HS_DESC UPLOADED {service_id} UNKNOWN $AAAA~relay\r\n"
                )
            }
            "SIGNAL" => {
                write.write_all(b"250 OK\r\n").await.unwrap();
                std::fs::write(wallet_dir.join("stop-now"), b"").unwrap();
                return;
            }
            _ => "510 Unrecognized command\r\n".to_owned(),
        };
        write.write_all(answer.as_bytes()).await.unwrap();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn safecookie(cookie: &[u8], key: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<TorEvent>>>);

impl Events {
    fn report(&self) -> TorReport {
        let events = Arc::clone(&self.0);
        Arc::new(move |event| events.lock().unwrap().push(event))
    }

    fn kinds(&self) -> Vec<TorEventKind> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|event| event.kind)
            .collect()
    }

    fn find(&self, kind: TorEventKind) -> Option<TorEvent> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|event| event.kind == kind)
            .cloned()
    }

    async fn wait_for(&self, kind: TorEventKind) -> TorEvent {
        for _ in 0..1000 {
            if let Some(event) = self.find(kind) {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no {kind:?} in {:?}", self.kinds());
    }
}

/// Starts the tor of `session`, whose data directory is `dir`, and waits until its onion is
/// published.
async fn start_tor(
    network: &FakeNetwork,
    session: &Arc<Session>,
    dir: &Path,
) -> (Events, Arc<Mutex<Vec<String>>>) {
    let onion = session.onion_address().unwrap();
    let commands = network.prepare(dir, &onion).await;
    let events = Events::default();
    session.set_tor_timings(quick());
    session
        .start_tor(fake_tor(), None, events.report())
        .await
        .unwrap();
    let ready = events.wait_for(TorEventKind::Ready).await;
    assert_eq!(ready.onion, Some(onion));
    (events, commands)
}

async fn tor_pair() -> (Pair, FakeNetwork) {
    (funded_pair().await, FakeNetwork::start().await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tor_send_reaches_the_onion_of_the_other_wallet_and_is_finalized_and_posted() {
    let (pair, network) = tor_pair().await;
    let (bob_events, _) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    let (alice_events, _) = start_tor(&network, &pair.alice, pair.dirs[0].path()).await;
    let bob_onion = pair.bob.onion_address().unwrap();

    let sent = pair
        .alice
        .send_tor(2 * EPIC, 1, &bob_onion, Some("over tor".to_owned()), None)
        .await
        .unwrap();

    assert!(sent.posted);
    assert_eq!(sent.amount, 2 * EPIC);
    assert_eq!(pair.chain.pushed_count(), 1);
    let alice_tx = pair.alice.transaction(sent.tx_id).await.unwrap();
    assert_eq!(alice_tx.status, TxStatus::Posted);
    assert_eq!(alice_tx.transport.as_deref(), Some("tor"));
    assert!(alice_events.find(TorEventKind::Sending).is_some());
    let received = bob_events.wait_for(TorEventKind::Received).await;
    assert_eq!(received.amount, Some(2 * EPIC));
    assert!(!received.repeated);
    let bob_tx = pair.bob.transaction(received.tx_id.unwrap()).await.unwrap();
    assert_eq!(bob_tx.status, TxStatus::Received);
    assert_eq!(bob_tx.slate_id, Some(sent.slate_id));
    assert_eq!(bob_tx.transport.as_deref(), Some("tor"));
    let kinds = bob_events.kinds();
    assert_eq!(kinds.first(), Some(&TorEventKind::Starting));
    assert!(kinds.contains(&TorEventKind::Bootstrapped));
    assert_eq!(pair.bob.tor_status().kind, TorStatusKind::Ready);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_to_an_onion_that_is_not_online_is_kept_for_a_resend() {
    let (pair, network) = tor_pair().await;
    start_tor(&network, &pair.alice, pair.dirs[0].path()).await;
    let bob_onion = pair.bob.onion_address().unwrap();

    let unreachable = pair.alice.send_tor(EPIC, 1, &bob_onion, None, None).await;

    assert_eq!(kind(unreachable), WalletErrorKind::OnionUnreachable);
    let stored = sends(&pair.alice).await;
    let [sent] = stored.as_slice() else {
        panic!("{stored:?}");
    };
    assert_eq!(sent.status, TxStatus::Sent);

    start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    let resent = pair
        .alice
        .resend_tor(sent.tx_id, &format!("http://{bob_onion}/"))
        .await
        .unwrap();

    assert!(resent.posted);
    assert_eq!(Some(resent.slate_id), sent.slate_id);
    assert_eq!(pair.chain.pushed_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tor_send_needs_an_onion_and_a_running_tor_and_stores_nothing_without() {
    let pair = funded_pair().await;
    let bob_onion = pair.bob.onion_address().unwrap();

    let without_tor = pair.alice.send_tor(EPIC, 1, &bob_onion, None, None).await;
    assert_eq!(kind(without_tor), WalletErrorKind::TorNotRunning);
    let mut typo = bob_onion.clone();
    typo.replace_range(..1, if typo.starts_with('a') { "b" } else { "a" });
    for invalid in ["", "wallet.example.org", typo.as_str()] {
        let refused = pair.alice.send_tor(EPIC, 1, invalid, None, None).await;
        assert_eq!(
            kind(refused),
            WalletErrorKind::OnionAddressInvalid,
            "{invalid}"
        );
    }
    assert!(sends(&pair.alice).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_stops_tor_and_then_its_listener() {
    let (pair, network) = tor_pair().await;
    let (events, commands) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    let onion = pair.bob.onion_address().unwrap();
    let port = network.listener_port(&onion).unwrap();
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok(),
        "the listener behind the onion answers"
    );

    pair.bob.lock();

    events.wait_for(TorEventKind::Stopped).await;
    assert_eq!(events.kinds().last(), Some(&TorEventKind::Stopped));
    let commands = commands.lock().unwrap().clone();
    assert!(commands.contains(&format!("DEL_ONION {}", onion.trim_end_matches(".onion"))));
    assert_eq!(commands.last().map(String::as_str), Some("SIGNAL SHUTDOWN"));
    std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    assert_eq!(pair.bob.tor_status().kind, TorStatusKind::Off);
    let locked = pair
        .bob
        .start_tor(fake_tor(), None, Events::default().report())
        .await;
    assert_eq!(kind(locked), WalletErrorKind::Locked);
    assert_eq!(kind(pair.bob.onion_address()), WalletErrorKind::Locked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_reaches_the_running_tor_and_keeps_the_onion() {
    let (pair, network) = tor_pair().await;
    assert_eq!(
        kind(pair.bob.refresh_tor(false).await),
        WalletErrorKind::TorNotRunning
    );
    let (events, commands) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;

    pair.bob.refresh_tor(false).await.unwrap();
    assert_eq!(
        commands.lock().unwrap().last().map(String::as_str),
        Some("SIGNAL ACTIVE")
    );
    pair.bob.refresh_tor(true).await.unwrap();
    let commands = commands.lock().unwrap().clone();
    assert_eq!(
        commands[commands.len() - 5..],
        [
            "SETCONF DisableNetwork=1".to_owned(),
            "SETCONF DisableNetwork=0".to_owned(),
            "GETINFO net/listeners/socks".to_owned(),
            "SIGNAL NEWNYM".to_owned(),
            "SIGNAL ACTIVE".to_owned(),
        ]
    );
    let status = pair.bob.tor_status();
    assert_eq!(status.kind, TorStatusKind::Ready);
    assert_eq!(status.onion, Some(pair.bob.onion_address().unwrap()));
    assert!(events.find(TorEventKind::Failed).is_none());

    pair.bob.lock();
    events.wait_for(TorEventKind::Stopped).await;
    assert_eq!(
        kind(pair.bob.refresh_tor(false).await),
        WalletErrorKind::Locked
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_network_turns_the_running_tor_off_until_the_next_refresh() {
    let (pair, network) = tor_pair().await;
    pair.bob.tor_network_lost().await.unwrap();
    let (events, commands) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;

    let before = commands.lock().unwrap().len();
    pair.bob.tor_network_lost().await.unwrap();
    assert_eq!(
        commands.lock().unwrap()[before..],
        ["SETCONF DisableNetwork=1".to_owned()]
    );
    pair.bob.refresh_tor(true).await.unwrap();
    assert_eq!(
        commands.lock().unwrap().last().map(String::as_str),
        Some("SIGNAL ACTIVE")
    );
    assert!(commands.lock().unwrap()[before..].contains(&"SETCONF DisableNetwork=0".to_owned()));
    assert_eq!(pair.bob.tor_status().kind, TorStatusKind::Ready);
    assert!(events.find(TorEventKind::Failed).is_none());

    pair.bob.lock();
    events.wait_for(TorEventKind::Stopped).await;
    pair.bob.tor_network_lost().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_tor_frees_the_slot_for_a_new_start_and_a_wallet_runs_one_tor() {
    let (pair, network) = tor_pair().await;
    let (events, _) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    let second = Events::default();
    pair.bob
        .start_tor(fake_tor(), None, second.report())
        .await
        .unwrap();
    assert!(second.kinds().is_empty());

    pair.bob.stop_tor();
    events.wait_for(TorEventKind::Stopped).await;
    assert_eq!(pair.bob.tor_status().kind, TorStatusKind::Off);

    start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_goes_through_tor_while_it_runs_and_the_setting_is_on() {
    let (pair, network) = tor_pair().await;
    let bob = &pair.bob;
    assert!(bob.epicbox_over_tor(), "on by default");
    assert!(!bob.relay_through_tor(), "tor is off");

    let (events, _) = start_tor(&network, bob, pair.dirs[1].path()).await;
    assert!(bob.relay_through_tor());
    bob.set_epicbox_over_tor(false);
    assert!(!bob.epicbox_over_tor() && !bob.relay_through_tor());
    bob.set_epicbox_over_tor(true);
    assert!(bob.relay_through_tor());

    bob.stop_tor();
    events.wait_for(TorEventKind::Stopped).await;
    assert!(bob.epicbox_over_tor() && !bob.relay_through_tor());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_waits_for_a_tor_that_has_not_bootstrapped() {
    let (pair, _network) = tor_pair().await;
    let bob = &pair.bob;
    // No control port is served for this tor, so it stays starting.
    bob.set_tor_timings(quick());
    let events = Events::default();
    bob.start_tor(fake_tor(), None, events.report())
        .await
        .unwrap();
    assert_eq!(bob.tor_status().kind, TorStatusKind::Starting);
    assert!(bob.relay_through_tor(), "never direct while tor starts");
    bob.stop_tor();
    events.wait_for(TorEventKind::Stopped).await;
    assert!(!bob.relay_through_tor());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tor_announced_before_it_starts_holds_the_relay_until_started_or_stopped() {
    let (pair, network) = tor_pair().await;
    let bob = &pair.bob;
    bob.expect_tor().unwrap();
    assert!(bob.relay_through_tor(), "the listener would wait for tor");
    bob.stop_tor();
    assert!(
        bob.relay_through_tor(),
        "the stop of a restart keeps it waiting"
    );
    bob.stop_tor();
    assert!(!bob.relay_through_tor(), "a second stop ends the wait");

    bob.expect_tor().unwrap();
    let (events, _) = start_tor(&network, bob, pair.dirs[1].path()).await;
    assert!(bob.relay_through_tor());
    // A restart: announced, stopped, started again, with the relay waiting throughout.
    bob.expect_tor().unwrap();
    bob.stop_tor();
    events.wait_for(TorEventKind::Stopped).await;
    assert!(bob.relay_through_tor());
    let (events, _) = start_tor(&network, bob, pair.dirs[1].path()).await;
    bob.stop_tor();
    events.wait_for(TorEventKind::Stopped).await;
    assert!(
        !bob.relay_through_tor(),
        "a stop without an announcement leads back"
    );

    bob.expect_tor().unwrap();
    bob.lock();
    assert!(!bob.relay_through_tor(), "lock ends the wait");
    assert_eq!(kind(bob.expect_tor()), WalletErrorKind::Locked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn onion_routes_replace_the_built_in_table_only_when_every_one_is_valid() {
    use crate::api::tor::OnionRoute;
    use lepic_epicbox::tunnel::DialTarget;
    use lepic_epicbox::{Domain, RelayEndpoint, Security};

    let (pair, _network) = tor_pair().await;
    let bob = &pair.bob;
    let endpoint =
        |host: &str| RelayEndpoint::new(Domain::parse(host).unwrap(), None, Security::Tls);
    let built_in = "j2xf5rizkow5jtrdf6edotk5qam4kohavip23dqeuih5bq4yqisbz5ad.onion";
    assert_eq!(
        bob.onion_routes.route(&endpoint("flooepicbox.btlabs.uk")),
        Some(DialTarget {
            host: built_in.to_owned(),
            port: 443
        })
    );

    let onion = lepic_tor::OnionAddress::from_public_key(&[3; 32]).host();
    let route = |host: &str, onion: &str, port: u16| OnionRoute {
        host: host.to_owned(),
        port,
        onion: onion.to_owned(),
        onion_port: 443,
    };
    for bad in [
        vec![
            route("node.btlabs.uk", &onion, 443),
            route("bad host!", &onion, 443),
        ],
        vec![route("node.btlabs.uk", "notanonion.onion", 443)],
        vec![route("node.btlabs.uk", &onion, 0)],
        vec![route("node.btlabs.uk", &onion, 443); 257],
    ] {
        assert_eq!(
            kind(bob.set_onion_routes(bad)),
            WalletErrorKind::InvalidArgument
        );
    }
    assert!(
        bob.onion_routes
            .route(&endpoint("flooepicbox.btlabs.uk"))
            .is_some(),
        "a refused list changes nothing"
    );

    let upper = onion.to_ascii_uppercase().replace(".ONION", ".onion");
    bob.set_onion_routes(vec![route("node.btlabs.uk", &upper, 443)])
        .unwrap();
    assert_eq!(
        bob.onion_routes.route(&endpoint("node.btlabs.uk")),
        Some(DialTarget {
            host: onion.clone(),
            port: 443
        })
    );
    assert_eq!(
        bob.onion_routes.route(&endpoint("flooepicbox.btlabs.uk")),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_right_after_a_stop_waits_for_the_stopped_tor_to_be_down() {
    let (pair, network) = tor_pair().await;
    let (first, _) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    let onion = pair.bob.onion_address().unwrap();
    // What the next fake tor copies; the running one copied its own already.
    network.prepare(pair.dirs[1].path(), &onion).await;

    pair.bob.stop_tor();
    let second = Events::default();
    pair.bob
        .start_tor(fake_tor(), None, second.report())
        .await
        .unwrap();

    assert!(
        first.find(TorEventKind::Stopped).is_some(),
        "{:?}",
        first.kinds()
    );
    let ready = second.wait_for(TorEventKind::Ready).await;
    assert_eq!(ready.onion, Some(onion));
    assert!(
        second.find(TorEventKind::Failed).is_none(),
        "{:?}",
        second.kinds()
    );
    assert_eq!(pair.bob.tor_status().kind, TorStatusKind::Ready);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tor_ending_after_it_bootstrapped_is_reported_and_frees_the_slot() {
    let (pair, network) = tor_pair().await;
    let (events, _) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    let onion = pair.bob.onion_address().unwrap();
    let port = network.listener_port(&onion).unwrap();

    // The fake tor exits as tor would on its own.
    std::fs::write(pair.dirs[1].path().join("stop-now"), b"").unwrap();

    events.wait_for(TorEventKind::Stopped).await;
    let kinds = events.kinds();
    let failed = events.find(TorEventKind::Failed).unwrap();
    assert_eq!(failed.failure, Some(TorFailureKind::Stopped));
    assert_eq!(
        kinds[kinds.len() - 2..],
        [TorEventKind::Failed, TorEventKind::Stopped]
    );
    assert!(eventually(|| pair.bob.tor_status().kind == TorStatusKind::Off).await);
    std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    assert!(
        pair.bob.relay_through_tor(),
        "the relay waits for tor to be started again, never going directly"
    );

    start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    pair.bob.stop_tor();
    assert!(!pair.bob.relay_through_tor(), "stopping tor leads back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_wallet_stops_its_tor() {
    let (pair, network) = tor_pair().await;
    let (events, _) = start_tor(&network, &pair.bob, pair.dirs[1].path()).await;

    drop(crate::api::wallet::EpicWallet::of_session(Arc::clone(
        &pair.bob,
    )));

    events.wait_for(TorEventKind::Stopped).await;
    assert_eq!(pair.bob.tor_status().kind, TorStatusKind::Off);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_onion_answers_more_senders_at_once_than_one_address_may_hold() {
    let (pair, network) = tor_pair().await;
    start_tor(&network, &pair.bob, pair.dirs[1].path()).await;
    start_tor(&network, &pair.alice, pair.dirs[0].path()).await;
    let bob_onion = pair.bob.onion_address().unwrap();
    let port = network.listener_port(&bob_onion).unwrap();
    // Tor connects every sender from 127.0.0.1: these stand for other senders mid-request.
    let mut held = Vec::new();
    for _ in 0..=lepic_tor::MAX_STREAMS_PER_CIRCUIT {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"POST /v2/foreign HTTP/1.1\r\n")
            .await
            .unwrap();
        held.push(stream);
    }
    // Accepted in order, so the held connections count before the send's.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let sent = pair
        .alice
        .send_tor(EPIC, 1, &bob_onion, None, None)
        .await
        .unwrap();

    assert!(sent.posted);
    drop(held);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_the_wallet_cannot_pay_reports_no_sending() {
    let (pair, network) = tor_pair().await;
    let (events, _) = start_tor(&network, &pair.alice, pair.dirs[0].path()).await;
    let bob_onion = pair.bob.onion_address().unwrap();

    let refused = pair
        .alice
        .send_tor(1000 * EPIC, 1, &bob_onion, None, None)
        .await;

    assert_eq!(kind(refused), WalletErrorKind::NotEnoughFunds);
    assert!(
        events.find(TorEventKind::Sending).is_none(),
        "{:?}",
        events.kinds()
    );
    assert!(sends(&pair.alice).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_tor_binary_is_reported_and_ends_the_stream() {
    let pair = funded_pair().await;
    let events = Events::default();
    let missing = pair.dirs[1].path().join("no-tor-here");

    pair.bob
        .start_tor(
            missing.to_string_lossy().into_owned(),
            None,
            events.report(),
        )
        .await
        .unwrap();

    events.wait_for(TorEventKind::Stopped).await;
    let failed = events.find(TorEventKind::Failed).unwrap();
    assert_eq!(failed.failure, Some(TorFailureKind::Missing));
    assert_eq!(events.kinds().last(), Some(&TorEventKind::Stopped));
    assert!(eventually(|| pair.bob.tor_status().kind == TorStatusKind::Off).await);
}

/// `testdata/vectors/keys/address_keys_seed32.json`: the onion `epic-wallet` derives from the
/// payment-proof key of the vector's seed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_onion_address_is_the_payment_proof_address_in_onion_form() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/keys/address_keys_seed32.json");
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let case = &vector["expected"]["cases"][0];
    assert_eq!(case["key_bip32_path"], "m/0/1/0");
    let seed = unhex(vector["inputs"]["seed"].as_str().unwrap());
    let phrase = lepic_keychain::Seed::from_entropy(&seed)
        .unwrap()
        .to_mnemonic()
        .unwrap();
    let chain = crate::api::testing::MockChain::new(1).unwrap();
    let runtime = chain.runtime(LogLevel::Warn).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = WalletConfig {
        data_dir: dir.path().to_string_lossy().into_owned(),
        chain: Chain::Mainnet,
        node_url: "http://127.0.0.1:1".to_owned(),
        node_api_secret: None,
        epicbox_domain: String::new(),
        epicbox_port: 443,
    };
    let secret = crate::node::NodeSecret::take(&mut config);
    let session = Session::new(
        &runtime.inner,
        &config,
        &secret,
        AppSecretStore::in_memory(),
    )
    .await
    .unwrap();
    session
        .create(
            SeedOrigin::Phrase(Zeroizing::new(phrase.to_string())),
            password(),
        )
        .await
        .unwrap();

    let onion = session.onion_address().unwrap();

    assert_eq!(
        onion,
        format!("{}.onion", case["payment_proof_onion_v3"].as_str().unwrap())
    );
    let public_key: [u8; 32] = unhex(case["payment_proof_public_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert_eq!(onion, lepic_tor::onion_address(&public_key));
}

/// Opt-in: two wallets on the scripted chain, each with a real tor, pay each other over the
/// Tor network. Needs the network and a tor binary:
///
/// ```text
/// LEPIC_LIVE_TESTS=1 LEPIC_TOR_BINARY=/path/to/tor LEPIC_TOR_LIB_DIR=/path/to/libs \
///     cargo test -p lepic-ffi --lib tests::tor::live -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs LEPIC_LIVE_TESTS=1, LEPIC_TOR_BINARY and the network"]
async fn live_a_payment_over_the_tor_network_is_finalized_and_posted() {
    if std::env::var("LEPIC_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: LEPIC_LIVE_TESTS is not 1");
        return;
    }
    let binary = std::env::var("LEPIC_TOR_BINARY").unwrap();
    let lib_dir = std::env::var("LEPIC_TOR_LIB_DIR").ok();
    let pair = funded_pair().await;
    let start = |session: Arc<Session>| {
        let (binary, lib_dir) = (binary.clone(), lib_dir.clone());
        async move {
            let events = Events::default();
            session
                .start_tor(binary, lib_dir, events.report())
                .await
                .unwrap();
            events
        }
    };
    let started = std::time::Instant::now();
    let bob_events = start(Arc::clone(&pair.bob)).await;
    let wait = |events: Events, kind: TorEventKind| async move {
        tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                if let Some(event) = events.find(kind) {
                    return event;
                }
                if let Some(failed) = events.find(TorEventKind::Failed) {
                    panic!("tor failed: {:?}", failed.failure);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap()
    };
    let ready = wait(bob_events.clone(), TorEventKind::Ready).await;
    eprintln!(
        "bob's onion published after {:.1} s",
        started.elapsed().as_secs_f32()
    );
    assert_eq!(ready.onion, Some(pair.bob.onion_address().unwrap()));
    let alice_events = start(Arc::clone(&pair.alice)).await;
    wait(alice_events, TorEventKind::Bootstrapped).await;

    let sending = std::time::Instant::now();
    let onion = ready.onion.unwrap();
    // The descriptor reaches every directory a client may ask only some seconds after the
    // first upload, so the first sends may find no onion yet.
    let mut posted = match pair.alice.send_tor(EPIC, 1, &onion, None, None).await {
        Ok(sent) => Ok(sent.posted),
        Err(error) => Err(error),
    };
    for _ in 0..6 {
        let Err(error) = &posted else { break };
        assert_eq!(error.kind, WalletErrorKind::OnionUnreachable, "{error}");
        eprintln!("not reached yet: {}", error.message);
        tokio::time::sleep(Duration::from_secs(10)).await;
        let tx_id = sends(&pair.alice).await[0].tx_id;
        posted = pair
            .alice
            .resend_tor(tx_id, &onion)
            .await
            .map(|resent| resent.posted);
    }
    eprintln!("sent over tor in {:.1} s", sending.elapsed().as_secs_f32());

    assert!(posted.unwrap());
    assert_eq!(pair.chain.pushed_count(), 1);
    wait(bob_events.clone(), TorEventKind::Received).await;
    pair.alice.lock();
    pair.bob.lock();
    wait(bob_events, TorEventKind::Stopped).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_goes_through_tor_while_it_runs_and_the_setting_is_on() {
    let (pair, network) = tor_pair().await;
    let bob = &pair.bob;
    assert!(bob.node_over_tor(), "on by default");
    assert!(!bob.node_through_tor(), "tor is off");

    bob.expect_tor().unwrap();
    assert!(bob.node_through_tor(), "never direct while tor is awaited");
    bob.set_node_over_tor(false);
    assert!(!bob.node_over_tor() && !bob.node_through_tor());
    bob.set_node_over_tor(true);
    assert!(bob.node_through_tor());
    bob.stop_tor();
    bob.stop_tor();
    assert!(!bob.node_through_tor(), "a stop leads back to direct");

    let (events, _) = start_tor(&network, bob, pair.dirs[1].path()).await;
    assert!(bob.node_through_tor() && bob.relay_through_tor());
    bob.set_epicbox_over_tor(false);
    assert!(
        bob.node_through_tor(),
        "the settings of the node and the relay are separate"
    );
    bob.set_node_over_tor(false);
    assert!(!bob.node_through_tor());
    bob.set_node_over_tor(true);

    bob.stop_tor();
    events.wait_for(TorEventKind::Stopped).await;
    assert!(bob.node_over_tor() && !bob.node_through_tor());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_status_and_the_events_carry_the_socks_port_once_tor_has_bootstrapped() {
    let (pair, network) = tor_pair().await;
    let bob = &pair.bob;
    assert_eq!(bob.tor_status().socks_port, None);
    let socks_port = network.socks.port();

    let (events, _) = start_tor(&network, bob, pair.dirs[1].path()).await;
    let status = bob.tor_status();
    assert_eq!(status.kind, TorStatusKind::Ready);
    assert_eq!(status.socks_port, Some(socks_port));
    for kind in [
        TorEventKind::Bootstrapped,
        TorEventKind::Publishing,
        TorEventKind::Ready,
    ] {
        assert_eq!(
            events.wait_for(kind).await.socks_port,
            Some(socks_port),
            "{kind:?}"
        );
    }

    bob.stop_tor();
    events.wait_for(TorEventKind::Stopped).await;
    assert_eq!(bob.tor_status().socks_port, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wallet_that_expected_tor_waits_for_it_from_its_next_open_until_tor_is_stopped() {
    let fixture = super::Fixture::new();
    let store = AppSecretStore::in_memory();
    let session = || async {
        let mut config = fixture.config();
        let secret = crate::node::NodeSecret::take(&mut config);
        Session::new(&fixture.runtime.inner, &config, &secret, store.clone())
            .await
            .unwrap()
    };
    let first = session().await;
    assert!(!first.relay_through_tor() && !first.node_through_tor());
    first
        .create(SeedOrigin::Generate, password())
        .await
        .unwrap();
    first.expect_tor().unwrap();
    first.lock();
    drop(first);

    let second = session().await;
    assert!(
        second.relay_through_tor() && second.node_through_tor(),
        "waits for tor before the app says anything"
    );
    second.open(password()).await.unwrap();
    assert!(second.relay_through_tor() && second.node_through_tor());
    second.set_epicbox_over_tor(false);
    assert!(!second.relay_through_tor(), "the setting off goes directly");
    second.set_epicbox_over_tor(true);
    assert!(second.relay_through_tor());
    second.stop_tor();
    assert!(!second.relay_through_tor() && !second.node_through_tor());
    second.lock();
    drop(second);

    let third = session().await;
    assert!(
        !third.relay_through_tor() && !third.node_through_tor(),
        "a stopped tor is not waited for"
    );
}
