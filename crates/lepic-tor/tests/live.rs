//! Opt-in: a real tor publishes an onion for a throwaway random key, and this wallet reaches it
//! over tor's SOCKS port with `check_version`. Needs the network and a tor binary:
//!
//! ```text
//! LEPIC_LIVE_TESTS=1 LEPIC_TOR_BINARY=/path/to/tor LEPIC_TOR_LIB_DIR=/path/to/libs \
//!     cargo test -p lepic-tor --test live -- --ignored --nocapture
//! ```

// Helpers outside #[test] functions unwrap too; a failure there is a test failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lepic_foreign::{Exposure, ListenSettings, ReceiveHandler, Refusal, listen};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_tor::socks::{SocksCredentials, SocksReply};
use lepic_tor::{
    OnionClient, OnionClientSettings, SendFailure, SocksError, TorProcess, TorSendError,
    TorSettings, TorTransport,
};
use lepic_transport::transport::BoxFuture;

const S1: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000"}"#;

struct RefusesEverything;

impl ReceiveHandler for RefusesEverything {
    fn receive(&self, _slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async { Err(Refusal::Rejected) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs LEPIC_LIVE_TESTS=1, LEPIC_TOR_BINARY and the network"]
async fn publishes_an_onion_and_reaches_it_over_tor() {
    if std::env::var("LEPIC_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: LEPIC_LIVE_TESTS is not 1");
        return;
    }
    let binary = PathBuf::from(std::env::var("LEPIC_TOR_BINARY").unwrap());
    let dir = tempfile::tempdir().unwrap();
    let mut settings = TorSettings::new(binary, dir.path().join("tor"));
    settings.lib_dir = std::env::var_os("LEPIC_TOR_LIB_DIR").map(PathBuf::from);

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let listener = listen(
        ListenSettings::new(Exposure::LocalOnly, 0),
        Arc::new(RefusesEverything),
    )
    .await
    .unwrap();

    let started = Instant::now();
    let tor = TorProcess::start(settings);
    let socks = tor.wait_bootstrapped().await.unwrap();
    eprintln!(
        "bootstrapped after {:.1} s",
        started.elapsed().as_secs_f64()
    );
    let onion = tor
        .publish_onion(&seed, listener.local_addr().port())
        .await
        .unwrap();
    eprintln!(
        "onion published after {:.1} s",
        started.elapsed().as_secs_f64()
    );

    // As TorTransport does: the first circuit to a fresh onion may need a second try.
    let mut client_settings = OnionClientSettings::default();
    if let Ok(seconds) = std::env::var("LEPIC_TOR_CONNECT_SECS") {
        client_settings.connect_timeout = Duration::from_secs(seconds.parse().unwrap());
    }
    let client = OnionClient::new(client_settings);
    let mut attempt = 1;
    let asked = Instant::now();
    let version = loop {
        match client
            .check_version(socks, &onion, &SocksCredentials::random().unwrap())
            .await
        {
            // A descriptor just published may not have reached every directory yet.
            Err(TorSendError::Socks(
                error @ (SocksError::Timeout | SocksError::Refused(SocksReply::OnionNotFound)),
            )) if attempt < 2 => {
                eprintln!(
                    "attempt {attempt} failed after {:.1} s: {error}",
                    asked.elapsed().as_secs_f64()
                );
                attempt += 1;
            }
            other => break other.unwrap(),
        }
    };
    eprintln!(
        "check_version over tor answered after {:.1} s, attempt {attempt} (v3 {}, v2 {})",
        asked.elapsed().as_secs_f64(),
        version.v3,
        version.v2
    );
    assert!(version.v2 && version.v3);

    let transport = TorTransport::new(client);
    let tor = Arc::new(tor);
    transport.attach(tor.clone());
    let sent = Instant::now();
    let error = transport
        .send(
            &onion.to_string(),
            &WireSlate::text(MediaType::JSON, S1.to_owned()),
        )
        .await
        .unwrap_err();
    eprintln!(
        "send over tor reached the wallet and was refused after {:.1} s",
        sent.elapsed().as_secs_f64()
    );
    assert_eq!(error.class(), SendFailure::Refused, "{error:?}");
    transport.detach();
    let tor = Arc::into_inner(tor).unwrap();

    let stopping = Instant::now();
    tor.stop().await;
    eprintln!("stopped in {:.1} s", stopping.elapsed().as_secs_f64());
    listener.shutdown().await;
}

/// `check_version` at `onion` through `tor`, with more tries than [`TorTransport`] makes.
async fn reach(tor: &TorProcess, onion: &lepic_tor::OnionAddress) -> f64 {
    let client = OnionClient::new(OnionClientSettings::default());
    let asked = Instant::now();
    let mut last = None;
    for attempt in 1..=3 {
        let socks = tor.wait_bootstrapped().await.unwrap();
        match client
            .check_version(socks, onion, &SocksCredentials::random().unwrap())
            .await
        {
            Ok(version) => {
                assert!(version.v2 && version.v3);
                return asked.elapsed().as_secs_f64();
            }
            Err(error) => {
                eprintln!("attempt {attempt}: {error:?}");
                last = Some(error);
            }
        }
    }
    panic!("onion not reached: {last:?}");
}

/// Sends `signal` to the tor started with `torrc`.
fn signal_tor(torrc: &std::path::Path, signal: &str) {
    let status = std::process::Command::new("pkill")
        .arg(format!("-{signal}"))
        .arg("-f")
        .arg("--")
        .arg(format!("-f {}", torrc.display()))
        .status()
        .unwrap();
    assert!(status.success(), "no tor runs with {}", torrc.display());
}

/// Opt-in, as above: a tor an earlier run left holds the data directory and the start halts
/// it; then tor is frozen as a phone's app freezer does, for `LEPIC_TOR_PAUSE_SECS` (default
/// 90), thawed and refreshed, and refreshed again as after a network change. The onion
/// answers after each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs LEPIC_LIVE_TESTS=1, LEPIC_TOR_BINARY and the network"]
async fn survives_a_left_tor_a_pause_and_a_network_change() {
    use lepic_tor::process::{TorPaths, build_torrc};
    use std::os::unix::fs::PermissionsExt;

    if std::env::var("LEPIC_LIVE_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: LEPIC_LIVE_TESTS is not 1");
        return;
    }
    let binary = PathBuf::from(std::env::var("LEPIC_TOR_BINARY").unwrap());
    let lib_dir = std::env::var_os("LEPIC_TOR_LIB_DIR").map(PathBuf::from);
    let pause = Duration::from_secs(
        std::env::var("LEPIC_TOR_PAUSE_SECS").map_or(90, |s| s.parse().unwrap()),
    );
    let dir = tempfile::tempdir().unwrap();
    let paths = TorPaths::new(&dir.path().join("tor"));
    for private in [&paths.dir, &paths.data] {
        std::fs::create_dir_all(private).unwrap();
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(&paths.defaults, "").unwrap();
    std::fs::write(
        &paths.torrc,
        build_torrc(&paths, std::process::id()).unwrap(),
    )
    .unwrap();
    let mut left = std::process::Command::new(&binary);
    left.arg("-f")
        .arg(&paths.torrc)
        .arg("--defaults-torrc")
        .arg(&paths.defaults)
        .stdout(std::process::Stdio::null());
    if let Some(lib_dir) = &lib_dir {
        left.env("LD_LIBRARY_PATH", lib_dir);
    }
    let mut left = left.spawn().unwrap();
    let waited = Instant::now();
    while !paths.control_file.exists() {
        assert!(
            waited.elapsed() < Duration::from_secs(30),
            "the left tor did not start"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut settings = TorSettings::new(binary, paths.dir.clone());
    settings.lib_dir = lib_dir;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let listener = listen(
        ListenSettings::new(Exposure::LocalOnly, 0),
        Arc::new(RefusesEverything),
    )
    .await
    .unwrap();
    let started = Instant::now();
    let tor = TorProcess::start(settings);
    tor.wait_bootstrapped().await.unwrap();
    eprintln!(
        "bootstrapped over a left tor after {:.1} s",
        started.elapsed().as_secs_f64()
    );
    assert!(
        left.try_wait().unwrap().is_some(),
        "the left tor was halted"
    );
    let onion = tor
        .publish_onion(&seed, listener.local_addr().port())
        .await
        .unwrap();
    eprintln!("reached the onion in {:.1} s", reach(&tor, &onion).await);

    signal_tor(&paths.torrc, "STOP");
    tokio::time::sleep(pause).await;
    signal_tor(&paths.torrc, "CONT");
    tor.refresh(false).await.unwrap();
    eprintln!(
        "reached the onion {} s after a pause, in {:.1} s",
        pause.as_secs(),
        reach(&tor, &onion).await
    );

    let before = tor.wait_bootstrapped().await.unwrap();
    tor.refresh(true).await.unwrap();
    let after = tor.wait_bootstrapped().await.unwrap();
    eprintln!("socks {before} moved to {after} after a network change");
    eprintln!(
        "reached the onion after a network change, in {:.1} s",
        reach(&tor, &onion).await
    );
    tor.stop().await;
    listener.shutdown().await;
}
