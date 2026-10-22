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
use lepic_tor::socks::SocksCredentials;
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
            Err(TorSendError::Socks(SocksError::Timeout)) if attempt < 2 => {
                eprintln!(
                    "attempt {attempt} timed out after {:.1} s",
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
