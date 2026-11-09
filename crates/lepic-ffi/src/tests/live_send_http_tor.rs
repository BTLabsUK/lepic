// SPDX-License-Identifier: Apache-2.0
//! A floonet payment over HTTP from a session that wants Tor, to a wallet only Tor can reach.
//! Ignored and opt-in (`docs/rules.md`):
//!
//! ```text
//! LEPIC_LIVE_TESTS=1 LEPIC_TEST_NODE_URL=https://<floonet node> \
//! LEPIC_TOR_BINARY=<tor> [LEPIC_TOR_LIB_DIR=<dir>] LEPIC_TEST_LISTEN_PORT=<port> \
//! LEPIC_TEST_WALLET_URL=http://<onion>[:port] \
//! cargo test -p lepic-ffi --lib tests::live_send_http_tor -- --ignored --nocapture
//! ```
//!
//! The session opens with `tor_wanted`, so its node, its sends and everything else wait for
//! its tor. It takes funds on a loopback HTTP listener at `LEPIC_TEST_LISTEN_PORT` (pay it
//! from another floonet wallet when it says so), then pays 1 EPIC to `LEPIC_TEST_WALLET_URL`
//! with `send_http`.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lepic_keychain::KdfParams;
use zeroize::Zeroizing;

use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::http::{HttpCoinbase, HttpExposure, HttpListenerEvent};
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::tor::{TorEvent, TorEventKind};
use crate::api::types::{Chain, WalletConfig};
use crate::node::{NodeFactory, NodeSecret};
use crate::pin::PinPolicy;
use crate::session::{SeedOrigin, Session};

const EPIC: u64 = 100_000_000;

#[test]
#[ignore = "opt-in live send over HTTP through tor on floonet"]
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
fn live_send_http_through_tor() {
    assert_eq!(
        std::env::var("LEPIC_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set LEPIC_LIVE_TESTS=1"
    );
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name}"));
    let node_url = env("LEPIC_TEST_NODE_URL");
    let binary = env("LEPIC_TOR_BINARY");
    let lib_dir = std::env::var("LEPIC_TOR_LIB_DIR").ok();
    let port: u16 = env("LEPIC_TEST_LISTEN_PORT").parse().unwrap();
    let url = env("LEPIC_TEST_WALLET_URL");

    let runtime = LepicRuntime::start(
        LogLevel::Warn,
        NodeFactory::Http,
        KdfParams::DEFAULT,
        PinPolicy::DEFAULT,
    )
    .unwrap();
    let rt = runtime.inner.boundary.handle.clone();
    let data = tempfile::tempdir().unwrap();
    let mut config = WalletConfig {
        policy: Default::default(),
        data_dir: data.path().to_string_lossy().into_owned(),
        chain: Chain::Floonet,
        node_url,
        node_api_secret: None,
        epicbox_domain: "localhost".to_owned(),
        epicbox_port: 443,
        onion_routes: Vec::new(),
        tuning: crate::tuning::shipped(),
        offline: false,
        tor_wanted: true,
        host_features: 0,
        profile: 0,
        domain: None,
    };
    let secret = NodeSecret::take(&mut config);

    rt.block_on(async {
        let session = Arc::new(
            Session::new(
                &runtime.inner,
                &config,
                &secret,
                AppSecretStore::in_memory(),
            )
            .await
            .unwrap(),
        );
        session
            .create(SeedOrigin::Generate, Zeroizing::new("password".to_owned()))
            .await
            .unwrap();

        let tor_events: Arc<Mutex<Vec<TorEvent>>> = Arc::default();
        let seen = Arc::clone(&tor_events);
        let started = Instant::now();
        session
            .start_tor(
                binary,
                lib_dir,
                false,
                Arc::new(move |event| seen.lock().unwrap().push(event)),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                let events = tor_events.lock().unwrap().clone();
                if events.iter().any(|e| e.kind == TorEventKind::Bootstrapped) {
                    return;
                }
                if let Some(failed) = events.iter().find(|e| e.kind == TorEventKind::Failed) {
                    panic!("tor failed: {:?}", failed.failure);
                }
                drop(events);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap();
        eprintln!(
            "tor bootstrapped in {:.1} s",
            started.elapsed().as_secs_f32()
        );

        session
            .start_http_listener(
                HttpExposure::LocalOnly,
                port,
                HttpCoinbase::Off,
                Arc::new(|event: HttpListenerEvent| eprintln!("listener: {:?}", event.kind)),
            )
            .await
            .unwrap();
        eprintln!("FUND http://127.0.0.1:{port} with at least 2 EPIC");

        let funding = Instant::now();
        loop {
            match session.refresh().await {
                Ok(summary) if summary.spendable >= 2 * EPIC => {
                    eprintln!(
                        "spendable {} after {:.0} s",
                        summary.spendable,
                        funding.elapsed().as_secs_f32()
                    );
                    break;
                }
                Ok(summary) => eprintln!(
                    "height {} spendable {} awaiting {}",
                    summary.last_confirmed_height, summary.spendable, summary.awaiting_confirmation
                ),
                Err(error) => eprintln!("refresh: {error}"),
            }
            assert!(
                funding.elapsed() < Duration::from_secs(45 * 60),
                "not funded"
            );
            tokio::time::sleep(Duration::from_secs(30)).await;
        }

        let sending = Instant::now();
        // An onion just published may not be found by every directory yet.
        let mut sent = session
            .send_http_with(EPIC, 1, &url, true, None, None, false)
            .await
            .map(|sent| (sent.tx_id, sent.slate_id, sent.posted));
        for _ in 0..6 {
            let Err(error) = &sent else { break };
            assert_eq!(error.kind, WalletErrorKind::TransportFailed, "{error}");
            eprintln!("not reached yet: {}", error.message);
            tokio::time::sleep(Duration::from_secs(15)).await;
            let tx_id = super::http::sends(&session).await[0].tx_id;
            sent = session
                .resend_http(tx_id, &url, true, false)
                .await
                .map(|resent| (resent.tx_id, resent.slate_id, resent.posted));
        }
        let (tx_id, slate_id, posted) = sent.unwrap();
        eprintln!(
            "sent tx {tx_id} slate {slate_id} over tor in {:.1} s, posted {posted}",
            sending.elapsed().as_secs_f32()
        );
        assert!(posted);
        session.lock();
    });
}

/// Opt-in: a session that wants Tor and never gets one (its tor files missing) reaches nothing,
/// the public node included. `LEPIC_LIVE_TESTS=1 LEPIC_TEST_NODE_URL=https://<floonet node>`.
#[test]
#[ignore = "opt-in live check that a session waiting for tor stays off the network"]
fn live_tor_wanted_without_tor_reaches_nothing() {
    assert_eq!(
        std::env::var("LEPIC_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set LEPIC_LIVE_TESTS=1"
    );
    let runtime = LepicRuntime::start(
        LogLevel::Warn,
        NodeFactory::Http,
        KdfParams::DEFAULT,
        PinPolicy::DEFAULT,
    )
    .unwrap();
    let rt = runtime.inner.boundary.handle.clone();
    let data = tempfile::tempdir().unwrap();
    let mut config = WalletConfig {
        policy: Default::default(),
        data_dir: data.path().to_string_lossy().into_owned(),
        chain: Chain::Floonet,
        node_url: std::env::var("LEPIC_TEST_NODE_URL").unwrap(),
        node_api_secret: None,
        epicbox_domain: "localhost".to_owned(),
        epicbox_port: 443,
        onion_routes: Vec::new(),
        tuning: crate::tuning::shipped(),
        offline: false,
        tor_wanted: true,
        host_features: 0,
        profile: 0,
        domain: None,
    };
    let secret = NodeSecret::take(&mut config);
    rt.block_on(async {
        let session = Session::new(
            &runtime.inner,
            &config,
            &secret,
            AppSecretStore::in_memory(),
        )
        .await
        .unwrap();
        session
            .create(SeedOrigin::Generate, Zeroizing::new("password".to_owned()))
            .await
            .unwrap();
        let refreshed = tokio::time::timeout(Duration::from_secs(20), session.refresh()).await;
        eprintln!(
            "refresh after 20 s: {:?}",
            refreshed
                .as_ref()
                .map(|r| r.as_ref().map(|_| ()).map_err(|e| e.kind))
        );
        assert!(
            !matches!(refreshed, Ok(Ok(_))),
            "the node answered without tor"
        );
        session.lock();
    });
}
