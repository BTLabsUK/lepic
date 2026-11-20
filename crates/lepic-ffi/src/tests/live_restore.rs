// SPDX-License-Identifier: Apache-2.0
//! A restore from a block height on a real runtime against a public floonet node: the scan from
//! that height leaves the restore scan pending, a scan to the tip from 100 blocks before the last
//! scan does not end it, and a scan without a start height begins at genesis and ends it.
//! Ignored and opt-in (`docs/rules.md`), with a throwaway seed:
//!
//! ```text
//! LEPIC_LIVE_TESTS=1 LEPIC_TEST_NODE_URL=https://<floonet node> \
//! cargo test -p lepic-ffi live_restore -- --ignored --nocapture
//! ```

use std::sync::{Arc, Mutex};
use std::time::Instant;

use lepic_keychain::KdfParams;
use lepic_primitives::amount::Height;
use zeroize::Zeroizing;

use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{Chain, ScanProgress, WalletConfig};
use crate::node::{NodeFactory, NodeSecret};
use crate::pin::PinPolicy;
use crate::session::{self, SeedOrigin, Session};

fn password() -> Zeroizing<String> {
    Zeroizing::new("password".to_owned())
}

async fn session_in(runtime: &LepicRuntime, config: &WalletConfig) -> Session {
    let mut config = config.clone();
    let secret = NodeSecret::take(&mut config);
    Session::new(
        &runtime.inner,
        &config,
        &secret,
        AppSecretStore::in_memory(),
    )
    .await
    .unwrap()
}

/// Scans from `start` and returns the last event.
async fn scan(session: &Session, start: Option<u64>) -> ScanProgress {
    let events = Arc::new(Mutex::new(Vec::new()));
    let report = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let t0 = Instant::now();
    session.scan(start, false, report).await.unwrap();
    let last = events.lock().unwrap().last().cloned().unwrap();
    println!(
        "scan(start_height: {start:?}) took {:.1} s: {:?}",
        t0.elapsed().as_secs_f64(),
        last.result
    );
    last
}

async fn invoice_refusal(session: &Session) -> Option<WalletErrorKind> {
    session
        .issue_invoice_slate(1, None)
        .await
        .err()
        .map(|error| error.kind)
}

#[test]
#[ignore = "opt-in live restore against a public floonet node"]
fn live_restore() {
    assert_eq!(
        std::env::var("LEPIC_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set LEPIC_LIVE_TESTS=1"
    );
    let node_url = std::env::var("LEPIC_TEST_NODE_URL").expect("LEPIC_TEST_NODE_URL");
    let runtime = LepicRuntime::start(
        LogLevel::Warn,
        NodeFactory::Http,
        KdfParams::DEFAULT,
        PinPolicy::DEFAULT,
    )
    .unwrap();
    let rt = runtime.inner.boundary.handle.clone();
    let created_dir = tempfile::tempdir().unwrap();
    let restored_dir = tempfile::tempdir().unwrap();
    let config = |dir: &tempfile::TempDir| WalletConfig {
        policy: Default::default(),
        data_dir: dir.path().to_string_lossy().into_owned(),
        chain: Chain::Floonet,
        node_url: node_url.clone(),
        node_api_secret: None,
        epicbox_domain: String::new(),
        epicbox_port: 443,
        onion_routes: Vec::new(),
        tuning: crate::tuning::shipped(),
        offline: false,
        tor_wanted: false,
        host_features: 0,
        profile: 0,
        domain: None,
    };
    rt.block_on(async {
        // A throwaway seed made here, never anyone's wallet.
        let created = session_in(&runtime, &config(&created_dir)).await;
        created
            .create(SeedOrigin::Generate, password())
            .await
            .unwrap();
        let phrase = created.recovery_phrase(password()).await.unwrap();
        drop(created);

        let restored = session_in(&runtime, &config(&restored_dir)).await;
        restored
            .create(SeedOrigin::Phrase {
                phrase: Zeroizing::new(phrase),
                scan_from: Height::ZERO,
            }, password())
            .await
            .unwrap();
        let mut tip_config = config(&restored_dir);
        let secret = NodeSecret::take(&mut tip_config);
        let tip = session::node_tip(&runtime.inner, &tip_config, &secret, &crate::api::types::NodeRoute { socks: None })
            .await
            .unwrap()
            .height;
        println!("floonet tip {tip}");
        let required = restored.restore_scan_required().unwrap();
        println!("restored: restore_scan_required = {required}");
        assert!(required);

        let start = tip.saturating_sub(50);
        let from_height = scan(&restored, Some(start)).await;
        assert_eq!(from_height.result.unwrap().start_height, start);
        let required = restored.restore_scan_required().unwrap();
        let refusal = invoice_refusal(&restored).await;
        println!("after the scan from {start}: required = {required}, invoice: {refusal:?}");
        assert!(required);
        assert_eq!(refusal, Some(WalletErrorKind::RestoreScanRequired));

        // What a scan without a start did before: from 100 blocks before the last scan.
        let t0 = Instant::now();
        restored.scan_to_tip().await;
        let required = restored.restore_scan_required().unwrap();
        println!(
            "after the earlier binding's scan without a start ({:.1} s): required = {required}",
            t0.elapsed().as_secs_f64()
        );
        assert!(required);

        let without_start = scan(&restored, None).await;
        let result = without_start.result.unwrap();
        let required = restored.restore_scan_required().unwrap();
        let refusal = invoice_refusal(&restored).await;
        println!(
            "after scan(None): start_height = {}, required = {required}, invoice refused: {refusal:?}",
            result.start_height
        );
        assert_eq!(result.start_height, 0);
        assert!(!required);
        assert_eq!(refusal, None);
    });
}
