//! Scans through the binding: the result the last event carries, the `delete_unconfirmed`
//! repair, cancelling a scan that waits on the node, and the start of a scan while a restore
//! scan is pending.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroizing;

use super::eventually;
use super::http::{EPIC, funded_pair, password};
use crate::api::error::WalletErrorKind;
use crate::api::secret_store::AppSecretStore;
use crate::api::types::{Chain, ScanProgress, ScanResult, TxStatus, WalletConfig};
use crate::session::{SeedOrigin, Session};

#[derive(Clone, Default)]
struct Progress(Arc<Mutex<Vec<ScanProgress>>>);

impl Progress {
    fn report(&self) -> impl Fn(ScanProgress) + use<> {
        let events = Arc::clone(&self.0);
        move |event| events.lock().unwrap().push(event)
    }

    fn last(&self) -> ScanProgress {
        self.0.lock().unwrap().last().cloned().unwrap()
    }
}

async fn scan(session: &Session, delete_unconfirmed: bool) -> ScanResult {
    scan_from(session, None, delete_unconfirmed)
        .await
        .result
        .unwrap()
}

/// The last event of a completed scan from `start_height`.
async fn scan_from(
    session: &Session,
    start_height: Option<u64>,
    delete_unconfirmed: bool,
) -> ScanProgress {
    let progress = Progress::default();
    session
        .scan(start_height, delete_unconfirmed, progress.report())
        .await
        .unwrap();
    let last = progress.last();
    assert!(last.finished);
    last
}

/// A wallet restored from `session`'s phrase into a new directory, on the pair's chain.
async fn restored_from(
    pair: &super::http::Pair,
    session: &Session,
) -> (tempfile::TempDir, Session) {
    let phrase = session.recovery_phrase(password()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = WalletConfig {
        data_dir: dir.path().to_string_lossy().into_owned(),
        chain: Chain::Floonet,
        node_url: "http://127.0.0.1:1".to_owned(),
        node_api_secret: None,
        epicbox_domain: String::new(),
        epicbox_port: 443,
    };
    let secret = crate::node::NodeSecret::take(&mut config);
    let restored = Session::new(
        &pair.runtime().inner,
        &config,
        &secret,
        AppSecretStore::in_memory(),
    )
    .await
    .unwrap();
    restored
        .create(SeedOrigin::Phrase(Zeroizing::new(phrase)), password())
        .await
        .unwrap();
    (dir, restored)
}

/// The fix for a restore from a block height: that scan finds the outputs above it, and the
/// next scan without a start goes back to genesis, not to shortly before the last scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_scanned_from_a_height_refuses_outputs_until_a_scan_without_one_completes() {
    let pair = funded_pair().await;
    pair.chain.set_height(300);
    let (_dir, bob) = restored_from(&pair, &pair.bob).await;
    assert!(bob.restore_scan_required().unwrap());

    let from_height = scan_from(&bob, Some(250), false).await;
    assert_eq!(from_height.result.unwrap().start_height, 250);
    assert!(bob.restore_scan_required().unwrap());
    let slate = pair.alice.create_send_slate(EPIC, 1, None).await.unwrap();
    let refused = bob.receive_slate(slate.json.clone()).await;
    assert_eq!(
        refused.unwrap_err().kind,
        WalletErrorKind::RestoreScanRequired
    );

    let result = scan(&bob, false).await;

    assert_eq!(
        result.start_height, 0,
        "a pending restore scan starts at genesis"
    );
    assert!(!bob.restore_scan_required().unwrap());
    assert!(bob.receive_slate(slate.json).await.is_ok());
    let next = scan(&bob, false).await;
    assert_eq!(
        next.start_height, 200,
        "then 100 blocks before the last scan again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scan_from_height_zero_also_ends_the_restore_scan() {
    let pair = funded_pair().await;
    pair.chain.set_height(300);
    let (_dir, alice) = restored_from(&pair, &pair.alice).await;
    scan_from(&alice, Some(250), false).await;

    let last = scan_from(&alice, Some(0), false).await;

    let result = last.result.unwrap();
    assert_eq!((result.start_height, result.found), (0, 1));
    assert!(!alice.restore_scan_required().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_restore_scan_is_finished_by_the_next_scan_without_a_start() {
    let pair = funded_pair().await;
    pair.chain.set_height(300);
    let (_dir, alice) = restored_from(&pair, &pair.alice).await;
    let alice = Arc::new(alice);
    pair.chain.set_node_stalled(true);
    let running = {
        let alice = Arc::clone(&alice);
        let report = Progress::default().report();
        tokio::spawn(async move { alice.scan(None, false, report).await })
    };
    assert!(eventually(|| pair.chain.stalled_node_calls() > 0).await);
    alice.cancel_scan();
    let ended = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ended.unwrap_err().kind, WalletErrorKind::Cancelled);
    pair.chain.set_node_stalled(false);
    assert!(alice.restore_scan_required().unwrap());

    let result = scan(&alice, false).await;

    assert_eq!((result.start_height, result.found), (0, 1));
    assert!(!alice.restore_scan_required().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_above_the_tip_is_reported_as_skipped_and_the_restore_scan_stays_pending() {
    let pair = funded_pair().await;
    let (_dir, alice) = restored_from(&pair, &pair.alice).await;

    let last = scan_from(&alice, Some(1_000), false).await;

    assert!(last.message.contains("skipped"), "{}", last.message);
    let result = last.result.unwrap();
    assert!(result.start_height > result.end_height);
    assert_eq!(result.found, 0);
    assert!(alice.restore_scan_required().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_scan_reports_the_outputs_it_restored() {
    let pair = funded_pair().await;
    let phrase = pair.alice.recovery_phrase(password()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut config = WalletConfig {
        data_dir: dir.path().to_string_lossy().into_owned(),
        chain: Chain::Floonet,
        node_url: "http://127.0.0.1:1".to_owned(),
        node_api_secret: None,
        epicbox_domain: String::new(),
        epicbox_port: 443,
    };
    let secret = crate::node::NodeSecret::take(&mut config);
    let runtime = pair
        .chain
        .runtime(crate::api::diagnostics::LogLevel::Warn)
        .unwrap();
    let restored = Session::new(
        &runtime.inner,
        &config,
        &secret,
        AppSecretStore::in_memory(),
    )
    .await
    .unwrap();
    restored
        .create(SeedOrigin::Phrase(Zeroizing::new(phrase)), password())
        .await
        .unwrap();

    let result = scan(&restored, false).await;

    assert_eq!(
        result,
        ScanResult {
            start_height: 0,
            end_height: 20,
            resumed: false,
            found: 1,
            restored: 1,
            revived: 0,
            unlocked: 0,
            deleted: 0,
        }
    );
    let again = scan(&restored, false).await;
    assert_eq!((again.found, again.restored), (1, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_unconfirmed_cancels_a_waiting_send_and_frees_its_inputs() {
    let pair = funded_pair().await;
    let alice = &pair.alice;
    let slate = alice.create_send_slate(EPIC, 1, None).await.unwrap();
    assert_eq!(alice.stored_summary().unwrap().spendable, 0);

    let plain = scan(alice, false).await;
    assert_eq!((plain.unlocked, plain.deleted), (0, 0));
    let send = alice.transaction(slate.tx_id).await.unwrap();
    assert_eq!(send.status, TxStatus::Sent);

    let repair = scan(alice, true).await;

    assert_eq!((repair.found, repair.unlocked, repair.deleted), (1, 1, 1));
    let send = alice.transaction(slate.tx_id).await.unwrap();
    assert_eq!(send.status, TxStatus::Cancelled);
    let summary = alice.stored_summary().unwrap();
    assert_eq!((summary.spendable, summary.locked), (10 * EPIC, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_scan_ends_a_scan_waiting_on_the_node_and_the_next_one_completes() {
    let pair = funded_pair().await;
    let alice = Arc::clone(&pair.alice);
    let before = alice.stored_summary().unwrap();
    pair.chain.set_node_stalled(true);
    let progress = Progress::default();
    let running = {
        let alice = Arc::clone(&alice);
        let report = progress.report();
        tokio::spawn(async move { alice.scan(None, false, report).await })
    };
    assert!(eventually(|| pair.chain.stalled_node_calls() > 0).await);

    alice.cancel_scan();

    let ended = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .expect("a cancelled scan ends within three seconds")
        .unwrap();
    assert_eq!(ended.unwrap_err().kind, WalletErrorKind::Cancelled);
    assert!(
        progress
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|event| !event.finished)
    );
    pair.chain.set_node_stalled(false);
    assert_eq!(alice.stored_summary().unwrap(), before);
    let result = scan(&alice, false).await;
    assert_eq!(result.found, 1);
    assert_eq!(alice.refresh().await.unwrap().spendable, 10 * EPIC);
}

/// Alice's send of 1 EPIC waits for an answer, its input locked, on a chain grown 280 blocks
/// past it, more than a scan reaches back.
async fn send_on_a_long_chain() -> (super::http::Pair, u32) {
    let pair = funded_pair().await;
    let slate = pair.alice.create_send_slate(EPIC, 1, None).await.unwrap();
    pair.chain.set_height(300);
    scan(&pair.alice, false).await;
    (pair, slate.tx_id)
}

fn locked(session: &Session) -> Vec<u64> {
    session
        .outputs()
        .unwrap()
        .into_iter()
        .filter(|output| output.status == crate::api::types::OutputStatus::Locked)
        .map(|output| output.value)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_scan_of_a_long_chain_leaves_a_waiting_send_alone() {
    let (pair, tx_id) = send_on_a_long_chain().await;

    let result = scan(&pair.alice, false).await;

    assert_eq!(result.start_height, 200, "100 blocks before the last scan");
    assert_eq!(locked(&pair.alice), [10 * EPIC]);
    let send = pair.alice.transaction(tx_id).await.unwrap();
    assert_eq!(send.status, TxStatus::Sent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_of_a_long_chain_frees_the_inputs_of_the_send_it_cancels() {
    let (pair, tx_id) = send_on_a_long_chain().await;

    let result = scan(&pair.alice, true).await;

    assert_eq!(result.start_height, 0, "a repair scans the whole chain");
    assert_eq!((result.unlocked, result.deleted), (1, 1));
    assert!(locked(&pair.alice).is_empty());
    let send = pair.alice.transaction(tx_id).await.unwrap();
    assert_eq!(send.status, TxStatus::Cancelled);
    let summary = pair.alice.refresh().await.unwrap();
    assert_eq!((summary.spendable, summary.locked), (10 * EPIC, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repair_from_a_start_height_is_refused() {
    let pair = funded_pair().await;
    let refused = pair
        .alice
        .scan(Some(5), true, Progress::default().report())
        .await;
    assert_eq!(refused.unwrap_err().kind, WalletErrorKind::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_scan_while_one_runs_is_refused_and_cancel_reaches_the_first() {
    let pair = funded_pair().await;
    let alice = Arc::clone(&pair.alice);
    pair.chain.set_node_stalled(true);
    let running = {
        let alice = Arc::clone(&alice);
        let report = Progress::default().report();
        tokio::spawn(async move { alice.scan(None, false, report).await })
    };
    assert!(eventually(|| pair.chain.stalled_node_calls() > 0).await);

    let second = alice.scan(None, false, Progress::default().report()).await;

    assert_eq!(second.unwrap_err().kind, WalletErrorKind::WalletBusy);
    alice.cancel_scan();
    let first = tokio::time::timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.unwrap_err().kind, WalletErrorKind::Cancelled);
    pair.chain.set_node_stalled(false);
    assert_eq!(scan(&alice, false).await.found, 1, "the slot is free again");
}
