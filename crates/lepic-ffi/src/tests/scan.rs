//! Scans through the binding: the result the last event carries, the `delete_unconfirmed`
//! repair, and cancelling a scan that waits on the node.

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
    let progress = Progress::default();
    session
        .scan(None, delete_unconfirmed, progress.report())
        .await
        .unwrap();
    let last = progress.last();
    assert!(last.finished);
    last.result.unwrap()
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
