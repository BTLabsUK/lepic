//! The output list through the binding.

use super::http::{EPIC, funded_pair};
use crate::api::types::{OutputCategory, OutputStatus};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outputs_show_the_locked_input_and_the_change_of_a_send() {
    let pair = funded_pair().await;
    let alice = &pair.alice;
    let summary = alice.refresh().await.unwrap();
    let funded = alice.outputs().unwrap();
    assert_eq!(funded.len(), 1);
    let funding = &funded[0];
    assert_eq!(funding.status, OutputStatus::Unspent);
    assert_eq!(funding.category, Some(OutputCategory::Spendable));
    assert_eq!(funding.value, 10 * EPIC);
    assert_eq!((funding.height, funding.confirmations), (1, 20));
    assert_eq!(summary.last_confirmed_height, 20);
    assert!(!funding.is_coinbase);
    assert!(funding.mmr_index.is_some());
    assert_eq!(funding.commitment.len(), 66);

    let slate = alice.create_send_slate(EPIC, 1, None).await.unwrap();

    let outputs = alice.outputs().unwrap();
    let input = outputs
        .iter()
        .find(|output| output.commitment == funding.commitment)
        .unwrap();
    assert_eq!(input.status, OutputStatus::Locked);
    assert_eq!(input.category, Some(OutputCategory::Locked));
    assert_eq!(input.tx_id, Some(slate.tx_id));
    let change: Vec<_> = outputs
        .iter()
        .filter(|output| output.status == OutputStatus::Unconfirmed)
        .collect();
    assert_eq!(change.len(), 1);
    assert_eq!(
        change[0].category,
        Some(OutputCategory::AwaitingFinalization)
    );
    assert_eq!((change[0].confirmations, change[0].mmr_index), (0, None));
    assert_eq!(change[0].tx_id, Some(slate.tx_id));
    let summary = alice.stored_summary().unwrap();
    assert_eq!(summary.locked, input.value);
    assert_eq!(summary.awaiting_finalization, change[0].value);
}
