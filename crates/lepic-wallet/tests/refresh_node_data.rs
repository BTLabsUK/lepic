// SPDX-License-Identifier: Apache-2.0
//! Refresh against node answers that cannot be true: a tip far beyond what the chain can have
//! reached, heights above the tip, a tip that moves while transactions are being expired, an
//! output that goes missing for one answer. None of them may expire, spend or confirm anything.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod send_support;
mod support;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use lepic_crypto::{Commitment, RangeProof};
use lepic_node::mock::{ChainOutput, MockNode};
use lepic_node::{
    BlockHeaderInfo, CallPolicy, LocatedKernel, NodeApi, NodeClient, NodeError, NodeVersion,
    OutputLocation, PmmrIndices, PoolTransaction, Propagation, RetryPolicy, RpcTransport, Tip,
    UnspentOutputs,
};
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_primitives::tx::Transaction;
use lepic_slate::codec::legacy::v3_json::LEGACY_V3_JSON;
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_store::{
    OutputRecord, OutputStatus, SlateStage, StoredSlate, TransactionEntry, TxDirection, TxId,
    TxState, WalletStore,
};
use lepic_transport::transport::Destination;
use lepic_wallet::chain::{ImplausibleNodeData, TIP_SLACK_BLOCKS};
use lepic_wallet::invoice::{InvoiceError, InvoiceRequest, PayRequest};
use lepic_wallet::refresh::{RefreshError, RefreshOutcome};
use lepic_wallet::release::RELEASE_AFTER_BLOCKS;
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use lepic_wallet::selection::{SelectionOptions, SelectionStrategy};
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use lepic_wallet::{Ports, SharedRng, Wallet, WalletError};
use rand::SeedableRng;
use rand::rngs::StdRng;
use send_support::{ACCOUNT, PEER, Sender, TIP, legacy_codecs};
use support::{FixedClock, TestStores, TestVault, fixed_time, password};
use uuid::Uuid;

const AMOUNT: u64 = 100_000_000;
const TTL_BLOCKS: u64 = 5;

const SEND_FILE_PLAIN_S3: &str =
    include_str!("../../../testdata/vectors/slates/send_file_plain_s3_v3.json");

/// Answers a test scripts on top of the mock chain's.
#[derive(Default)]
struct Script {
    /// Tips answered instead of the chain's, in order.
    tips: Vec<u64>,
    /// The next `get_outputs` answers that no output is on chain.
    hide_outputs_once: bool,
    /// Blocks added to every output height `get_outputs` reports.
    raise_outputs: u64,
    /// Blocks added to every kernel height `get_kernel` reports.
    raise_kernels: u64,
    /// Seconds the scripted wallet's clock runs ahead of the sender's.
    clock_ahead: i64,
}

/// The mock node's client with scripted answers applied after the client's own checks, so the
/// wallet sees them exactly as a node would send them to a client that checks nothing. This is
/// what shows the wallet's checks hold on their own.
struct Scripted {
    inner: NodeClient<MockNode>,
    tips: Mutex<VecDeque<u64>>,
    hide_outputs_once: AtomicBool,
    raise_outputs: u64,
    raise_kernels: u64,
}

impl NodeApi for Scripted {
    fn get_version(&self) -> impl Future<Output = Result<NodeVersion, NodeError>> + Send {
        self.inner.get_version()
    }

    fn get_tip(&self) -> impl Future<Output = Result<Tip, NodeError>> + Send {
        let scripted = self.tips.lock().unwrap().pop_front();
        let answer = self.inner.get_tip();
        async move {
            let mut tip = answer.await?;
            if let Some(height) = scripted {
                tip.height = Height::new(height);
            }
            Ok(tip)
        }
    }

    fn get_header(
        &self,
        height: Height,
    ) -> impl Future<Output = Result<Option<BlockHeaderInfo>, NodeError>> + Send {
        self.inner.get_header(height)
    }

    fn get_kernel(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> impl Future<Output = Result<Option<LocatedKernel>, NodeError>> + Send {
        let answer = self.inner.get_kernel(excess, min_height, max_height);
        let raise = self.raise_kernels;
        async move {
            Ok(answer.await?.map(|mut located| {
                located.height = Height::new(located.height.value() + raise);
                located
            }))
        }
    }

    fn get_outputs(
        &self,
        commitments: &[Commitment],
    ) -> impl Future<Output = Result<Vec<OutputLocation>, NodeError>> + Send {
        let hide = self.hide_outputs_once.swap(false, Ordering::SeqCst);
        let answer = self.inner.get_outputs(commitments);
        let raise = self.raise_outputs;
        async move {
            let mut found = answer.await?;
            for location in &mut found {
                location.height = Height::new(location.height.value() + raise);
            }
            Ok(if hide { Vec::new() } else { found })
        }
    }

    fn get_unspent_outputs(
        &self,
        start_index: u64,
        end_index: Option<u64>,
        max: u64,
    ) -> impl Future<Output = Result<UnspentOutputs, NodeError>> + Send {
        self.inner.get_unspent_outputs(start_index, end_index, max)
    }

    fn get_pmmr_indices(
        &self,
        start_height: Height,
        end_height: Option<Height>,
    ) -> impl Future<Output = Result<PmmrIndices, NodeError>> + Send {
        self.inner.get_pmmr_indices(start_height, end_height)
    }

    fn push_transaction(
        &self,
        transaction: &Transaction,
        propagation: Propagation,
    ) -> impl Future<Output = Result<(), NodeError>> + Send {
        self.inner.push_transaction(transaction, propagation)
    }

    fn get_unconfirmed_transactions(
        &self,
    ) -> impl Future<Output = Result<Vec<PoolTransaction>, NodeError>> + Send {
        self.inner.get_unconfirmed_transactions()
    }
}

type ScriptedWallet = Wallet<Scripted, TestStores, TestVault>;

/// A second handle on the sender's wallet, unlocked, whose node answers as scripted.
fn scripted(sender: &Sender, script: Script) -> ScriptedWallet {
    let ports = sender.wallet.ports();
    let wallet = Wallet::new(
        sender.wallet.config().clone(),
        Ports {
            node: Scripted {
                inner: sender.harness.node.client(),
                tips: Mutex::new(script.tips.into_iter().collect()),
                hide_outputs_once: AtomicBool::new(script.hide_outputs_once),
                raise_outputs: script.raise_outputs,
                raise_kernels: script.raise_kernels,
            },
            stores: ports.stores.clone(),
            secrets: ports.secrets.clone(),
            clock: Arc::new(FixedClock(
                jiff::Timestamp::from_second(fixed_time().as_second() + script.clock_ahead)
                    .unwrap(),
            )),
            rng: SharedRng::new(StdRng::seed_from_u64(43)),
            runtime: sender.harness.runtime.handle().clone(),
            methods: None,
        },
    )
    .unwrap();
    sender
        .harness
        .block_on(wallet.open(password("sender")))
        .unwrap();
    wallet
}

fn on_chain(output: &OutputRecord, height: u64, mmr_index: u64) -> ChainOutput {
    ChainOutput {
        commitment: output.id.commitment,
        features: output.id.features,
        proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
        height: Height::new(height),
        mmr_index,
        spent: false,
    }
}

fn funded() -> (Sender, OutputRecord) {
    let sender = Sender::new();
    let funding = sender.outputs().remove(0);
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(on_chain(&funding, 1, 1));
    });
    (sender, funding)
}

fn set_tip(sender: &Sender, height: u64) {
    sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(height));
}

fn send_with_ttl(sender: &Sender) -> TxId {
    let request = SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ttl_blocks: Some(TTL_BLOCKS),
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    };
    let delivery = Delivery::Deliver {
        to: Destination::new(PEER.to_owned()),
    };
    sender
        .harness
        .block_on(
            sender
                .wallet
                .send(&sender.harness.method(), request, delivery),
        )
        .unwrap()
        .tx_id
}

fn state(sender: &Sender, tx_id: TxId) -> TxState {
    sender.read(|repos| repos.transaction(tx_id)).unwrap().state
}

fn status(sender: &Sender, record: &OutputRecord) -> OutputStatus {
    sender
        .read(|repos| repos.output(record.commitment()))
        .unwrap()
        .status
}

fn tip_requests(sender: &Sender) -> usize {
    sender
        .harness
        .node
        .calls()
        .iter()
        .filter(|method| *method == "get_tip")
        .count()
}

fn refreshed(outcome: &Result<RefreshOutcome, RefreshError>) {
    assert!(
        matches!(outcome, Ok(RefreshOutcome::Refreshed(_))),
        "{outcome:?}"
    );
}

#[test]
fn refuses_a_tip_beyond_any_plausible_chain_height() {
    let (sender, funding) = funded();
    let sent = send_with_ttl(&sender);
    let wallet = scripted(
        &sender,
        Script {
            // Two equal tips, so only the plausibility check can refuse them.
            tips: vec![u64::MAX, u64::MAX],
            ..Script::default()
        },
    );

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(result, Err(RefreshError::Implausible(_))),
        "{result:?}"
    );
    assert_eq!(state(&sender, sent), TxState::Sent);
    assert_eq!(status(&sender, &funding), OutputStatus::Locked);
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);

    // The honest node is followed again at once.
    set_tip(&sender, TIP + 1);
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP + 1))
    );
}

/// Whichever layer refuses the answer, the node client or the wallet, the refresh fails and
/// nothing is stored.
fn assert_refused(result: &Result<RefreshOutcome, RefreshError>) {
    assert!(
        matches!(
            result,
            Err(RefreshError::Implausible(_) | RefreshError::Node(_))
        ),
        "{result:?}"
    );
}

#[test]
fn a_tip_beyond_any_plausible_height_changes_nothing_through_the_node_client() {
    let (sender, funding) = funded();
    let sent = send_with_ttl(&sender);
    set_tip(&sender, u64::MAX);

    let result = sender.harness.block_on(sender.wallet.refresh());

    assert_refused(&result);
    assert_eq!(state(&sender, sent), TxState::Sent);
    assert_eq!(status(&sender, &funding), OutputStatus::Locked);
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
}

#[test]
fn expires_nothing_when_a_second_tip_disagrees() {
    let (sender, funding) = funded();
    let sent = send_with_ttl(&sender);
    set_tip(&sender, TIP + TTL_BLOCKS);
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![TIP + TTL_BLOCKS, TIP],
            ..Script::default()
        },
    );

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(result, Err(RefreshError::Implausible(_))),
        "{result:?}"
    );
    assert_eq!(state(&sender, sent), TxState::Sent);
    assert_eq!(status(&sender, &funding), OutputStatus::Locked);
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
}

#[test]
fn expiry_needs_a_second_agreeing_tip_and_keeps_the_stored_height() {
    let (sender, funding) = funded();
    let sent = send_with_ttl(&sender);
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![TIP + TTL_BLOCKS, TIP + TTL_BLOCKS + 1],
            ..Script::default()
        },
    );

    refreshed(&sender.harness.block_on(wallet.refresh()));

    assert_eq!(state(&sender, sent), TxState::Expired);
    assert_eq!(status(&sender, &funding), OutputStatus::Unspent);
    // A tip that expired transactions is not stored; the next refresh stores the tip.
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP))
    );
    set_tip(&sender, TIP + TTL_BLOCKS);
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP + TTL_BLOCKS))
    );
}

#[test]
fn marks_an_output_spent_only_when_two_answers_miss_it() {
    let (sender, funding) = funded();
    let wallet = scripted(
        &sender,
        Script {
            hide_outputs_once: true,
            ..Script::default()
        },
    );

    let summary = sender.harness.block_on(wallet.refresh()).unwrap();

    assert!(
        matches!(summary, RefreshOutcome::Refreshed(summary) if summary.spent_outputs == 0),
        "{summary:?}"
    );
    assert_eq!(status(&sender, &funding), OutputStatus::Unspent);

    sender
        .harness
        .node
        .update_chain(|chain| chain.outputs[0].spent = true);
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    assert_eq!(status(&sender, &funding), OutputStatus::Spent);
}

#[test]
fn refuses_an_output_height_above_the_tip() {
    let (sender, funding) = funded();
    let wallet = scripted(
        &sender,
        Script {
            raise_outputs: TIP + 50,
            ..Script::default()
        },
    );
    let tips_before = tip_requests(&sender);

    let result = sender.harness.block_on(wallet.refresh());

    // The tip is read once more, and the node still reports the same one.
    assert!(
        matches!(
            result,
            Err(RefreshError::Implausible(
                ImplausibleNodeData::OutputAboveTip { tip, .. }
            )) if tip == Height::new(TIP)
        ),
        "{result:?}"
    );
    assert_eq!(tip_requests(&sender) - tips_before, 2);
    let stored = sender
        .read(|repos| repos.output(funding.commitment()))
        .unwrap();
    assert_eq!(stored, funding);
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
}

#[test]
fn an_output_height_above_the_tip_changes_nothing_through_the_node_client() {
    let (sender, funding) = funded();
    sender
        .harness
        .node
        .update_chain(|chain| chain.outputs[0].height = Height::new(TIP + 50));

    let result = sender.harness.block_on(sender.wallet.refresh());

    assert_refused(&result);
    let stored = sender
        .read(|repos| repos.output(funding.commitment()))
        .unwrap();
    assert_eq!(stored, funding);
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
}

#[test]
fn an_output_mined_after_the_tip_was_read_is_covered_by_a_second_tip() {
    let (sender, funding) = funded();
    // The block holding the output lands between the tip and the outputs requests.
    sender.harness.node.update_chain(|chain| {
        chain.tip.height = Height::new(TIP + 1);
        chain.outputs[0].height = Height::new(TIP + 1);
    });
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![TIP],
            ..Script::default()
        },
    );
    let tips_before = tip_requests(&sender);

    let outcome = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(outcome, Ok(RefreshOutcome::Refreshed(summary)) if summary.height == Height::new(TIP + 1)),
        "{outcome:?}"
    );
    assert_eq!(tip_requests(&sender) - tips_before, 2);
    let stored = sender
        .read(|repos| repos.output(funding.commitment()))
        .unwrap();
    assert_eq!(stored.status, OutputStatus::Unspent);
    assert_eq!(stored.height, Height::new(TIP + 1));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP + 1))
    );
}

#[test]
fn an_output_above_a_second_implausible_tip_is_refused() {
    let (sender, funding) = funded();
    let wallet = scripted(
        &sender,
        Script {
            // The second tip covers the output but is far ahead of the first.
            tips: vec![TIP, TIP + 51],
            raise_outputs: TIP + 50,
            ..Script::default()
        },
    );

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(
            result,
            Err(RefreshError::Implausible(
                ImplausibleNodeData::TipChanged { .. }
            ))
        ),
        "{result:?}"
    );
    let stored = sender
        .read(|repos| repos.output(funding.commitment()))
        .unwrap();
    assert_eq!(stored, funding);
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
}

/// A posted send without change, whose final slate is stored, as `send_file_plain` ends.
fn posted_without_change(sender: &Sender) -> (TxId, LocatedKernel) {
    posted(sender, Amount::ZERO)
}

/// A posted send of the `send_file_plain` final slate, crediting `change` back to the wallet.
fn posted(sender: &Sender, change: Amount) -> (TxId, LocatedKernel) {
    let vector: serde_json::Value = serde_json::from_str(SEND_FILE_PLAIN_S3).unwrap();
    let json = vector["expected"]["json"].as_str().unwrap().to_owned();
    let slate = legacy_codecs()
        .decode(&WireSlate::binary(
            MediaType::JSON,
            json.clone().into_bytes(),
        ))
        .unwrap();
    let slate_id = Uuid::from_bytes(*slate.id().as_bytes());
    let tx_id = sender
        .store
        .write(|repos| {
            let tx_id = repos.insert_transaction(&TransactionEntry {
                account: ACCOUNT,
                direction: TxDirection::Outgoing,
                state: TxState::Posted,
                slate_id: Some(slate_id),
                transport: None,
                amount_credited: change,
                amount_debited: Amount::new(AMOUNT),
                fee: Some(Fee::new(800_000)),
                created_at: fixed_time(),
                updated_at: fixed_time(),
            })?;
            repos.insert_slate(&StoredSlate {
                slate_id,
                stage: SlateStage::Standard3,
                codec: LEGACY_V3_JSON.as_str().to_owned(),
                bytes: json.into_bytes(),
            })?;
            Ok::<_, lepic_store::StoreError>(tx_id)
        })
        .unwrap();
    let kernel = LocatedKernel {
        kernel: slate.kernel().unwrap(),
        height: slate.height().checked_add_blocks(1).unwrap(),
        mmr_index: 1,
    };
    (tx_id, kernel)
}

#[test]
fn refuses_a_kernel_height_above_the_tip() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_without_change(&sender);
    set_tip(&sender, kernel.height.value());
    sender
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(kernel));
    let wallet = scripted(
        &sender,
        Script {
            raise_kernels: 40,
            ..Script::default()
        },
    );

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(result, Err(RefreshError::Implausible(_))),
        "{result:?}"
    );
    assert_eq!(state(&sender, tx_id), TxState::Posted);
}

#[test]
fn a_kernel_above_the_first_tip_is_covered_by_a_second_tip() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_without_change(&sender);
    let height = kernel.height.value();
    set_tip(&sender, height + 1);
    sender
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(kernel));
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![height],
            raise_kernels: 1,
            ..Script::default()
        },
    );

    refreshed(&sender.harness.block_on(wallet.refresh()));

    assert_eq!(state(&sender, tx_id), TxState::Confirmed);
    assert_eq!(
        sender.read(|repos| repos.confirmed_height(tx_id)),
        Some(Height::new(height + 1))
    );
}

#[test]
fn a_tip_read_again_is_not_read_a_third_time_for_a_kernel_above_it() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_without_change(&sender);
    let height = kernel.height.value();
    set_tip(&sender, height);
    sender
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(kernel));
    let wallet = scripted(
        &sender,
        Script {
            // The second tip covers the output but not the kernel two blocks above the first.
            tips: vec![height, height + 1],
            raise_outputs: height,
            raise_kernels: 2,
            ..Script::default()
        },
    );
    let tips_before = tip_requests(&sender);

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(
            result,
            Err(RefreshError::Implausible(
                ImplausibleNodeData::KernelOutOfRange { tip, .. }
            )) if tip == Height::new(height + 1)
        ),
        "{result:?}"
    );
    assert_eq!(tip_requests(&sender) - tips_before, 2);
    assert_eq!(state(&sender, tx_id), TxState::Posted);
}

#[test]
fn expiry_at_a_tip_read_again_does_not_read_it_a_third_time() {
    let (sender, funding) = funded();
    let sent = send_with_ttl(&sender);
    let wallet = scripted(
        &sender,
        Script {
            // Nothing expires at the first tip; the second, which covers the input, expires
            // the send.
            tips: vec![TIP + TTL_BLOCKS - 1, TIP + TTL_BLOCKS],
            raise_outputs: TIP + TTL_BLOCKS - 1,
            ..Script::default()
        },
    );
    let tips_before = tip_requests(&sender);

    let outcome = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(outcome, Ok(RefreshOutcome::Refreshed(summary))
            if summary.expired_transactions == 1
                && summary.height == Height::new(TIP + TTL_BLOCKS)),
        "{outcome:?}"
    );
    assert_eq!(tip_requests(&sender) - tips_before, 2);
    assert_eq!(state(&sender, sent), TxState::Expired);
    assert_eq!(status(&sender, &funding), OutputStatus::Unspent);
}

#[test]
fn a_second_tip_above_the_plausible_limit_is_refused() {
    let (sender, funding) = funded();
    let reference = format!("{TIP} {}", fixed_time().as_second());
    sender
        .store
        .write(|repos| {
            repos.put_setting("chain.first", &reference)?;
            repos.put_setting("chain.reference", &reference)?;
            repos.delete_setting("chain.pending")
        })
        .unwrap();
    let limit = TIP + TIP_SLACK_BLOCKS;
    let wallet = scripted(
        &sender,
        Script {
            // Both tips agree; only the second is above the limit, and only it covers the
            // output.
            tips: vec![limit, limit + 1],
            raise_outputs: limit,
            ..Script::default()
        },
    );

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(
            result,
            Err(RefreshError::Implausible(
                ImplausibleNodeData::TipTooHigh { tip, .. }
            )) if tip == Height::new(limit + 1)
        ),
        "{result:?}"
    );
    let stored = sender
        .read(|repos| repos.output(funding.commitment()))
        .unwrap();
    assert_eq!(stored, funding);
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
    assert_eq!(
        sender.read(|repos| repos.setting("chain.reference")),
        Some(reference)
    );
}

#[test]
fn a_release_check_kernel_above_the_tip_does_not_move_the_tip() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted(&sender, Amount::new(1));
    let created = kernel.height.value() - 1;
    let due = created + RELEASE_AFTER_BLOCKS;
    sender
        .store
        .write(|repos| repos.put_setting("refresh.last_confirmed_height", &due.to_string()))
        .unwrap();
    set_tip(&sender, due);
    sender
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(kernel));
    let wallet = scripted(
        &sender,
        Script {
            // A node that answers above the bound it was given, with a tip that would cover it.
            tips: vec![due, due + 1],
            raise_kernels: due - created,
            clock_ahead: DAY_SECONDS,
            ..Script::default()
        },
    );
    let tips_before = tip_requests(&sender);

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(
            result,
            Err(RefreshError::Implausible(
                ImplausibleNodeData::KernelOutOfRange { tip, .. }
            )) if tip == Height::new(due)
        ),
        "{result:?}"
    );
    assert_eq!(tip_requests(&sender) - tips_before, 1);
    assert_eq!(state(&sender, tx_id), TxState::Posted);
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(due))
    );
}

/// The raw mock node with every `get_kernel` answer raised by some blocks, below the node
/// client, as a node would send it.
struct RaisedKernels {
    node: MockNode,
    blocks: u64,
}

impl RpcTransport for RaisedKernels {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        let kernel_request = serde_json::from_slice::<serde_json::Value>(&body)
            .is_ok_and(|request| request["method"] == "get_kernel");
        let response = self.node.post(endpoint, body).await?;
        if !kernel_request {
            return Ok(response);
        }
        let mut response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        if let Some(height) = response.pointer_mut("/result/Ok/height") {
            *height = serde_json::json!(height.as_u64().unwrap() + self.blocks);
        }
        Ok(serde_json::to_vec(&response).unwrap())
    }

    fn node_label(&self) -> &str {
        "raised kernels"
    }
}

#[test]
fn a_kernel_height_above_the_tip_changes_nothing_through_the_node_client() {
    let (sender, _) = funded();
    let (tx_id, kernel) = posted_without_change(&sender);
    set_tip(&sender, kernel.height.value());
    sender
        .harness
        .node
        .update_chain(|chain| chain.kernels.push(kernel));
    let ports = sender.wallet.ports();
    let client = NodeClient::new(
        RaisedKernels {
            node: sender.harness.node.clone(),
            blocks: 40,
        },
        CallPolicy {
            retry: RetryPolicy::NONE,
            ..lepic_node::testing::call_policy()
        },
    );
    let wallet = Wallet::new(
        sender.wallet.config().clone(),
        Ports {
            node: client,
            stores: ports.stores.clone(),
            secrets: ports.secrets.clone(),
            clock: Arc::new(FixedClock(fixed_time())),
            rng: SharedRng::new(StdRng::seed_from_u64(44)),
            runtime: sender.harness.runtime.handle().clone(),
            methods: None,
        },
    )
    .unwrap();
    sender
        .harness
        .block_on(wallet.open(password("sender")))
        .unwrap();

    let result = sender.harness.block_on(wallet.refresh());

    assert_refused(&result);
    assert_eq!(state(&sender, tx_id), TxState::Posted);
}

#[test]
fn never_expires_a_finalized_transaction() {
    let (sender, funding) = funded();
    let sent = send_with_ttl(&sender);
    sender
        .store
        .write(|repos| {
            let mut entry = repos.transaction(sent)?.unwrap();
            entry.state = TxState::Finalized;
            repos.update_transaction(sent, &entry)
        })
        .unwrap();
    set_tip(&sender, TIP + TTL_BLOCKS + 10);

    let outcome = sender.harness.block_on(sender.wallet.refresh()).unwrap();

    assert!(
        matches!(outcome, RefreshOutcome::Refreshed(summary) if summary.expired_transactions == 0),
        "{outcome:?}"
    );
    assert_eq!(state(&sender, sent), TxState::Finalized);
    assert_eq!(status(&sender, &funding), OutputStatus::Locked);
}

#[test]
fn reset_recovers_a_wallet_whose_stored_height_is_ahead_of_the_chain() {
    let sender = Sender::new();
    let stale_reference = format!("1000000 {}", fixed_time().as_second());
    sender
        .store
        .write(|repos| {
            repos.put_setting("refresh.last_confirmed_height", &u64::MAX.to_string())?;
            repos.put_setting("chain.reference", &stale_reference)
        })
        .unwrap();
    let behind = sender.harness.block_on(sender.wallet.refresh()).unwrap();
    assert!(
        matches!(behind, RefreshOutcome::NodeBehind { .. }),
        "{behind:?}"
    );

    sender
        .harness
        .block_on(sender.wallet.reset_chain_position(
            ScanOptions::restore(lepic_primitives::params::Network::Floonet),
            &ScanCancel::new(),
        ))
        .unwrap();

    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
    // The stale reference is gone; the rescan holds the tip it reached until a refresh agrees.
    assert_eq!(sender.read(|repos| repos.setting("chain.reference")), None);
    assert_eq!(
        sender.read(|repos| repos.setting("chain.pending")),
        Some(format!("{TIP} {}", fixed_time().as_second()))
    );
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP))
    );
    assert_eq!(
        sender.read(|repos| repos.setting("chain.reference")),
        Some(format!("{TIP} {}", fixed_time().as_second()))
    );
}

const DAY_SECONDS: i64 = 86_400;

#[test]
fn one_answer_far_ahead_does_not_leave_the_honest_node_behind() {
    let (sender, _) = funded();
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP))
    );
    // A day later a node answers once with a tip well ahead of the chain, but below every
    // bound.
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![TIP + 2_000],
            clock_ahead: DAY_SECONDS,
            ..Script::default()
        },
    );

    refreshed(&sender.harness.block_on(wallet.refresh()));

    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP))
    );
    set_tip(&sender, TIP + 1);
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP + 1))
    );
}

#[test]
fn a_tip_ahead_is_confirmed_by_a_later_agreeing_refresh() {
    let (sender, _) = funded();
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![TIP + 2_000, TIP + 2_001],
            clock_ahead: DAY_SECONDS,
            ..Script::default()
        },
    );

    refreshed(&sender.harness.block_on(wallet.refresh()));
    refreshed(&sender.harness.block_on(wallet.refresh()));

    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP + 2_001))
    );
}

#[test]
fn a_wallet_with_no_confirmed_tip_is_bounded_by_the_network_checkpoint() {
    let (sender, _) = funded();
    sender
        .store
        .write(|repos| {
            for name in ["chain.first", "chain.reference", "chain.pending"] {
                repos.delete_setting(name)?;
            }
            Ok::<_, lepic_store::StoreError>(())
        })
        .unwrap();
    // Far above the floonet chain, though below twice the blocks since genesis.
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![5_000_000, 5_000_000],
            ..Script::default()
        },
    );

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(
            result,
            Err(RefreshError::Implausible(
                ImplausibleNodeData::TipTooHigh { .. }
            ))
        ),
        "{result:?}"
    );
    assert_eq!(sender.wallet.last_confirmed_height().unwrap(), None);
}

#[test]
fn send_refuses_a_tip_above_the_plausible_height() {
    let (sender, funding) = funded();
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![TIP + 100_000],
            ..Script::default()
        },
    );
    let request = SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    };
    let delivery = Delivery::Deliver {
        to: Destination::new(PEER.to_owned()),
    };

    let result = sender
        .harness
        .block_on(wallet.send(&sender.harness.method(), request, delivery));

    assert!(
        matches!(
            result,
            Err(SendError::Wallet(WalletError::Implausible(
                ImplausibleNodeData::TipTooHigh { .. }
            )))
        ),
        "{result:?}"
    );
    assert_eq!(status(&sender, &funding), OutputStatus::Unspent);
}

/// The sender's wallet after a refresh confirmed the tip, as a scripted handle whose node next
/// answers a tip far above the plausible height.
fn answering_an_implausible_tip(sender: &Sender) -> ScriptedWallet {
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    scripted(
        sender,
        Script {
            tips: vec![TIP + 100_000],
            ..Script::default()
        },
    )
}

/// A golden slate vector's JSON, as it arrives over the loopback transport.
fn slate_vector(json: &str) -> (WireSlate, Amount) {
    let vector: serde_json::Value = serde_json::from_str(json).unwrap();
    let text = vector["expected"]["json"].as_str().unwrap().to_owned();
    let slate: serde_json::Value = serde_json::from_str(&text).unwrap();
    let amount = Amount::new(slate["amount"].as_str().unwrap().parse().unwrap());
    (
        WireSlate::binary(MediaType::JSON, text.into_bytes()),
        amount,
    )
}

fn assert_implausible_wallet_error(error: &WalletError) {
    assert!(
        matches!(
            error,
            WalletError::Implausible(ImplausibleNodeData::TipTooHigh { .. })
        ),
        "{error:?}"
    );
}

/// Nothing a refused stage could have stored is there: no transaction, the funding unspent.
fn assert_nothing_stored(sender: &Sender, funding: &OutputRecord) {
    assert!(sender.transactions().is_empty());
    assert_eq!(status(sender, funding), OutputStatus::Unspent);
    assert_eq!(sender.outputs().len(), 1);
}

#[test]
fn receive_refuses_a_tip_above_the_plausible_height() {
    let (sender, funding) = funded();
    let wallet = answering_an_implausible_tip(&sender);
    let (s1, _) = slate_vector(include_str!(
        "../../../testdata/vectors/slates/send_file_plain_s1_v3.json"
    ));

    let result = sender.harness.block_on(wallet.receive(
        &sender.harness.method(),
        &s1,
        lepic_wallet::ReceiveRequest::default(),
    ));

    match result {
        Err(lepic_wallet::ReceiveError::Wallet(error)) => assert_implausible_wallet_error(&error),
        other => panic!("{other:?}"),
    }
    assert_nothing_stored(&sender, &funding);
}

#[test]
fn finalize_refuses_a_tip_above_the_plausible_height() {
    let (sender, funding) = funded();
    let wallet = answering_an_implausible_tip(&sender);
    let (s2, _) = slate_vector(include_str!(
        "../../../testdata/vectors/slates/send_file_plain_s2_v3.json"
    ));

    let result =
        sender
            .harness
            .block_on(wallet.finalize(&sender.harness.method(), &s2, Propagation::Stem));

    match result {
        Err(lepic_wallet::FinalizeError::Wallet(error)) => assert_implausible_wallet_error(&error),
        other => panic!("{other:?}"),
    }
    assert_nothing_stored(&sender, &funding);
}

#[test]
fn invoice_issue_refuses_a_tip_above_the_plausible_height() {
    let (sender, funding) = funded();
    let wallet = answering_an_implausible_tip(&sender);
    let request = InvoiceRequest {
        account: ACCOUNT,
        amount: Amount::new(AMOUNT),
        message: None,
        ttl_blocks: None,
    };
    let delivery = Delivery::Deliver {
        to: Destination::new(PEER.to_owned()),
    };

    let result =
        sender
            .harness
            .block_on(wallet.issue_invoice(&sender.harness.method(), request, delivery));

    match result {
        Err(InvoiceError::Wallet(error)) => assert_implausible_wallet_error(&error),
        other => panic!("{other:?}"),
    }
    assert_nothing_stored(&sender, &funding);
}

#[test]
fn invoice_pay_refuses_a_tip_above_the_plausible_height() {
    let (sender, funding) = funded();
    let wallet = answering_an_implausible_tip(&sender);
    let (i1, amount) = slate_vector(include_str!(
        "../../../testdata/vectors/slates/invoice_file_header_7_i1_v3.json"
    ));

    let result = sender.harness.block_on(wallet.pay_invoice(
        &sender.harness.method(),
        &i1,
        PayRequest::new(ACCOUNT, amount),
    ));

    match result {
        Err(InvoiceError::Wallet(error)) => assert_implausible_wallet_error(&error),
        other => panic!("{other:?}"),
    }
    assert_nothing_stored(&sender, &funding);
}

#[test]
fn invoice_finalize_refuses_a_tip_above_the_plausible_height() {
    let (sender, funding) = funded();
    let wallet = answering_an_implausible_tip(&sender);
    let (i2, _) = slate_vector(include_str!(
        "../../../testdata/vectors/slates/invoice_file_header_7_i2_v3.json"
    ));

    let result = sender.harness.block_on(wallet.finalize_invoice(
        &sender.harness.method(),
        &i2,
        Propagation::Stem,
    ));

    match result {
        Err(InvoiceError::Wallet(error)) => assert_implausible_wallet_error(&error),
        other => panic!("{other:?}"),
    }
    assert_nothing_stored(&sender, &funding);
}

#[test]
fn fee_estimates_refuse_a_tip_above_the_plausible_height() {
    let (sender, _) = funded();
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    let wallet = scripted(
        &sender,
        Script {
            tips: vec![TIP + 100_000, TIP + 100_000],
            ..Script::default()
        },
    );
    let options = SelectionOptions {
        minimum_confirmations: 1,
        ..SelectionOptions::new(ACCOUNT)
    };

    let fee = sender
        .harness
        .block_on(wallet.estimate_fee(Amount::new(AMOUNT), options.clone()));
    let max = sender.harness.block_on(wallet.estimate_max(options));

    for result in [fee, max] {
        assert!(
            matches!(
                result,
                Err(SendError::Wallet(WalletError::Implausible(
                    ImplausibleNodeData::TipTooHigh { .. }
                )))
            ),
            "{result:?}"
        );
    }
}
