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
    LocatedKernel, NodeApi, NodeClient, NodeError, NodeVersion, OutputLocation, PmmrIndices,
    Propagation, Tip, UnspentOutputs,
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
use lepic_wallet::refresh::{RefreshError, RefreshOutcome};
use lepic_wallet::scan::{ScanCancel, ScanOptions};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Ports, SharedRng, Wallet};
use rand::SeedableRng;
use rand::rngs::StdRng;
use send_support::{ACCOUNT, PEER, Sender, TIP, legacy_codecs};
use support::{FixedClock, LOOPBACK, MemoryStores, TestVault, fixed_time, password};
use uuid::Uuid;

const AMOUNT: u64 = 100_000_000;
const TTL_BLOCKS: u64 = 5;

const SEND_FILE_PLAIN_S3: &str =
    include_str!("../../../testdata/vectors/slates/send_file_plain_s3_v3.json");

/// The mock node's client, with answers a test scripts on top of the chain's.
struct Scripted {
    inner: NodeClient<MockNode>,
    /// Tips answered instead of the chain's, in order.
    tips: Mutex<VecDeque<u64>>,
    /// The next `get_outputs` answers that no output is on chain.
    hide_outputs_once: AtomicBool,
    /// `get_kernel` ignores the height range it is asked for.
    unbounded_kernels: bool,
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

    fn get_kernel(
        &self,
        excess: &Commitment,
        min_height: Option<Height>,
        max_height: Option<Height>,
    ) -> impl Future<Output = Result<Option<LocatedKernel>, NodeError>> + Send {
        if self.unbounded_kernels {
            self.inner.get_kernel(excess, None, None)
        } else {
            self.inner.get_kernel(excess, min_height, max_height)
        }
    }

    fn get_outputs(
        &self,
        commitments: &[Commitment],
    ) -> impl Future<Output = Result<Vec<OutputLocation>, NodeError>> + Send {
        let hide = self.hide_outputs_once.swap(false, Ordering::SeqCst);
        let answer = self.inner.get_outputs(commitments);
        async move {
            let found = answer.await?;
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
}

type ScriptedWallet = Wallet<Scripted, MemoryStores, TestVault>;

/// A second handle on the sender's wallet, unlocked, whose node answers as scripted.
fn scripted(sender: &Sender, tips: &[u64], hide_outputs_once: bool) -> ScriptedWallet {
    scripted_with(sender, tips, hide_outputs_once, false)
}

fn scripted_with(
    sender: &Sender,
    tips: &[u64],
    hide_outputs_once: bool,
    unbounded_kernels: bool,
) -> ScriptedWallet {
    let ports = sender.wallet.ports();
    let wallet = Wallet::new(
        sender.wallet.config().clone(),
        Ports {
            node: Scripted {
                inner: sender.harness.node.client(),
                tips: Mutex::new(tips.iter().copied().collect()),
                hide_outputs_once: AtomicBool::new(hide_outputs_once),
                unbounded_kernels,
            },
            stores: ports.stores.clone(),
            secrets: ports.secrets.clone(),
            transports: sender.harness.transports(),
            clock: Arc::new(FixedClock(fixed_time())),
            rng: SharedRng::new(StdRng::seed_from_u64(43)),
            runtime: sender.harness.runtime.handle().clone(),
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
        transport: LOOPBACK,
        to: Destination::new(PEER.to_owned()),
    };
    sender
        .harness
        .block_on(sender.wallet.send(request, delivery))
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
    set_tip(&sender, u64::MAX);

    let result = sender.harness.block_on(sender.wallet.refresh());

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

#[test]
fn expires_nothing_when_a_second_tip_disagrees() {
    let (sender, funding) = funded();
    let sent = send_with_ttl(&sender);
    set_tip(&sender, TIP + TTL_BLOCKS);
    let wallet = scripted(&sender, &[TIP + TTL_BLOCKS, TIP], false);

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
    let wallet = scripted(&sender, &[TIP + TTL_BLOCKS, TIP + TTL_BLOCKS + 1], false);

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
    let wallet = scripted(&sender, &[], true);

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
    sender
        .harness
        .node
        .update_chain(|chain| chain.outputs[0].height = Height::new(TIP + 50));

    let result = sender.harness.block_on(sender.wallet.refresh());

    assert!(
        matches!(result, Err(RefreshError::Implausible(_))),
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
                amount_credited: Amount::ZERO,
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
    let tip = kernel.height.value();
    set_tip(&sender, tip);
    sender.harness.node.update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            height: Height::new(tip + 40),
            ..kernel
        });
    });
    let wallet = scripted_with(&sender, &[], false, true);

    let result = sender.harness.block_on(wallet.refresh());

    assert!(
        matches!(result, Err(RefreshError::Implausible(_))),
        "{result:?}"
    );
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
    sender
        .store
        .write(|repos| repos.put_setting("refresh.last_confirmed_height", &u64::MAX.to_string()))
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
    refreshed(&sender.harness.block_on(sender.wallet.refresh()));
    assert_eq!(
        sender.wallet.last_confirmed_height().unwrap(),
        Some(Height::new(TIP))
    );
}
