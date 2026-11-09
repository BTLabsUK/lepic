// SPDX-License-Identifier: Apache-2.0
//! Posting to a node whose pool already holds the transaction: the node refuses the repeated
//! push with its pool's duplicate answer, and the wallet records the transaction as posted
//! instead of reporting a failed post. The node is the mock node behind a transport that gives
//! that answer, as a node at `v4.0.4` words it, for chosen pushes.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lepic_legacy_slate::v3_json::V3JsonCodec;
use lepic_node::mock::{MockFailure, MockNode};
use lepic_node::{
    CallPolicy, LocatedKernel, NodeClient, NodeError, Propagation, RejectionKind, RetryPolicy,
    RpcTransport,
};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::OutputFeatures;
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec as _, MediaType, WireSlate};
use lepic_store::{AccountRecord, SlateStage, StoreError, TxId, TxState, WalletStore};
use lepic_transport::file::FILE;
use lepic_transport::transport::{Destination, Inbound};
use lepic_wallet::event::TransactionState;
use lepic_wallet::finalize::{FinalizeError, Posted};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest};
use lepic_wallet::{Event, Ports, StoreOpener, Wallet};
use receive_harness::Receiver;
use send_support::{ACCOUNT, FUNDING, NEXT_CHILD, PEER, SENDER_MNEMONIC, TIP, context_key, output};
use serde_json::{Value, json};
use support::{Harness, TestStore, TestStores, TestVault, password};

const AMOUNT: u64 = 100_000_000;

const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// The mock node, except that the next `duplicates` pushes get the answer a node's pool API
/// gives for a transaction its pool already holds.
#[derive(Clone)]
struct PoolWithTransaction {
    node: MockNode,
    duplicates: Arc<AtomicUsize>,
}

impl PoolWithTransaction {
    fn answer_next_push_as_duplicate(&self) {
        self.duplicates.fetch_add(1, Ordering::SeqCst);
    }

    fn take_duplicate(&self) -> bool {
        self.duplicates
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
    }
}

impl RpcTransport for PoolWithTransaction {
    async fn post(&self, endpoint: &'static str, body: Vec<u8>) -> Result<Vec<u8>, NodeError> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        if request["method"] == "push_transaction" && self.take_duplicate() {
            let answer = json!({
                "id": request["id"],
                "jsonrpc": "2.0",
                "result": {"Err": {"Internal": "Failed to update pool: Duplicate tx"}},
            });
            return Ok(answer.to_string().into_bytes());
        }
        self.node.post(endpoint, body).await
    }

    fn node_label(&self) -> &str {
        "mock"
    }
}

type PoolWallet = Wallet<NodeClient<PoolWithTransaction>, TestStores, TestVault>;

/// The funded `send_file_plain` sender on that node, with a transaction sent and answered.
struct Posting {
    harness: Harness,
    pool: PoolWithTransaction,
    wallet: PoolWallet,
    store: TestStore,
    tx_id: TxId,
    s2: WireSlate,
}

impl Posting {
    fn new() -> Self {
        let harness = Harness::new();
        let pool = PoolWithTransaction {
            node: harness.node.clone(),
            duplicates: Arc::default(),
        };
        let shared = harness.ports(TestVault::default());
        let ports = Ports {
            node: NodeClient::new(
                pool.clone(),
                CallPolicy {
                    retry: RetryPolicy::NONE,
                    ..lepic_node::testing::call_policy()
                },
            ),
            stores: shared.stores,
            secrets: shared.secrets,
            methods: shared.methods,
            clock: shared.clock,
            rng: shared.rng,
            runtime: shared.runtime,
        };
        let wallet = Wallet::new(harness.config(Network::Floonet), ports).unwrap();
        harness
            .block_on(wallet.restore(password("sender"), SENDER_MNEMONIC))
            .unwrap();
        support::complete_restore_scan(&harness.runtime, &wallet);
        harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(TIP));
        let seed = lepic_keychain::Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = harness
            .stores
            .open(
                &harness.data_dir,
                context_key(&seed),
                &lepic_wallet::store_key(&seed).unwrap(),
            )
            .unwrap();
        let keychain =
            lepic_keychain::Keychain::from_seed(&seed, lepic_primitives::params::Network::Floonet)
                .unwrap();
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: ACCOUNT,
                    label: "default".to_owned(),
                    next_child: NEXT_CHILD,
                })?;
                repos.put_output(&output(&keychain, 0, FUNDING, OutputFeatures::Coinbase))
            })
            .unwrap();

        let sent = harness
            .block_on(wallet.send(
                &harness.method(),
                SendRequest {
                    minimum_confirmations: 1,
                    strategy: SelectionStrategy::Smallest,
                    ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
                },
                Delivery::Deliver {
                    to: Destination::new(PEER.to_owned()),
                },
            ))
            .unwrap();
        let peer = harness.peer.lock().unwrap().take().unwrap();
        let s1 = harness
            .block_on(peer.next_envelope())
            .unwrap()
            .unwrap()
            .wire()
            .clone();
        let s2 = Receiver::new(RECEIVER_MNEMONIC, TIP)
            .receive(FILE, s1.as_text().unwrap(), None)
            .unwrap()
            .reply;
        Self {
            harness,
            pool,
            wallet,
            store,
            tx_id: sent.tx_id,
            s2,
        }
    }

    fn finalize(&self) -> Result<lepic_wallet::Finalized, FinalizeError> {
        self.harness.block_on(self.wallet.finalize(
            &self.harness.method(),
            &self.s2,
            Propagation::Stem,
        ))
    }

    fn post(&self) -> Result<Posted, FinalizeError> {
        self.harness
            .block_on(self.wallet.post(self.tx_id, Propagation::Stem))
    }

    /// The S3 the wallet stored when it finalized, read back from its database.
    fn stored_s3(&self) -> lepic_slate::model::Slate {
        let stored = self
            .store
            .read(|repos| {
                let entry = repos.transaction(self.tx_id)?.unwrap();
                repos.slate(entry.slate_id.unwrap(), SlateStage::Standard3)
            })
            .unwrap()
            .unwrap();
        V3JsonCodec::new(Network::Floonet.params().default_base_fee())
            .decode(&WireSlate::binary(MediaType::JSON, stored.bytes))
            .unwrap()
    }

    fn state(&self) -> TxState {
        self.store
            .read(|repos| Ok::<_, StoreError>(repos.transaction(self.tx_id)?.unwrap().state))
            .unwrap()
    }
}

fn transaction_events(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
) -> Vec<(TxState, TxState)> {
    let mut changes = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let Event::Transaction(TransactionState { from, to, .. }) = event {
            changes.push((from, to));
        }
    }
    changes
}

#[test]
fn a_post_the_node_already_holds_is_recorded_as_posted() {
    let posting = Posting::new();
    // The first push reached the node, but its answer was lost.
    posting
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    let error = posting.finalize().unwrap_err();
    assert!(
        matches!(error, FinalizeError::NotPosted { .. }),
        "{error:?}"
    );
    assert_eq!(posting.state(), TxState::Finalized);

    let mut events = posting.wallet.subscribe();
    posting.pool.answer_next_push_as_duplicate();
    posting.post().unwrap();

    assert_eq!(posting.state(), TxState::Posted);
    assert_eq!(
        transaction_events(&mut events),
        vec![(TxState::Finalized, TxState::Posted)]
    );
}

#[test]
fn a_post_whose_kernel_is_already_on_chain_reports_that() {
    let posting = Posting::new();
    let finalized = posting.finalize().unwrap();
    let mined_at = Height::new(TIP + 1);
    posting.harness.node.update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            kernel: finalized.slate.kernel().unwrap(),
            height: mined_at,
            mmr_index: 1,
        });
        chain.tip.height = mined_at;
    });
    posting.harness.node.fail_next(
        "push_transaction",
        MockFailure::Rejected(RejectionKind::Internal),
    );

    let posted = posting.post().unwrap();

    assert_eq!(posted, Posted::AlreadyOnChain { height: mined_at });
    assert_eq!(posting.state(), TxState::Posted);
}

#[test]
fn a_finalized_transaction_whose_kernel_is_on_chain_is_recorded_as_posted() {
    let posting = Posting::new();
    posting
        .harness
        .node
        .fail_next("push_transaction", MockFailure::Unreachable);
    let error = posting.finalize().unwrap_err();
    assert!(
        matches!(error, FinalizeError::NotPosted { .. }),
        "{error:?}"
    );
    let finalized = posting.stored_s3();
    let mined_at = Height::new(TIP + 1);
    posting.harness.node.update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            kernel: finalized.kernel().unwrap(),
            height: mined_at,
            mmr_index: 1,
        });
    });
    posting.harness.node.fail_next(
        "push_transaction",
        MockFailure::Rejected(RejectionKind::Internal),
    );
    let mut events = posting.wallet.subscribe();

    let posted = posting.post().unwrap();

    assert_eq!(posted, Posted::AlreadyOnChain { height: mined_at });
    assert_eq!(posting.state(), TxState::Posted);
    assert_eq!(
        transaction_events(&mut events),
        vec![(TxState::Finalized, TxState::Posted)]
    );
}

#[test]
fn a_finalize_whose_push_the_node_already_holds_is_posted() {
    let posting = Posting::new();
    posting.pool.answer_next_push_as_duplicate();

    posting.finalize().unwrap();

    assert_eq!(posting.state(), TxState::Posted);
    assert!(posting.harness.node.pushed_transactions().is_empty());
}

#[test]
fn any_other_refusal_of_the_push_is_a_failed_post() {
    let posting = Posting::new();
    posting.harness.node.fail_next(
        "push_transaction",
        MockFailure::Rejected(RejectionKind::Internal),
    );

    let error = posting.finalize().unwrap_err();

    assert!(
        matches!(
            &error,
            FinalizeError::NotPosted {
                source: NodeError::Rejected { .. },
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(posting.state(), TxState::Finalized);
}

/// Another wallet on the phrase spent the send's input: the node's pool refuses the push and
/// the input is gone from the chain (the scripted chain never held it).
#[test]
fn a_post_whose_inputs_another_wallet_spent_ends_the_send_with_its_own_error() {
    let posting = Posting::new();
    posting
        .harness
        .node
        .fail_next("push_transaction", MockFailure::PoolRefused);

    let error = posting.finalize().unwrap_err();

    assert!(
        matches!(error, FinalizeError::InputsSpentElsewhere { tx_id, .. } if tx_id == posting.tx_id),
        "{error:?}"
    );
    assert_eq!(posting.state(), TxState::Cancelled);
    let outputs = posting
        .store
        .read(|repos| repos.outputs(ACCOUNT, None))
        .unwrap();
    assert!(
        outputs
            .iter()
            .all(|output| output.status == lepic_store::OutputStatus::Spent),
        "{outputs:?}"
    );
}

#[test]
fn a_pool_refusal_with_the_inputs_on_chain_is_only_not_posted() {
    let posting = Posting::new();
    let input = posting
        .store
        .read(|repos| repos.outputs(ACCOUNT, None))
        .unwrap()
        .into_iter()
        .find(|output| output.status == lepic_store::OutputStatus::Locked)
        .unwrap();
    posting.harness.node.update_chain(|chain| {
        chain.outputs.push(lepic_node::mock::ChainOutput {
            commitment: input.id.commitment,
            features: input.id.features,
            proof: support::some_proof(),
            height: Height::new(1),
            mmr_index: 1,
            spent: false,
        });
    });
    posting
        .harness
        .node
        .fail_next("push_transaction", MockFailure::PoolRefused);

    let error = posting.finalize().unwrap_err();

    assert!(
        matches!(error, FinalizeError::NotPosted { .. }),
        "{error:?}"
    );
    assert_eq!(posting.state(), TxState::Finalized);
}
