// SPDX-License-Identifier: Apache-2.0
//! An offline session (`WalletConfig::offline`): no node call is sent, yet a send is made on
//! the last confirmed tip, received by an online wallet, and finalized without a push. Its
//! finished payment is the stored S3, and a later online session confirms the transaction once
//! its kernel is on chain.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

#[path = "receive/harness.rs"]
mod receive_harness;
mod send_support;
mod support;

use std::sync::PoisonError;

use lepic_node::mock::ChainOutput;
use lepic_node::{LocatedKernel, NodeError, Propagation};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_primitives::tx::Transaction;
use lepic_slate::codec::WireSlate;
use lepic_slate::stage::Stage;
use lepic_store::{TxId, TxState};
use lepic_transport::file::FILE;
use lepic_transport::loopback::LoopbackTransport;
use lepic_transport::transport::{Destination, Inbound as _};
use lepic_wallet::WalletConfig;
use lepic_wallet::refresh::RefreshOutcome;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendError, SendRequest};
use receive_harness::Receiver;
use send_support::{ACCOUNT, PEER, Sender, TIP};
use support::{LOOPBACK, TestWallet, password};

const AMOUNT: u64 = 100_000_000;
const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

fn request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

/// The funded sender, its funding on chain and refreshed online, so it has a confirmed tip.
fn funded_sender() -> Sender {
    let sender = Sender::new();
    let funding = sender.outputs()[0].clone();
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(ChainOutput {
            commitment: funding.id.commitment,
            features: funding.id.features,
            proof: support::some_proof(),
            height: Height::new(1),
            mmr_index: 1,
            spent: false,
        });
    });
    refreshed(&sender.harness, &sender.wallet);
    sender
}

fn refreshed(harness: &support::Harness, wallet: &TestWallet) {
    match harness.block_on(wallet.refresh()).unwrap() {
        RefreshOutcome::Refreshed(_) => {}
        other @ RefreshOutcome::NodeBehind { .. } => panic!("refresh did not apply: {other:?}"),
    }
}

/// The sender's wallet opened again with `offline`, as the app does on a mode change, and
/// the other end of its loopback transport.
fn reopened(sender: &Sender, offline: bool) -> (TestWallet, LoopbackTransport) {
    sender.wallet.lock();
    let harness = &sender.harness;
    let config = WalletConfig {
        offline,
        ..harness.config(Network::Floonet)
    };
    let wallet = harness.wallet_with(config, harness.vault.clone());
    harness.block_on(wallet.open(password("sender"))).unwrap();
    let peer = harness
        .peer
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .unwrap();
    (wallet, peer)
}

fn send(sender: &Sender, wallet: &TestWallet, peer: &LoopbackTransport) -> (TxId, WireSlate) {
    let sent = sender
        .harness
        .block_on(wallet.send(
            request(),
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap();
    let envelope = sender
        .harness
        .block_on(peer.next_envelope())
        .unwrap()
        .unwrap();
    (sent.tx_id, envelope.wire().clone())
}

fn state(sender: &Sender, tx_id: TxId) -> TxState {
    sender.read(|repos| repos.transaction(tx_id)).unwrap().state
}

/// A send made, received by an online wallet and finalized in an offline session.
struct Cold {
    sender: Sender,
    wallet: TestWallet,
    tx_id: TxId,
}

fn cold_payment() -> Cold {
    let sender = funded_sender();
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    receiver.block_on(receiver.wallet.refresh()).unwrap();
    let (wallet, peer) = reopened(&sender, true);
    let calls = sender.harness.node.calls().len();

    let (tx_id, s1) = send(&sender, &wallet, &peer);
    let s2 = receiver
        .receive(FILE, s1.as_text().unwrap(), None)
        .unwrap()
        .reply;
    let finalized = sender
        .harness
        .block_on(wallet.finalize(LOOPBACK, &s2, Propagation::Fluff))
        .unwrap();

    assert!(!finalized.pushed);
    assert_eq!(state(&sender, tx_id), TxState::Finalized);
    assert_eq!(
        sender.harness.node.calls().len(),
        calls,
        "an offline session called the node: {:?}",
        sender.harness.node.calls()
    );
    assert!(sender.harness.node.pushed_transactions().is_empty());
    Cold {
        sender,
        wallet,
        tx_id,
    }
}

#[test]
fn an_offline_session_sends_and_finalizes_without_calling_the_node() {
    cold_payment();
}

#[test]
fn the_finished_payment_is_the_stored_s3_as_legacy_v3_text() {
    let cold = cold_payment();

    let finished = cold
        .sender
        .harness
        .block_on(cold.wallet.finished_payment(cold.tx_id))
        .unwrap();

    let slate = send_support::legacy_codecs().decode(&finished).unwrap();
    assert_eq!(slate.stage(), Stage::S3);
    assert_eq!(slate.amount(), Amount::new(AMOUNT));
    assert!(slate.kernel().is_some());
    let text = finished.as_text().unwrap();
    let json: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(json["version_info"]["version"], 3);
    let parts = lepic_slate::ur_slate::encode_ur_slate(text, 200).unwrap();
    let decoded = lepic_slate::ur_slate::decode_ur_slate(&parts).unwrap();
    assert_eq!(decoded.json.as_deref(), Some(text));
}

#[test]
fn a_send_without_a_finished_payment_has_none() {
    let sender = funded_sender();
    let (wallet, peer) = reopened(&sender, true);
    let (tx_id, _) = send(&sender, &wallet, &peer);

    let error = sender
        .harness
        .block_on(wallet.finished_payment(tx_id))
        .unwrap_err();

    assert!(
        matches!(
            error,
            lepic_wallet::FinalizeError::NotPostable {
                state: TxState::Sent,
                ..
            }
        ),
        "{error:?}"
    );
}

#[test]
fn an_offline_session_without_a_confirmed_tip_refuses_to_send() {
    let sender = Sender::new();
    let (wallet, _peer) = reopened(&sender, true);
    let calls = sender.harness.node.calls().len();

    let error = sender
        .harness
        .block_on(wallet.send(
            request(),
            Delivery::Deliver {
                transport: LOOPBACK,
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap_err();

    assert!(
        matches!(error, SendError::Node(NodeError::Offline)),
        "{error:?}"
    );
    assert_eq!(sender.harness.node.calls().len(), calls);
}

#[test]
fn an_online_session_asks_the_node_and_posts_as_before() {
    let sender = funded_sender();
    let receiver = Receiver::new(RECEIVER_MNEMONIC, TIP);
    receiver.block_on(receiver.wallet.refresh()).unwrap();
    let (wallet, peer) = reopened(&sender, false);
    let calls = sender.harness.node.calls().len();

    let (tx_id, s1) = send(&sender, &wallet, &peer);
    assert!(sender.harness.node.calls().len() > calls);
    let s2 = receiver
        .receive(FILE, s1.as_text().unwrap(), None)
        .unwrap()
        .reply;
    let finalized = sender
        .harness
        .block_on(wallet.finalize(LOOPBACK, &s2, Propagation::Fluff))
        .unwrap();

    assert!(finalized.pushed);
    assert_eq!(state(&sender, tx_id), TxState::Posted);
    assert_eq!(sender.harness.node.pushed_transactions().len(), 1);
}

#[test]
fn a_later_online_session_confirms_the_cold_payment_once_its_kernel_is_on_chain() {
    let cold = cold_payment();
    let finished = cold
        .sender
        .harness
        .block_on(cold.wallet.finished_payment(cold.tx_id))
        .unwrap();
    // Another device posted it, and a miner included it.
    mine(&cold.sender, &final_transaction(&finished), TIP + 1);
    let (online, _peer) = reopened(&cold.sender, false);

    refreshed(&cold.sender.harness, &online);

    assert_eq!(state(&cold.sender, cold.tx_id), TxState::Confirmed);
}

fn final_transaction(finished: &WireSlate) -> Transaction {
    let slate = send_support::legacy_codecs().decode(finished).unwrap();
    let kernel = slate.kernel().unwrap();
    Transaction::new(
        slate.offset().clone(),
        lepic_primitives::tx::TransactionBody::new(
            slate.inputs().to_vec(),
            slate.outputs().to_vec(),
            vec![kernel],
        ),
    )
}

/// A miner includes `transaction` at `height`: its inputs are spent, its outputs and kernel
/// are on chain, and the tip moves there.
fn mine(sender: &Sender, transaction: &Transaction, height: u64) {
    sender.harness.node.update_chain(|chain| {
        for output in &mut chain.outputs {
            if transaction
                .inputs()
                .iter()
                .any(|input| input.commitment == output.commitment)
            {
                output.spent = true;
            }
        }
        for (position, output) in transaction.outputs().iter().enumerate() {
            chain.outputs.push(ChainOutput {
                commitment: output.commitment,
                features: output.features,
                proof: output.proof.clone(),
                height: Height::new(height),
                mmr_index: 100 + position as u64,
                spent: false,
            });
        }
        chain.kernels.push(LocatedKernel {
            kernel: transaction.kernels()[0],
            height: Height::new(height),
            mmr_index: 100,
        });
        chain.tip.height = Height::new(height);
    });
}
