// SPDX-License-Identifier: Apache-2.0
//! A TTL on a send whose format has no TTL field, the legacy V2 shape a stock Epicbox receiver
//! gets: the slate goes out without it, the wallet keeps the cutoff as the send's local cutoff,
//! and a refresh at that height expires the unanswered send and frees its inputs, also after a
//! restart. An answer that arrives after that is refused.

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

use std::sync::{Arc, PoisonError};

use lepic_crypto::RangeProof;
use lepic_legacy_slate::v2_json::V2JsonCodec;
use lepic_node::Propagation;
use lepic_node::mock::ChainOutput;
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, EncodeContext, WireSlate};
use lepic_store::{OutputRecord, OutputStatus, TxId, TxState};
use lepic_transport::file::FILE;
use lepic_transport::transport::Destination;
use lepic_wallet::finalize::FinalizeError;
use lepic_wallet::refresh::{RefreshOutcome, RefreshSummary};
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{Delivery, SendRequest, SentSlate};
use receive_harness::Receiver;
use send_support::{ACCOUNT, PEER, Sender, TIP, V2Only, legacy_codecs, uuid};
use support::{TestWallet, both_stores, password};

const AMOUNT: u64 = 100_000_000;
const TTL_BLOCKS: u64 = 5;

/// The receiver of the G-03 cases.
const RECEIVER_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
    thank year wave sausage worth useful legal winner thank year wave sausage worth title";

fn request(ttl_blocks: Option<u64>, local_ttl_blocks: Option<u64>) -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ttl_blocks,
        local_ttl_blocks,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

/// A sender whose transport sends new slates in the V2 shape, with its funding output on chain.
fn funded() -> (Sender, OutputRecord) {
    let sender = Sender::with_policy(Arc::new(V2Only));
    let funding = sender.outputs().remove(0);
    sender.harness.node.update_chain(|chain| {
        chain.outputs.push(ChainOutput {
            commitment: funding.id.commitment,
            features: funding.id.features,
            height: Height::new(1),
            mmr_index: 1,
            // `get_outputs` answers do not carry proofs, so any proof bytes do.
            proof: RangeProof::from_bytes(&[1; 64]).unwrap(),
            spent: false,
        });
    });
    (sender, funding)
}

fn send(sender: &Sender, request: SendRequest) -> SentSlate {
    sender
        .harness
        .block_on(sender.wallet.send(
            &sender.harness.method(),
            request,
            Delivery::Deliver {
                to: Destination::new(PEER.to_owned()),
            },
        ))
        .unwrap()
}

fn set_tip(sender: &Sender, height: u64) {
    sender
        .harness
        .node
        .update_chain(|chain| chain.tip.height = Height::new(height));
}

fn refresh(wallet: &TestWallet, sender: &Sender) -> RefreshSummary {
    match sender.harness.block_on(wallet.refresh()).unwrap() {
        RefreshOutcome::Refreshed(summary) => summary,
        other @ RefreshOutcome::NodeBehind { .. } => panic!("refresh did not apply: {other:?}"),
    }
}

fn state(sender: &Sender, tx_id: TxId) -> TxState {
    sender.read(|repos| repos.transaction(tx_id)).unwrap().state
}

fn local_cutoff(sender: &Sender, tx_id: TxId) -> Option<Height> {
    sender.read(|repos| repos.tx_marks(tx_id)).local_cutoff
}

fn status(sender: &Sender, record: &OutputRecord) -> Option<OutputStatus> {
    sender
        .read(|repos| repos.output(record.commitment()))
        .map(|output| output.status)
}

/// The change output of the only send.
fn change(sender: &Sender, funding: &OutputRecord) -> OutputRecord {
    sender
        .outputs()
        .into_iter()
        .find(|output| output.id != funding.id)
        .unwrap()
}

/// The S2 a LEPIC receiver answers `s1` with, in the V2 shape a stock Epicbox peer returns.
fn v2_reply(s1: &WireSlate) -> WireSlate {
    let reply = Receiver::new(RECEIVER_MNEMONIC, TIP)
        .receive(FILE, s1.as_text().unwrap(), None)
        .unwrap()
        .reply;
    let s2 = legacy_codecs().decode(&reply).unwrap();
    V2JsonCodec::new(Network::Floonet.params().default_base_fee())
        .encode(
            &s2,
            &EncodeContext {
                block_header_version: 6,
            },
        )
        .unwrap()
}

/// The sender's wallet opened again on the same data, as after an app restart.
fn restarted(sender: &Sender) -> TestWallet {
    sender.wallet.lock();
    let harness = &sender.harness;
    let wallet = harness.wallet_with(harness.config(Network::Floonet), harness.vault.clone());
    harness.block_on(wallet.open(password("sender"))).unwrap();
    drop(
        harness
            .peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(),
    );
    wallet
}

both_stores!(a_v2_send_keeps_its_ttl_out_of_the_slate_as_a_local_cutoff);
fn a_v2_send_keeps_its_ttl_out_of_the_slate_as_a_local_cutoff() {
    // The TTL alone, and with a local TTL on either side of it: the earlier height applies.
    for (ttl_blocks, local_ttl_blocks, cutoff) in [
        (TTL_BLOCKS, None, TTL_BLOCKS),
        (TTL_BLOCKS, Some(3), 3),
        (3, Some(TTL_BLOCKS), 3),
    ] {
        let (sender, _) = funded();
        let sent = send(&sender, request(Some(ttl_blocks), local_ttl_blocks));

        let (wire, slate) = sender.received().unwrap();
        assert!(wire.as_text().unwrap().starts_with(r#"{"version_info":{"version":2,"#));
        assert!(!wire.as_text().unwrap().contains("ttl_cutoff_height"));
        assert_eq!(slate.ttl_cutoff_height(), None);
        assert_eq!(
            local_cutoff(&sender, sent.tx_id),
            Some(Height::new(TIP + cutoff))
        );
        assert_eq!(state(&sender, sent.tx_id), TxState::Sent);
        assert_eq!(sender.transactions().len(), 1);
    }
}

both_stores!(an_unanswered_v2_send_waits_before_its_cutoff_and_expires_at_it);
fn an_unanswered_v2_send_waits_before_its_cutoff_and_expires_at_it() {
    let (sender, funding) = funded();
    let sent = send(&sender, request(Some(TTL_BLOCKS), None));
    let change = change(&sender, &funding);

    set_tip(&sender, TIP + TTL_BLOCKS - 1);
    assert_eq!(refresh(&sender.wallet, &sender).expired_transactions, 0);
    assert_eq!(state(&sender, sent.tx_id), TxState::Sent);
    assert_eq!(status(&sender, &funding), Some(OutputStatus::Locked));

    set_tip(&sender, TIP + TTL_BLOCKS);
    assert_eq!(refresh(&sender.wallet, &sender).expired_transactions, 1);
    assert_eq!(state(&sender, sent.tx_id), TxState::Expired);
    assert_eq!(status(&sender, &funding), Some(OutputStatus::Unspent));
    assert_eq!(status(&sender, &change), None);
    assert!(!sender.has_sender_context(uuid(sent.slate_id)));
}

both_stores!(an_answer_that_arrives_after_the_expiry_is_refused);
fn an_answer_that_arrives_after_the_expiry_is_refused() {
    let (sender, funding) = funded();
    let sent = send(&sender, request(Some(TTL_BLOCKS), None));
    let (s1, _) = sender.received().unwrap();
    let s2 = v2_reply(&s1);

    set_tip(&sender, TIP + TTL_BLOCKS);
    assert_eq!(refresh(&sender.wallet, &sender).expired_transactions, 1);

    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .finalize(&sender.harness.method(), &s2, Propagation::Stem),
        )
        .unwrap_err();
    assert!(
        matches!(
            error,
            FinalizeError::NotFinalizable { tx_id, state: TxState::Expired } if tx_id == sent.tx_id
        ),
        "{error:?}"
    );
    assert_eq!(state(&sender, sent.tx_id), TxState::Expired);
    assert_eq!(status(&sender, &funding), Some(OutputStatus::Unspent));
    assert!(sender.harness.node.pushed_transactions().is_empty());
}

both_stores!(an_answer_at_the_cutoff_before_a_refresh_is_refused);
fn an_answer_at_the_cutoff_before_a_refresh_is_refused() {
    let (sender, funding) = funded();
    let sent = send(&sender, request(Some(TTL_BLOCKS), None));
    let (s1, _) = sender.received().unwrap();
    let s2 = v2_reply(&s1);

    set_tip(&sender, TIP + TTL_BLOCKS);
    let error = sender
        .harness
        .block_on(
            sender
                .wallet
                .finalize(&sender.harness.method(), &s2, Propagation::Stem),
        )
        .unwrap_err();
    assert!(
        matches!(
            error,
            FinalizeError::Expired { cutoff, tip }
                if cutoff == Height::new(TIP + TTL_BLOCKS) && tip == Height::new(TIP + TTL_BLOCKS)
        ),
        "{error:?}"
    );
    assert_eq!(state(&sender, sent.tx_id), TxState::Sent);
    assert_eq!(status(&sender, &funding), Some(OutputStatus::Locked));
    assert!(sender.harness.node.pushed_transactions().is_empty());
}

both_stores!(an_answer_before_the_cutoff_is_finalized);
fn an_answer_before_the_cutoff_is_finalized() {
    let (sender, _) = funded();
    let sent = send(&sender, request(Some(TTL_BLOCKS), None));
    let (s1, _) = sender.received().unwrap();
    let s2 = v2_reply(&s1);

    set_tip(&sender, TIP + TTL_BLOCKS - 1);
    sender
        .harness
        .block_on(
            sender
                .wallet
                .finalize(&sender.harness.method(), &s2, Propagation::Stem),
        )
        .unwrap();
    assert_eq!(state(&sender, sent.tx_id), TxState::Posted);
    assert_eq!(sender.harness.node.pushed_transactions().len(), 1);
}

both_stores!(the_cutoff_holds_across_a_restart);
fn the_cutoff_holds_across_a_restart() {
    let (sender, funding) = funded();
    let sent = send(&sender, request(Some(TTL_BLOCKS), None));

    let wallet = restarted(&sender);
    assert_eq!(
        local_cutoff(&sender, sent.tx_id),
        Some(Height::new(TIP + TTL_BLOCKS))
    );

    set_tip(&sender, TIP + TTL_BLOCKS - 1);
    assert_eq!(refresh(&wallet, &sender).expired_transactions, 0);
    assert_eq!(state(&sender, sent.tx_id), TxState::Sent);
    assert_eq!(status(&sender, &funding), Some(OutputStatus::Locked));

    set_tip(&sender, TIP + TTL_BLOCKS);
    assert_eq!(refresh(&wallet, &sender).expired_transactions, 1);
    assert_eq!(state(&sender, sent.tx_id), TxState::Expired);
    assert_eq!(status(&sender, &funding), Some(OutputStatus::Unspent));
}
