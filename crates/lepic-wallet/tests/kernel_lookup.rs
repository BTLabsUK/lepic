// SPDX-License-Identifier: Apache-2.0
//! `Wallet::kernel_on_chain`: where the chain holds a kernel, `None` when it holds none in the
//! range, and a refusal in an offline session before any node call.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;

use std::path::PathBuf;

use lepic_crypto::Commitment;
use lepic_node::{LocatedKernel, NodeError};
use lepic_primitives::amount::Height;
use lepic_primitives::params::Network;
use lepic_primitives::ser::ProtocolVersion;
use lepic_primitives::tx::Transaction;
use lepic_wallet::refresh::KernelLocation;
use lepic_wallet::{WalletConfig, WalletError};
use support::Harness;

const KERNEL_HEIGHT: u64 = 7;
const KERNEL_INDEX: u64 = 31;

fn transaction() -> Transaction {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors/primitives/tx_valid_plain_1_in_2_out.json");
    let vector: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = vector["expected"]["serialized_v2"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect();
    Transaction::decode(&bytes, ProtocolVersion::V2).unwrap()
}

/// A harness whose chain holds the kernel of [`transaction`], and that kernel's excess.
fn harness_with_kernel() -> (Harness, Commitment) {
    let harness = Harness::new();
    let kernel = transaction().kernels()[0];
    harness.node.update_chain(|chain| {
        chain.kernels.push(LocatedKernel {
            kernel,
            height: Height::new(KERNEL_HEIGHT),
            mmr_index: KERNEL_INDEX,
        });
    });
    (harness, kernel.excess)
}

#[test]
fn finds_a_kernel_on_chain() {
    let (harness, excess) = harness_with_kernel();
    let wallet = harness.wallet();

    let found = harness
        .block_on(wallet.kernel_on_chain(&excess, None))
        .unwrap();

    assert_eq!(
        found,
        Some(KernelLocation {
            height: Height::new(KERNEL_HEIGHT),
            mmr_index: KERNEL_INDEX,
        })
    );
}

#[test]
fn an_absent_kernel_is_none() {
    let (harness, _) = harness_with_kernel();
    let wallet = harness.wallet();
    let other = transaction().outputs()[0].commitment;

    let found = harness
        .block_on(wallet.kernel_on_chain(&other, None))
        .unwrap();

    assert_eq!(found, None);
}

#[test]
fn the_minimum_height_is_respected() {
    let (harness, excess) = harness_with_kernel();
    let wallet = harness.wallet();

    let at = harness
        .block_on(wallet.kernel_on_chain(&excess, Some(Height::new(KERNEL_HEIGHT))))
        .unwrap();
    let above = harness
        .block_on(wallet.kernel_on_chain(&excess, Some(Height::new(KERNEL_HEIGHT + 1))))
        .unwrap();

    assert_eq!(at.map(|location| location.mmr_index), Some(KERNEL_INDEX));
    assert_eq!(above, None);
}

#[test]
fn an_offline_session_is_refused_without_a_node_call() {
    let (harness, excess) = harness_with_kernel();
    let config = WalletConfig {
        offline: true,
        ..harness.config(Network::Mainnet)
    };
    let wallet = harness.wallet_with(config, harness.vault.clone());
    let calls = harness.node.calls().len();

    let error = harness
        .block_on(wallet.kernel_on_chain(&excess, None))
        .unwrap_err();

    assert!(
        matches!(error, WalletError::Node(NodeError::Offline)),
        "{error:?}"
    );
    assert_eq!(harness.node.calls().len(), calls);
}
