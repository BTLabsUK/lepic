// SPDX-License-Identifier: Apache-2.0
//! A restore from a start height: which scans complete it, where its key counters end up, and
//! how the scans after it read outputs below and above the start.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod scan_support;
mod support;

use lepic_keychain::proof::create_output;
use lepic_keychain::{Identifier, Keychain, ProofBuilder, SwitchCommitment};
use lepic_node::mock::ChainOutput;
use lepic_primitives::amount::Height;
use lepic_primitives::params::Network;
use lepic_store::{AccountIndex, AccountRecord, WalletStore};
use lepic_wallet::WalletError;
use lepic_wallet::account::next_output_key;
use lepic_wallet::legacy_history::TxOrigin;
use lepic_wallet::scan::{ScanCancel, ScanOptions, ScanStart};
use scan_support::{PASSWORD, full_scan_vector, snapshot, store};
use support::both_stores;
use support::{Harness, TestWallet, password};

const TIP: u64 = 300;
const START: Height = Height::new(250);
/// How far a restore from a start height keeps its counter from the keys it found.
const GAP: u32 = 1 << 20;
const DEFAULT: AccountIndex = AccountIndex(0);
/// The default account's key counter after the restore, inside the range installs draw from.
const COUNTER: u32 = 1 << 24;

struct Restored {
    harness: Harness,
    wallet: TestWallet,
    keychain: Keychain,
}

impl Restored {
    /// A wallet restored from the vector's phrase with `scan_from`, not scanned, with its key
    /// counter at [`COUNTER`], over a chain at [`TIP`] with no outputs.
    fn from(scan_from: Height) -> Self {
        let phrase = full_scan_vector()["inputs"]["subject"]["mnemonic"]
            .as_str()
            .unwrap()
            .to_owned();
        let harness = Harness::new();
        harness
            .node
            .update_chain(|state| state.tip.height = Height::new(TIP));
        let wallet = harness.wallet();
        harness
            .block_on(wallet.restore_from_height(password(PASSWORD), &phrase, scan_from))
            .unwrap();
        store(&harness)
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    next_child: COUNTER,
                    ..repos.account(DEFAULT)?.unwrap()
                })
            })
            .unwrap();
        Self {
            keychain: Keychain::from_mnemonic(&phrase, Network::Mainnet).unwrap(),
            harness,
            wallet,
        }
    }

    /// Puts outputs of the default account's keys on chain, as `(child, height)`, in place of
    /// those there.
    fn put_outputs(&self, outputs: &[(u32, u64)]) {
        let keychain = &self.keychain;
        let mut chain: Vec<ChainOutput> = outputs
            .iter()
            .map(|(child, height)| chain_output(keychain, *child, *height))
            .collect();
        chain.sort_by_key(|output| output.mmr_index);
        self.harness
            .node
            .update_chain(|state| state.outputs = chain);
    }

    fn scan_from(&self, start: ScanStart) -> u64 {
        let options = ScanOptions {
            start,
            ..ScanOptions::restore(Network::Mainnet)
        };
        self.harness
            .block_on(self.wallet.scan(options, &ScanCancel::new()))
            .unwrap()
            .restored
    }

    fn setting(&self, name: &str) -> Option<String> {
        store(&self.harness)
            .read(|repos| repos.setting(name))
            .unwrap()
    }

    fn next_key(&self) -> Result<Identifier, WalletError> {
        store(&self.harness).write(|repos| next_output_key(repos, DEFAULT))
    }

    fn counter_now(&self) -> u32 {
        snapshot(&self.harness).accounts[0].next_child
    }

    fn origin_at(&self, height: u64) -> TxOrigin {
        self.harness
            .block_on(self.wallet.transactions(DEFAULT))
            .unwrap()
            .into_iter()
            .find(|details| details.confirmed_height == Some(Height::new(height)))
            .unwrap_or_else(|| panic!("no transaction confirmed at {height}"))
            .origin
    }
}

/// An output of `m/0/0/<child>` at `height`, which is also its output index.
fn chain_output(keychain: &Keychain, child: u32, height: u64) -> ChainOutput {
    let key_id = Identifier::new(3, [0, 0, child, 0]).unwrap();
    let output = create_output(
        keychain,
        &ProofBuilder::new(keychain).unwrap(),
        1_000_000,
        &key_id,
        SwitchCommitment::Regular,
    )
    .unwrap();
    ChainOutput {
        commitment: output.commitment,
        features: output.features,
        proof: output.proof,
        height: Height::new(height),
        mmr_index: height,
        spent: false,
    }
}

both_stores!(a_scan_from_the_start_height_completes_a_restore_from_that_height);
fn a_scan_from_the_start_height_completes_a_restore_from_that_height() {
    let restored = Restored::from(START);
    let found = COUNTER + 3;
    restored.put_outputs(&[(found, 260)]);
    assert_eq!(
        restored.setting("wallet.restore_scan_required").as_deref(),
        Some("250")
    );
    assert_eq!(restored.wallet.restore_scan_start().unwrap(), Some(START));
    assert!(matches!(
        restored.next_key(),
        Err(WalletError::RestoreScanRequired)
    ));

    assert_eq!(restored.scan_from(ScanStart::Height(START)), 1);

    assert!(!restored.wallet.restore_scan_required().unwrap());
    assert_eq!(restored.wallet.restore_scan_start().unwrap(), None);
    assert_eq!(
        restored.setting("scan.restore_completed_from").as_deref(),
        Some("250")
    );
    assert_eq!(restored.setting("scan.genesis_completed"), None);
    assert_eq!(restored.counter_now(), found + 1 + GAP);
    assert_eq!(
        restored.next_key().unwrap().to_bip32_path(),
        format!("m/0/0/{}", found + 1 + GAP)
    );
}

both_stores!(a_scan_from_above_the_start_height_leaves_the_restore_pending);
fn a_scan_from_above_the_start_height_leaves_the_restore_pending() {
    let restored = Restored::from(START);
    restored
        .harness
        .block_on(restored.wallet.refresh_scan())
        .unwrap();
    assert_eq!(restored.wallet.last_scanned_block().unwrap(), None);

    restored.scan_from(ScanStart::Height(Height::new(251)));

    assert!(restored.wallet.restore_scan_required().unwrap());
    assert_eq!(restored.wallet.restore_scan_start().unwrap(), Some(START));
    assert_eq!(restored.setting("scan.restore_completed_from"), None);
    assert!(matches!(
        restored.next_key(),
        Err(WalletError::RestoreScanRequired)
    ));

    restored.scan_from(ScanStart::Height(Height::new(200)));

    assert!(!restored.wallet.restore_scan_required().unwrap());
    assert_eq!(
        restored.setting("scan.restore_completed_from").as_deref(),
        Some("200")
    );
    restored.next_key().unwrap();
}

both_stores!(
    an_updated_wallet_whose_restore_waits_for_genesis_stays_pending_after_a_scan_from_a_height
);
fn an_updated_wallet_whose_restore_waits_for_genesis_stays_pending_after_a_scan_from_a_height() {
    let restored = Restored::from(START);
    // The value a restore made by LEPIC 26.10.25 left.
    store(&restored.harness)
        .write(|repos| repos.put_setting("wallet.restore_scan_required", "true"))
        .unwrap();
    assert_eq!(
        restored.wallet.restore_scan_start().unwrap(),
        Some(Height::ZERO)
    );

    restored.scan_from(ScanStart::Height(START));

    assert!(restored.wallet.restore_scan_required().unwrap());
    assert_eq!(
        restored.wallet.restore_scan_start().unwrap(),
        Some(Height::ZERO)
    );
    assert_eq!(restored.setting("scan.restore_completed_from"), None);
    assert!(matches!(
        restored.next_key(),
        Err(WalletError::RestoreScanRequired)
    ));

    restored.scan_from(ScanStart::Genesis);

    assert!(!restored.wallet.restore_scan_required().unwrap());
    assert_eq!(
        restored.setting("scan.genesis_completed").as_deref(),
        Some("1")
    );
}

both_stores!(a_restore_from_genesis_completes_as_before);
fn a_restore_from_genesis_completes_as_before() {
    let restored = Restored::from(Height::ZERO);
    let found = COUNTER + 3;
    restored.put_outputs(&[(found, 260)]);
    assert_eq!(
        restored.setting("wallet.restore_scan_required").as_deref(),
        Some("true")
    );

    assert_eq!(restored.scan_from(ScanStart::Genesis), 1);

    assert!(!restored.wallet.restore_scan_required().unwrap());
    assert_eq!(
        restored.setting("scan.genesis_completed").as_deref(),
        Some("1")
    );
    assert_eq!(restored.setting("scan.restore_completed_from"), None);
    assert_eq!(
        restored.counter_now(),
        found + 1,
        "only a restore from a start height keeps a gap"
    );
}

#[test]
fn a_restore_from_a_height_moves_its_counter_past_found_keys_below_and_above_it() {
    let restored = Restored::from(START);
    let below = COUNTER - 7;
    let chained = below + 1 + GAP + 10;
    let far = COUNTER - GAP - 1;
    restored.put_outputs(&[(far, 255), (below, 260), (chained, 270)]);

    assert_eq!(restored.scan_from(ScanStart::Height(START)), 3);

    assert_eq!(restored.counter_now(), chained + 1 + GAP);
}

both_stores!(
    an_update_after_a_restore_from_a_height_reads_only_outputs_above_it_as_received_elsewhere
);
fn an_update_after_a_restore_from_a_height_reads_only_outputs_above_it_as_received_elsewhere() {
    let restored = Restored::from(START);
    let old = 5;
    restored.put_outputs(&[(old, 220)]);
    restored.scan_from(ScanStart::Height(START));
    restored
        .harness
        .node
        .update_chain(|state| state.tip.height = Height::new(TIP + 20));
    restored.put_outputs(&[(old, 220), (COUNTER + 5 * GAP, 310)]);

    restored
        .harness
        .block_on(restored.wallet.refresh_scan())
        .unwrap();

    assert_eq!(
        restored
            .wallet
            .last_scanned_block()
            .unwrap()
            .unwrap()
            .height,
        Height::new(TIP + 20)
    );
    assert_eq!(restored.origin_at(220), TxOrigin::FoundByScan);
    assert_eq!(restored.origin_at(310), TxOrigin::OtherWallet);
}

#[test]
fn a_pending_restore_value_that_is_not_a_height_needs_a_scan_from_genesis() {
    let restored = Restored::from(START);
    store(&restored.harness)
        .write(|repos| repos.put_setting("wallet.restore_scan_required", "+250"))
        .unwrap();

    assert_eq!(
        restored.wallet.restore_scan_start().unwrap(),
        Some(Height::ZERO)
    );
}
