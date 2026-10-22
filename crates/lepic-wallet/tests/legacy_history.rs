//! Import of an `epic-wallet` wallet's history (ADR 0019): the dates, kinds, amounts, messages
//! and links the old wallet's database gives the new wallet's log, how the scan reconciles them
//! with the chain, and the statuses of what cannot be imported.

// Tests may unwrap, index, panic and use plain arithmetic (docs/rules.md), including in helpers
// that clippy does not treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod legacy_support;
mod support;

use std::fs;
use std::path::Path;

use jiff::Timestamp;
use legacy_support::{
    ADDRESS_PIZZA, ADDRESS_RENT, MNEMONIC, OTHER_MNEMONIC, OldTx, OldWallet, SLATE_CREATED,
    SLATE_MISSING, SLATE_PIZZA, SLATE_POSTED, SLATE_RECEIVED, SLATE_RECEIVED_CANCELLED,
    SLATE_SAVINGS, SLATE_SENT, SLATE_SENT_CANCELLED, keychain, posted_excess, put_kernel,
    put_outputs, sent_excess, snapshot,
};
use lepic_keychain::Keychain;
use lepic_node::mock::MockFailure;
use lepic_primitives::amount::{Amount, Fee, Height};
use lepic_slate::role::Role;
use lepic_store::{AccountIndex, ChainCheck, ImportedKind, TxDirection, TxState};
use lepic_transport::transport::Destination;
use lepic_wallet::StoreOpener;
use lepic_wallet::details::{SlateMessage, TransactionDetails};
use lepic_wallet::legacy_history::{LegacyImportOutcome, LegacyImportStatus, TxOrigin};
use support::{Harness, TestWallet, fixed_time, password};
use tempfile::TempDir;
use uuid::Uuid;

const DEFAULT: AccountIndex = AccountIndex(0);
const SAVINGS: AccountIndex = AccountIndex(1);

/// An output of this seed the old wallet never knew: child 20, 3 M, mined at height 70.
const UNKNOWN: (u32, u32, u64, u64) = (0, 20, 3_000_000, 70);

struct World {
    harness: Harness,
    wallet: TestWallet,
    keychain: Keychain,
    source: TempDir,
}

impl World {
    /// A wallet restored from [`MNEMONIC`], not scanned, over a chain holding the outputs the
    /// old wallet still holds plus `extra`, and the old wallet's folder.
    fn new(old: &OldWallet, extra: &[(u32, u32, u64, u64)]) -> Self {
        let harness = Harness::new();
        let wallet = harness.wallet();
        harness
            .block_on(wallet.restore(password("import password"), MNEMONIC))
            .unwrap();
        let keychain = keychain(MNEMONIC);
        let mut on_chain = old.chain_outputs();
        on_chain.extend_from_slice(extra);
        put_outputs(&harness.node, &keychain, &on_chain);
        let source = tempfile::tempdir().unwrap();
        old.write(&keychain, source.path());
        Self {
            harness,
            wallet,
            keychain,
            source,
        }
    }

    fn import_from(&self, source: &Path) -> LegacyImportOutcome {
        let work = tempfile::tempdir().unwrap();
        self.harness
            .block_on(self.wallet.import_legacy_history(source, work.path()))
            .unwrap()
    }

    fn import(&self) -> LegacyImportOutcome {
        self.import_from(self.source.path())
    }

    fn scan(&self) {
        support::complete_restore_scan(&self.harness.runtime, &self.wallet);
    }

    fn txs(&self, account: AccountIndex) -> Vec<TransactionDetails> {
        self.harness
            .block_on(self.wallet.transactions(account))
            .unwrap()
    }

    fn tx(&self, account: AccountIndex, slate: &str) -> TransactionDetails {
        let slate = Uuid::parse_str(slate).unwrap();
        self.txs(account)
            .into_iter()
            .find(|d| d.transaction.entry.slate_id == Some(slate))
            .unwrap_or_else(|| panic!("no transaction with slate {slate}"))
    }

    fn total(&self, account: AccountIndex) -> Amount {
        self.wallet.balance(account).unwrap().total
    }

    fn labels(&self) -> Vec<(u32, String)> {
        self.wallet
            .accounts()
            .unwrap()
            .into_iter()
            .map(|account| (account.index.0, account.label))
            .collect()
    }

    fn store(&self) -> lepic_store::MemoryStore {
        self.harness
            .stores
            .open(
                &self.harness.data_dir,
                lepic_store::ContextKey::from_bytes([0; lepic_store::CONTEXT_KEY_LEN]),
            )
            .unwrap()
    }

    fn next_child(&self, account: AccountIndex) -> u32 {
        lepic_store::WalletStore::read(&self.store(), |repos| repos.account(account))
            .unwrap()
            .unwrap()
            .next_child
    }

    /// The time the scripted chain gives the block at `height`.
    fn block_time(&self, height: u64) -> Timestamp {
        let mut time = None;
        self.harness
            .node
            .update_chain(|chain| time = Some(chain.header_time(Height::new(height))));
        time.unwrap()
    }
}

fn time(text: &str) -> Timestamp {
    text.parse().unwrap()
}

fn message(role: Role, text: &str) -> SlateMessage {
    SlateMessage {
        role,
        text: text.to_owned(),
    }
}

fn check(details: &TransactionDetails) -> ChainCheck {
    details.imported.as_ref().unwrap().check
}

fn empty_dir() -> TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn import_before_the_scan_keeps_the_old_wallets_dates_kinds_amounts_and_slate_ids() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[UNKNOWN]);

    let outcome = world.import();

    assert_eq!(outcome.status, LegacyImportStatus::Imported);
    assert_eq!(outcome.transactions, 9);
    assert_eq!(outcome.outputs, 9);
    assert_eq!(outcome.skipped, 0);
    assert_eq!(outcome.accounts_named, 1);
    assert_eq!(outcome.linked, 0);
    assert_eq!(outcome.confirmed_by_kernel, 0);
    assert_eq!(world.txs(DEFAULT).len(), 8);

    let received = world.tx(DEFAULT, SLATE_RECEIVED);
    let entry = &received.transaction.entry;
    assert_eq!(entry.direction, TxDirection::Incoming);
    assert_eq!(entry.state, TxState::Confirmed);
    assert_eq!(entry.created_at, time("2024-03-01T10:20:30.123456789Z"));
    assert_eq!(entry.amount_credited, Amount::new(100_000_000));
    assert_eq!(entry.amount_debited, Amount::ZERO);
    assert_eq!(entry.fee, None);
    assert_eq!(received.confirmed_at, Some(time("2024-03-01T10:25:00Z")));
    assert_eq!(received.confirmed_height, Some(Height::new(10)));
    assert_eq!(received.counterparty, None, "\"Restore\" is not an address");
    assert_eq!(received.origin, TxOrigin::Imported);
    let imported = received.imported.unwrap();
    assert_eq!(imported.source_id, 0);
    assert_eq!(imported.kind, ImportedKind::Received);
    assert_eq!(imported.check, ChainCheck::Unchecked);

    let sent = world.tx(DEFAULT, SLATE_SENT);
    let entry = &sent.transaction.entry;
    assert_eq!(entry.direction, TxDirection::Outgoing);
    assert_eq!(entry.state, TxState::Confirmed);
    assert_eq!(entry.created_at, time("2024-03-02T09:00:01.5Z"));
    assert_eq!(entry.amount_debited, Amount::new(100_000_000));
    assert_eq!(entry.amount_credited, Amount::new(69_000_000));
    assert_eq!(entry.fee, Some(Fee::new(1_000_000)));
    assert_eq!(
        sent.counterparty,
        Some(Destination::new(ADDRESS_RENT.to_owned()))
    );
    assert_eq!(sent.kernel_excess, Some(sent_excess(&world.keychain)));
    assert_eq!(sent.ttl_cutoff_height, Some(Height::new(500)));
    assert_eq!(sent.imported.unwrap().kind, ImportedKind::Sent);
    assert_eq!(
        sent.messages,
        [
            message(Role::Sender, "rent for march"),
            message(Role::Receiver, "thanks")
        ]
    );

    let pizza = world.tx(DEFAULT, SLATE_PIZZA);
    assert_eq!(
        pizza.counterparty,
        Some(Destination::new(ADDRESS_PIZZA.to_owned()))
    );
    assert_eq!(
        pizza.messages,
        [message(Role::Sender, "for the pizza")],
        "the message whose signature does not verify is left out"
    );

    let received_cancelled = world.tx(DEFAULT, SLATE_RECEIVED_CANCELLED);
    assert_eq!(
        received_cancelled.transaction.entry.state,
        TxState::Cancelled
    );
    assert_eq!(
        received_cancelled.transaction.entry.direction,
        TxDirection::Incoming
    );
    assert_eq!(
        received_cancelled.imported.unwrap().kind,
        ImportedKind::ReceivedCancelled
    );
    let sent_cancelled = world.tx(DEFAULT, SLATE_SENT_CANCELLED);
    assert_eq!(sent_cancelled.transaction.entry.state, TxState::Cancelled);
    assert_eq!(
        sent_cancelled.transaction.entry.direction,
        TxDirection::Outgoing
    );

    let posted = world.tx(DEFAULT, SLATE_POSTED);
    assert_eq!(posted.transaction.entry.state, TxState::Posted);
    assert_eq!(posted.kernel_excess, Some(posted_excess(&world.keychain)));
    assert_eq!(posted.ttl_cutoff_height, Some(Height::new(900)));
    let created = world.tx(DEFAULT, SLATE_CREATED);
    assert_eq!(created.transaction.entry.state, TxState::Sent);
    assert_eq!(created.kernel_excess, None);

    let savings = world.txs(SAVINGS);
    assert_eq!(savings.len(), 1);
    assert_eq!(
        savings[0].transaction.entry.slate_id,
        Some(Uuid::parse_str(SLATE_SAVINGS).unwrap())
    );
    assert_eq!(savings[0].origin, TxOrigin::Imported);

    assert_eq!(
        world.total(DEFAULT),
        Amount::ZERO,
        "an import creates no funds: only the scan does"
    );
}

#[test]
fn the_scan_after_an_import_links_found_outputs_to_the_imported_entries() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[UNKNOWN]);
    world.import();

    world.scan();

    let sent = world.tx(DEFAULT, SLATE_SENT);
    assert_eq!(sent.transaction.entry.state, TxState::Confirmed);
    assert_eq!(sent.confirmed_height, Some(Height::new(20)));
    assert_eq!(check(&sent), ChainCheck::OnChain);
    let pizza = world.tx(DEFAULT, SLATE_PIZZA);
    assert_eq!(pizza.confirmed_height, Some(Height::new(30)));
    assert_eq!(check(&pizza), ChainCheck::OnChain);
    let savings = world.tx(SAVINGS, SLATE_SAVINGS);
    assert_eq!(savings.confirmed_height, Some(Height::new(50)));
    assert_eq!(check(&savings), ChainCheck::OnChain);

    let default = world.txs(DEFAULT);
    let found: Vec<_> = default
        .iter()
        .filter(|d| d.origin == TxOrigin::FoundByScan)
        .collect();
    assert_eq!(found.len(), 1, "only the output the old wallet never knew");
    assert_eq!(
        found[0].transaction.entry.amount_credited,
        Amount::new(3_000_000)
    );
    assert_eq!(found[0].transaction.entry.created_at, world.block_time(70));
    assert_eq!(default.len(), 9);
    assert_eq!(world.txs(SAVINGS).len(), 1);
    assert_eq!(
        world.total(DEFAULT),
        Amount::new(69_000_000 + 50_000_000 + 3_000_000),
        "the balance is the chain's outputs only"
    );
    assert_eq!(world.total(SAVINGS), Amount::new(25_000_000));
}

#[test]
fn import_after_the_scan_moves_outputs_to_imported_entries_and_dates_the_rest_by_block() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[UNKNOWN]);
    world.scan();
    let before = world.txs(DEFAULT);
    assert_eq!(before.len(), 3, "a scan-found entry per output");
    assert!(before.iter().all(|d| d.origin == TxOrigin::FoundByScan));
    assert!(world.labels().contains(&(1, "account_1".to_owned())));
    let total_before = (world.total(DEFAULT), world.total(SAVINGS));
    // An older build dated these entries by the scan, not by their block.
    rewrite_creation_times(&world, fixed_time());

    let outcome = world.import();

    assert_eq!(outcome.status, LegacyImportStatus::Imported);
    assert_eq!(outcome.linked, 3);
    assert_eq!(outcome.dated, 1);
    let default = world.txs(DEFAULT);
    assert_eq!(
        default.len(),
        9,
        "8 imported entries and the unknown output's"
    );
    let found: Vec<_> = default
        .iter()
        .filter(|d| d.origin == TxOrigin::FoundByScan)
        .collect();
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].transaction.entry.amount_credited,
        Amount::new(3_000_000)
    );
    assert_eq!(found[0].transaction.entry.created_at, world.block_time(70));
    let sent = world.tx(DEFAULT, SLATE_SENT);
    assert_eq!(sent.origin, TxOrigin::Imported);
    assert_eq!(
        sent.transaction.entry.created_at,
        time("2024-03-02T09:00:01.5Z")
    );
    assert_eq!(sent.confirmed_height, Some(Height::new(20)));
    assert_eq!(check(&sent), ChainCheck::OnChain);
    assert_eq!(world.txs(SAVINGS).len(), 1);
    assert_eq!(world.tx(SAVINGS, SLATE_SAVINGS).origin, TxOrigin::Imported);
    assert_eq!(
        (world.total(DEFAULT), world.total(SAVINGS)),
        total_before,
        "the import does not move money"
    );
}

/// Sets the creation time of every entry the wallet holds, as a scan of an older build left them.
fn rewrite_creation_times(world: &World, at: Timestamp) {
    lepic_store::WalletStore::write(&world.store(), |repos| {
        for account in [DEFAULT, SAVINGS] {
            for stored in repos.transactions(account)? {
                let mut entry = stored.entry;
                entry.created_at = at;
                entry.updated_at = at;
                repos.update_transaction(stored.id, &entry)?;
            }
        }
        Ok::<_, lepic_store::StoreError>(())
    })
    .unwrap();
}

#[test]
fn an_output_of_a_cancelled_entry_on_chain_confirms_it_and_records_the_contradiction() {
    let mut old = OldWallet::standard(&keychain(MNEMONIC));
    old.output_mut(0, 3).on_chain = true;
    old.output_mut(0, 4).on_chain = true;
    let world = World::new(&old, &[]);
    world.import();

    world.scan();

    for (slate, height) in [(SLATE_RECEIVED_CANCELLED, 40), (SLATE_SENT_CANCELLED, 45)] {
        let entry = world.tx(DEFAULT, slate);
        assert_eq!(entry.transaction.entry.state, TxState::Confirmed, "{slate}");
        assert_eq!(check(&entry), ChainCheck::CancelledButOnChain, "{slate}");
        assert_eq!(entry.confirmed_height, Some(Height::new(height)), "{slate}");
    }
}

#[test]
fn an_unspent_output_the_chain_lacks_is_flagged_and_not_counted_after_a_genesis_scan() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    world.import();
    assert_eq!(
        check(&world.tx(DEFAULT, SLATE_MISSING)),
        ChainCheck::Unchecked
    );

    world.scan();

    let missing = world.tx(DEFAULT, SLATE_MISSING);
    assert_eq!(check(&missing), ChainCheck::UnspentNotOnChain);
    assert_eq!(missing.transaction.entry.state, TxState::Confirmed);
    assert_eq!(
        world.total(DEFAULT),
        Amount::new(69_000_000 + 50_000_000),
        "the 11 M output the old wallet held is not on chain"
    );
}

#[test]
fn an_unspent_output_the_chain_lacks_is_flagged_when_the_scan_ran_before_the_import() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    world.scan();

    world.import();

    assert_eq!(
        check(&world.tx(DEFAULT, SLATE_MISSING)),
        ChainCheck::UnspentNotOnChain
    );
}

#[test]
fn a_pending_send_whose_kernel_the_node_holds_is_confirmed_by_kernel() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    put_kernel(&world.harness.node, posted_excess(&world.keychain), 80);

    let outcome = world.import();

    assert_eq!(outcome.confirmed_by_kernel, 1);
    let posted = world.tx(DEFAULT, SLATE_POSTED);
    assert_eq!(posted.transaction.entry.state, TxState::Confirmed);
    assert_eq!(posted.confirmed_height, Some(Height::new(80)));
    assert_eq!(check(&posted), ChainCheck::OnChain);
    let created = world.tx(DEFAULT, SLATE_CREATED);
    assert_eq!(
        created.transaction.entry.state,
        TxState::Sent,
        "a send without a kernel stays open"
    );
}

#[test]
fn a_folder_without_a_database_is_no_history() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    let folder = empty_dir();

    let outcome = world.import_from(folder.path());

    assert_eq!(outcome.status, LegacyImportStatus::NoHistory);
    assert!(world.txs(DEFAULT).is_empty());
}

#[test]
fn an_lmdb_wallet_is_an_old_format() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    let folder = empty_dir();
    fs::create_dir_all(folder.path().join("wallet_data/db/lmdb")).unwrap();
    fs::write(
        folder.path().join("wallet_data/db/lmdb/data.mdb"),
        [0_u8; 4096],
    )
    .unwrap();

    let outcome = world.import_from(folder.path());

    assert_eq!(outcome.status, LegacyImportStatus::OldFormat);
    assert!(world.txs(DEFAULT).is_empty());
}

#[test]
fn a_garbage_database_is_unreadable() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    let folder = empty_dir();
    let sqlite = folder.path().join("wallet_data/db/sqlite");
    fs::create_dir_all(&sqlite).unwrap();
    fs::write(sqlite.join("epic.db"), vec![0x5a_u8; 8192]).unwrap();

    let outcome = world.import_from(folder.path());

    assert_eq!(outcome.status, LegacyImportStatus::Unreadable);
    assert!(world.txs(DEFAULT).is_empty());
}

#[test]
fn a_history_made_by_another_seed_is_refused_and_stores_nothing() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    let other = keychain(OTHER_MNEMONIC);
    let folder = empty_dir();
    OldWallet::standard(&other).write(&other, folder.path());

    let outcome = world.import_from(folder.path());

    assert_eq!(outcome.status, LegacyImportStatus::OtherWallet);
    assert_eq!(outcome.transactions, 0);
    assert!(world.txs(DEFAULT).is_empty());
    assert_eq!(world.labels(), [(0, "default".to_owned())]);
    // Nothing was remembered: the right history still imports.
    assert_eq!(world.import().status, LegacyImportStatus::Imported);
}

#[test]
fn importing_the_same_history_twice_adds_no_entries() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[UNKNOWN]);
    world.import();
    world.scan();
    let before = (world.txs(DEFAULT).len(), world.txs(SAVINGS).len());

    let outcome = world.import();

    assert_eq!(outcome.status, LegacyImportStatus::AlreadyImported);
    assert_eq!(outcome.transactions, 0);
    assert_eq!((world.txs(DEFAULT).len(), world.txs(SAVINGS).len()), before);
    assert_eq!(before, (9, 1));
}

#[test]
fn a_different_history_after_an_import_is_refused() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    world.import();
    let mut changed = OldWallet::standard(&world.keychain);
    changed.tx_mut(0, 2).credited = 50_000_001;
    let folder = empty_dir();
    changed.write(&world.keychain, folder.path());

    let outcome = world.import_from(folder.path());

    assert_eq!(outcome.status, LegacyImportStatus::OtherHistory);
    assert_eq!(outcome.transactions, 0);
    assert_eq!(world.txs(DEFAULT).len(), 8);
    assert_eq!(
        world
            .tx(DEFAULT, SLATE_PIZZA)
            .transaction
            .entry
            .amount_credited,
        Amount::new(50_000_000)
    );
}

#[test]
fn an_account_the_wallet_lacks_is_created_with_the_old_label() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);

    world.import();

    assert_eq!(
        world.labels(),
        [(0, "default".to_owned()), (1, "savings".to_owned())]
    );
}

#[test]
fn a_label_a_scan_generated_is_renamed_to_the_old_label() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    world.scan();
    assert!(world.labels().contains(&(1, "account_1".to_owned())));

    let outcome = world.import();

    assert_eq!(outcome.accounts_named, 1);
    assert_eq!(
        world.labels(),
        [(0, "default".to_owned()), (1, "savings".to_owned())]
    );
}

#[test]
fn a_label_the_user_chose_is_kept() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    world.wallet.create_account("my stash").unwrap();

    world.import();

    assert_eq!(
        world.labels(),
        [(0, "default".to_owned()), (1, "my stash".to_owned())]
    );
    assert_eq!(world.txs(SAVINGS).len(), 1, "its history still lands there");
}

#[test]
fn key_counters_move_past_every_key_the_old_wallet_used() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);

    world.import();

    // The default account's highest key is child 7, above its counter of 4; savings used only
    // child 0, below its counter of 3.
    assert_eq!(world.next_child(DEFAULT), 8);
    assert_eq!(world.next_child(SAVINGS), 3);
}

#[test]
fn an_old_counter_far_past_every_reproduced_key_is_believed_only_a_little() {
    let mut old = OldWallet::standard(&keychain(MNEMONIC));
    old.counters = vec![(0, u32::MAX), (1, 2_000_000_000)];
    let world = World::new(&old, &[]);

    world.import();

    // At most 1000 keys past the highest reproduced key (child 7, and child 0 in savings).
    assert_eq!(world.next_child(DEFAULT), 1_008);
    assert_eq!(world.next_child(SAVINGS), 1_001);
}

#[test]
fn a_history_with_no_output_to_prove_it_is_refused_and_stores_nothing() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[]);
    let other = keychain(OTHER_MNEMONIC);
    let mut forged = OldWallet::standard(&other);
    forged.outputs.clear();
    forged.counters = vec![(0, u32::MAX)];
    let folder = empty_dir();
    forged.write(&other, folder.path());

    let outcome = world.import_from(folder.path());

    assert_eq!(outcome.status, LegacyImportStatus::OtherWallet);
    assert!(world.txs(DEFAULT).is_empty());
    assert_eq!(world.labels(), [(0, "default".to_owned())]);
    assert_eq!(world.next_child(DEFAULT), 0);
    assert_eq!(world.import().status, LegacyImportStatus::Imported);
}

#[test]
fn entries_of_accounts_the_old_wallet_never_had_are_skipped() {
    let mut old = OldWallet::standard(&keychain(MNEMONIC));
    let mut stray = OldTx::new(7, 0, "TxReceived", "2024-03-05T10:00:00Z");
    stray.slate = Some("7a7a7a7a-0000-4000-8000-000000000007");
    stray.credited = 1;
    old.txs.push(stray);
    let world = World::new(&old, &[]);

    let outcome = world.import();

    assert_eq!(outcome.status, LegacyImportStatus::Imported);
    assert_eq!(outcome.skipped, 1);
    assert_eq!(world.labels().len(), 2, "default and savings only");
}

#[test]
fn the_source_folder_is_not_touched_and_the_work_copy_can_be_removed() {
    let world = World::new(&OldWallet::standard(&keychain(MNEMONIC)), &[UNKNOWN]);
    let before = snapshot(world.source.path());
    let work = tempfile::tempdir().unwrap();

    let outcome = world
        .harness
        .block_on(
            world
                .wallet
                .import_legacy_history(world.source.path(), work.path()),
        )
        .unwrap();

    assert_eq!(outcome.status, LegacyImportStatus::Imported);
    let after = snapshot(world.source.path());
    assert_eq!(
        after, before,
        "same files, same bytes, same directory entries"
    );
    assert!(
        after.keys().all(|path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            !name.ends_with("-wal") && !name.ends_with("-shm") && !name.ends_with("-journal")
        }),
        "no sqlite side files beside the source"
    );
    work.close().unwrap();
    assert_eq!(
        world.txs(DEFAULT).len(),
        8,
        "the history is in the wallet, not the copy"
    );
}

#[test]
fn an_output_a_scan_restores_is_dated_by_its_block_and_marked_found() {
    let world = World::new(
        &OldWallet {
            accounts: Vec::new(),
            counters: Vec::new(),
            txs: Vec::new(),
            outputs: Vec::new(),
        },
        &[(0, 1, 40_000_000, 20), UNKNOWN],
    );

    world.scan();

    let default = world.txs(DEFAULT);
    assert_eq!(default.len(), 2);
    for details in &default {
        assert_eq!(details.origin, TxOrigin::FoundByScan);
        assert_eq!(details.imported, None);
        let height = details.confirmed_height.unwrap().value();
        assert_eq!(
            details.transaction.entry.created_at,
            world.block_time(height)
        );
        assert_ne!(details.transaction.entry.created_at, fixed_time());
    }
}

#[test]
fn an_output_whose_block_header_is_unavailable_is_dated_by_the_scan_time() {
    let world = World::new(
        &OldWallet {
            accounts: Vec::new(),
            counters: Vec::new(),
            txs: Vec::new(),
            outputs: Vec::new(),
        },
        &[UNKNOWN],
    );
    for _ in 0..16 {
        world
            .harness
            .node
            .fail_next("get_header", MockFailure::Unreachable);
    }

    world.scan();

    let default = world.txs(DEFAULT);
    assert_eq!(default.len(), 1);
    assert_eq!(default[0].origin, TxOrigin::FoundByScan);
    assert_eq!(default[0].transaction.entry.created_at, fixed_time());
}
