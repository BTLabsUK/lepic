// SPDX-License-Identifier: Apache-2.0
//! Wallets made by released builds, opened through the calls the app makes: they are moved to
//! the current schema, list the history they listed before, sync against a node and open a
//! second time unchanged. The wallets are the fixtures `testdata/upgrade/app-26.11.3-desktop`,
//! `app-26.11.3-mobile` and `ffi-0.4.0`; each README says how it was made.

use std::path::Path;
use std::sync::Arc;

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_node::mock::RecordedChain;
use lepic_store::{StoreError, WalletStore as _};
use serde_json::{Value, json};

use super::*;

const PASSWORD: &str = "upgrade fixture password";
const RELAY: &str = "relay.example.org";

/// What the app's secret store held when the generator stopped, and how the wallet opens.
struct Fixture {
    name: &'static str,
    mobile: bool,
}

const DESKTOP: Fixture = Fixture {
    name: "app-26.11.3-desktop",
    mobile: false,
};
const MOBILE: Fixture = Fixture {
    name: "app-26.11.3-mobile",
    mobile: true,
};
const FFI_0_4_0: Fixture = Fixture {
    name: "ffi-0.4.0",
    mobile: true,
};

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn dbg<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}

/// The fixture's wallet copied into a directory of its own, the node as the generator left it,
/// and the app's secret store as it was.
struct Upgrade {
    fixture: &'static Fixture,
    chain: MockChain,
    runtime: LepicRuntime,
    dir: tempfile::TempDir,
    store: AppSecretStore,
    secrets: Value,
    recorded: RecordedChain,
    expected: Value,
    phrase: String,
    _relay: MockRelay,
}

impl Upgrade {
    async fn new(fixture: &'static Fixture) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/upgrade")
            .join(fixture.name);
        let read = |name: &str| std::fs::read_to_string(root.join(name)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        copy_dir(&root.join("wallet"), dir.path());

        let recorded = RecordedChain::from_json(&read("chain.json")).unwrap();
        let chain = MockChain::new(1).unwrap();
        chain.backend().replace_chain(recorded.chain.clone());
        let mut runtime = chain.runtime(LogLevel::Warn).unwrap();
        let relay = MockRelay::new(RelayNetwork::Floonet);
        Arc::get_mut(&mut runtime.inner).unwrap().relay = Some(relay.connector());

        let secrets: Value = serde_json::from_str(&read("secrets.json")).unwrap();
        let store = AppSecretStore::in_memory();
        for (key, value) in secrets["store"].as_object().unwrap() {
            store
                .write(key, value.as_str().unwrap().to_owned())
                .await
                .unwrap();
        }
        Self {
            fixture,
            chain,
            runtime,
            dir,
            store,
            secrets,
            recorded,
            expected: serde_json::from_str(&read("expected.json")).unwrap(),
            phrase: read("mnemonic.txt").trim().to_owned(),
            _relay: relay,
        }
    }

    fn config(&self) -> WalletConfig {
        WalletConfig {
            policy: Default::default(),
            data_dir: self.dir.path().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: RELAY.to_owned(),
            epicbox_port: 443,
            onion_routes: Vec::new(),
            tuning: crate::tuning::shipped(),
            offline: false,
            tor_wanted: false,
            host_features: 0,
            profile: 0,
            domain: None,
        }
    }

    /// Opens the wallet the way the app opened it: with the password, or with the PIN and the
    /// sealed password the app kept.
    async fn open(&self) -> EpicWallet {
        if self.fixture.mobile {
            EpicWallet::open_with_pin(
                &self.runtime,
                self.config(),
                &self.store,
                self.secrets["pin"].as_str().unwrap().to_owned(),
                self.secrets["sealed_password"].as_str().unwrap().to_owned(),
            )
            .await
            .unwrap()
        } else {
            EpicWallet::open(
                &self.runtime,
                self.config(),
                &self.store,
                PASSWORD.to_owned(),
            )
            .await
            .unwrap()
        }
    }

    /// Whether the database has what schema 17 added, the two tables of the wallet API,
    /// read as another program with the phrase would. The file is encrypted under a key
    /// derived from the phrase, so its version number is not readable without the store.
    fn has_the_api_tables(&self) -> bool {
        let seed = lepic_keychain::Seed::from_mnemonic(&self.phrase).unwrap();
        let database = lepic_store::SqliteStore::open(
            &self.dir.path().join(lepic_wallet::ENCRYPTED_DATABASE_FILE),
            lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
            lepic_store::AtRest::Encrypted(&lepic_wallet::store_key(&seed).unwrap()),
        )
        .unwrap();
        database
            .read(|repos| {
                repos.api_event_last_id()?;
                repos.api_request("fixture", "absent")?;
                Ok::<_, StoreError>(())
            })
            .is_ok()
    }

    fn ids(&self) -> &Value {
        &self.expected["ids"]
    }
}

/// Everything the generator listed, read again through the same calls.
async fn listed(wallet: &EpicWallet) -> Value {
    let summary = wallet.summary(false).await.unwrap();
    let outputs = wallet.outputs().await.unwrap();
    let transactions = wallet.transactions().await.unwrap();
    let contacts = wallet.contacts().await.unwrap();
    json!({
        "summary": {
            "last_confirmed_height": summary.last_confirmed_height,
            "minimum_confirmations": summary.minimum_confirmations,
            "total": summary.total,
            "spendable": summary.spendable,
            "awaiting_confirmation": summary.awaiting_confirmation,
            "awaiting_finalization": summary.awaiting_finalization,
            "immature": summary.immature,
            "locked": summary.locked,
            "validated_with_node": summary.validated_with_node,
        },
        "outputs": outputs.iter().map(|output| json!({
            "commitment": output.commitment,
            "value": output.value,
            "status": dbg(&output.status),
            "category": dbg(&output.category),
            "is_coinbase": output.is_coinbase,
            "height": output.height,
            "lock_height": output.lock_height,
            "mmr_index": output.mmr_index,
            "confirmations": output.confirmations,
            "tx_id": output.tx_id,
        })).collect::<Vec<_>>(),
        "transactions": transactions.iter().map(|tx| json!({
            "tx_id": tx.tx_id,
            "direction": dbg(&tx.direction),
            "status": dbg(&tx.status),
            "slate_id": tx.slate_id,
            "transport": tx.transport,
            "amount_credited": tx.amount_credited,
            "amount_debited": tx.amount_debited,
            "fee": tx.fee,
            "created_at_ms": tx.created_at_ms,
            "confirmed_at_ms": tx.confirmed_at_ms,
            "confirmed_height": tx.confirmed_height,
            "kernel_excess": tx.kernel_excess,
            "counterparty": tx.counterparty,
            "ttl_cutoff_height": tx.ttl_cutoff_height,
            "messages": tx.messages.iter().map(|message| json!({
                "role": dbg(&message.role),
                "text": message.text,
            })).collect::<Vec<_>>(),
            "flow": dbg(&tx.flow),
            "origin": dbg(&tx.origin),
            "output_commits": tx.output_commits,
            "spent_commits": tx.spent_commits,
        })).collect::<Vec<_>>(),
        "contacts": contacts.iter().map(|contact| json!({
            "contact_id": contact.contact_id,
            "label": contact.label,
            "claimed_name": contact.claimed_name,
            "kind": dbg(&contact.kind),
            "state": dbg(&contact.state),
            "verified_at_ms": contact.verified_at_ms,
            "allow_invoices": contact.allow_invoices,
            "seal": dbg(&contact.seal),
            "home_relay": contact.home_relay,
            "created_at_ms": contact.created_at_ms,
            "status": dbg(&contact.status),
        })).collect::<Vec<_>>(),
    })
}

/// `expected` is in `actual`: every key of an object, every element of an array in order,
/// every other value equal. Keys `actual` has beyond `expected` are fields added since.
fn assert_holds(path: &str, expected: &Value, actual: &Value) {
    match (expected, actual) {
        (Value::Object(want), Value::Object(have)) => {
            for (key, value) in want {
                let here = format!("{path}.{key}");
                let found = have
                    .get(key)
                    .unwrap_or_else(|| panic!("{here} is gone; now {actual}"));
                assert_holds(&here, value, found);
            }
        }
        (Value::Array(want), Value::Array(have)) => {
            assert_eq!(want.len(), have.len(), "{path}: {expected} became {actual}");
            for (index, (value, found)) in want.iter().zip(have).enumerate() {
                assert_holds(&format!("{path}[{index}]"), value, found);
            }
        }
        _ => assert_eq!(expected, actual, "{path}"),
    }
}

fn transaction<'a>(listing: &'a Value, tx_id: &Value) -> &'a Value {
    listing["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tx| tx["tx_id"] == *tx_id)
        .unwrap_or_else(|| panic!("tx {tx_id} is not listed: {listing}"))
}

async fn check_the_open_reaches_the_current_schema(fixture: &'static Fixture) {
    let upgrade = Upgrade::new(fixture).await;
    let wallet = upgrade.open().await;
    assert!(upgrade.has_the_api_tables());
    let at_rest = wallet.store_at_rest().await.unwrap();
    assert_eq!(at_rest.state, StoreAtRestState::Encrypted, "{at_rest:?}");
    assert_eq!(
        dbg(&at_rest),
        upgrade.expected["store_at_rest"],
        "{at_rest:?}"
    );
}

async fn check_the_history_is_listed_again(fixture: &'static Fixture) {
    let upgrade = Upgrade::new(fixture).await;
    let wallet = upgrade.open().await;
    let now = listed(&wallet).await;
    for (name, expected) in upgrade.expected.as_object().unwrap() {
        if name == "ids" || name == "store_at_rest" {
            continue;
        }
        assert_holds(name, expected, &now[name]);
    }
    let ids = upgrade.ids();
    let status = |id: &str| {
        now["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tx| tx["tx_id"] == ids[id])
            .unwrap()["status"]
            .clone()
    };
    assert_eq!(status("pending"), "Posted");
    assert_eq!(status("mined"), "Confirmed");
    assert_eq!(status("cancelled"), "Cancelled");
    assert_eq!(now["contacts"][0]["contact_id"], ids["contact"]);
}

async fn check_the_sync_confirms_the_mined_send(fixture: &'static Fixture) {
    let upgrade = Upgrade::new(fixture).await;
    let wallet = upgrade.open().await;
    let before = listed(&wallet).await;
    let ids = upgrade.ids().clone();
    assert_eq!(transaction(&before, &ids["pending"])["status"], "Posted");

    let mined = upgrade.recorded.mined();
    upgrade.chain.backend().replace_chain(mined.clone());
    wallet.summary(true).await.unwrap();
    let after = listed(&wallet).await;

    assert_eq!(
        after["summary"]["last_confirmed_height"],
        mined.tip.height.value()
    );
    let confirmed = transaction(&after, &ids["pending"]);
    assert_eq!(confirmed["status"], "Confirmed", "{after}");
    assert_eq!(
        confirmed["confirmed_height"],
        mined.tip.height.value(),
        "{confirmed}"
    );
    for kept in [&ids["mined"], &ids["cancelled"]] {
        assert_eq!(
            transaction(&after, kept),
            transaction(&before, kept),
            "tx {kept}"
        );
    }
    // The two funding receives are as they were.
    for funding in [1, 2] {
        let funding = json!(funding);
        assert_eq!(
            transaction(&after, &funding),
            transaction(&before, &funding)
        );
    }
    assert_eq!(
        after["transactions"].as_array().unwrap().len(),
        before["transactions"].as_array().unwrap().len()
    );
    assert_eq!(after["contacts"], before["contacts"]);

    // The balance is what the chain holds: the outputs it shows unspent.
    let mut unspent = Vec::new();
    for output in after["outputs"].as_array().unwrap() {
        let commitment = output["commitment"].as_str().unwrap();
        let known = mined
            .outputs
            .iter()
            .find(|chain| chain.commitment.to_hex() == commitment)
            .unwrap_or_else(|| panic!("{commitment} is not on the chain"));
        assert_eq!(output["status"] == "Spent", known.spent, "{output}");
        if !known.spent {
            unspent.push(output["value"].as_u64().unwrap());
        }
    }
    let on_chain: u64 = unspent.iter().sum();
    assert_eq!(after["summary"]["total"], on_chain, "{}", after["summary"]);
    assert_eq!(
        after["summary"]["awaiting_finalization"], 0,
        "{}",
        after["summary"]
    );
}

async fn check_a_second_open_changes_nothing(fixture: &'static Fixture) {
    let upgrade = Upgrade::new(fixture).await;
    let wallet = upgrade.open().await;
    let first = listed(&wallet).await;
    wallet.lock();
    drop(wallet);

    let wallet = upgrade.open().await;
    assert_eq!(listed(&wallet).await, first);
    assert!(upgrade.has_the_api_tables());
    assert_eq!(listed(&wallet).await, first);
}

macro_rules! upgrade_tests {
    ($module:ident, $fixture:expr) => {
        mod $module {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn the_wallet_is_moved_to_the_current_schema_on_open() {
                check_the_open_reaches_the_current_schema(&$fixture).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn the_wallet_lists_the_history_it_listed_before() {
                check_the_history_is_listed_again(&$fixture).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn a_sync_confirms_the_send_the_node_mined_and_changes_nothing_else() {
                check_the_sync_confirms_the_mined_send(&$fixture).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn a_second_open_changes_nothing() {
                check_a_second_open_changes_nothing(&$fixture).await;
            }
        }
    };
}

upgrade_tests!(app_26_11_3_desktop, DESKTOP);
upgrade_tests!(app_26_11_3_mobile, MOBILE);
upgrade_tests!(ffi_0_4_0, FFI_0_4_0);
