// SPDX-License-Identifier: Apache-2.0
//! A wallet made by a released CLI opens with this code, is moved to the current schema, lists
//! its history again, syncs against a node and is served by `lepic serve`. The wallet is the
//! fixture `testdata/upgrade/cli-0.4.0`, made by LEPIC 0.4.0 (schema 16); its README says how.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod support;

use std::path::Path;

use lepic_keychain::Seed;
use lepic_node::mock::RecordedChain;
use lepic_store::{StoreError, WalletStore};
use lepic_wallet::{EncryptedSqliteStores, StoreOpener};
use serde_json::{Value, json};
use support::{Instance, SENDER_MNEMONIC, TestHost, http, serving};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/upgrade/cli-0.4.0"
);
const PASSWORD: &str = "upgrade fixture password";

fn fixture_file(name: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURE).join(name)).unwrap()
}

/// Copies `from` to `to`, owner-only as the CLI keeps a data directory (git keeps no modes).
fn copy_dir(from: &Path, to: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(to).unwrap();
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700)).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

/// The wallet the fixture holds, copied into a data directory of its own, and the node as
/// the generator left it: the two sends pushed, one of them mined.
struct Upgrade {
    wallet: Instance,
    host: TestHost,
    recorded: RecordedChain,
    expected: Value,
}

impl Upgrade {
    fn new() -> Self {
        let wallet = Instance::new(PASSWORD);
        copy_dir(&Path::new(FIXTURE).join("wallet"), &wallet.data_dir());
        let recorded = RecordedChain::from_json(&fixture_file("chain.json")).unwrap();
        let host = TestHost::new();
        host.node
            .update_chain(|chain| *chain = recorded.chain.clone());
        let mut expected: Value = serde_json::from_str(&fixture_file("expected.json")).unwrap();
        // The generator kept what `epic1 address` printed as text.
        let printed = expected["epic1_address"]["stdout"]
            .as_str()
            .unwrap()
            .to_owned();
        expected["epic1_address"]["stdout"] = serde_json::from_str(&printed).unwrap();
        Self {
            wallet,
            host,
            recorded,
            expected,
        }
    }

    fn run(&self, args: &[&str]) -> Value {
        self.wallet.run(&self.host, args).ok().json()
    }

    /// Reads what schema 17 added, as another program with the phrase would: the two tables
    /// of the wallet API (`api_events`, `api_requests`). The file is encrypted under a key
    /// derived from the phrase, so its version number is not readable without the store.
    /// Opening the store here also migrates a file still at an older schema, so call it
    /// after a command has.
    fn has_the_api_tables(&self) -> bool {
        let seed = Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = EncryptedSqliteStores
            .open(
                &self.wallet.data_dir(),
                lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
                &lepic_wallet::store_key(&seed).unwrap(),
            )
            .unwrap();
        store
            .read(|repos| {
                repos.api_event_last_id()?;
                repos.api_request("fixture", "absent")?;
                Ok::<_, StoreError>(())
            })
            .is_ok()
    }

    /// Every listing the generator recorded, read again.
    fn listings(&self) -> Value {
        let mut now = serde_json::Map::new();
        now.insert("wallet_info".to_owned(), self.run(&["wallet", "info"]));
        now.insert(
            "wallet_address".to_owned(),
            self.run(&["wallet", "address"]),
        );
        now.insert(
            "wallet_outputs".to_owned(),
            self.run(&["wallet", "outputs"]),
        );
        let list = self.run(&["tx", "list"]);
        let mut shown = serde_json::Map::new();
        for tx in list["transactions"].as_array().unwrap() {
            let id = tx["tx_id"].to_string();
            let one = self.run(&["tx", "show", &id]);
            shown.insert(id, one);
        }
        now.insert("tx_list".to_owned(), list);
        now.insert("tx_show".to_owned(), Value::Object(shown));
        now.insert("contact_list".to_owned(), self.run(&["contact", "list"]));
        let epic1 = self.wallet.run(&self.host, &["epic1", "address"]);
        now.insert(
            "epic1_address".to_owned(),
            json!({
                "code": epic1.code,
                "stdout": serde_json::from_str::<Value>(&epic1.stdout).unwrap_or(Value::Null),
                "stderr": epic1.stderr,
            }),
        );
        Value::Object(now)
    }
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

#[test]
fn a_wallet_made_by_0_4_0_is_moved_to_the_current_schema_on_open() {
    let upgrade = Upgrade::new();
    upgrade.run(&["wallet", "info"]);
    assert!(upgrade.has_the_api_tables());
}

#[test]
fn a_wallet_made_by_0_4_0_lists_the_history_it_listed_before() {
    let upgrade = Upgrade::new();
    let now = upgrade.listings();
    for (name, expected) in upgrade.expected.as_object().unwrap() {
        if name == "ids" {
            continue;
        }
        assert_holds(name, expected, &now[name]);
    }
    let ids = &upgrade.expected["ids"];
    assert_eq!(
        now["tx_show"][ids["pending"].to_string()]["state"],
        "posted"
    );
    assert_eq!(
        now["tx_show"][ids["mined"].to_string()]["state"],
        "confirmed"
    );
    assert_eq!(
        now["tx_show"][ids["cancelled"].to_string()]["state"],
        "cancelled"
    );
    assert_eq!(
        now["contact_list"]["contacts"][0]["contact_id"],
        ids["contact"]
    );
}

/// The chain one block later, with both pushed sends mined (the first one already was).
fn node_mines_the_pushed_sends(upgrade: &Upgrade) -> lepic_node::mock::ChainState {
    let mined = upgrade.recorded.mined();
    upgrade
        .host
        .node
        .update_chain(|chain| *chain = mined.clone());
    mined
}

fn state_of(listing: &Value, id: &Value) -> String {
    listing["tx_show"][id.to_string()]["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn a_sync_confirms_the_send_the_node_mined_and_changes_nothing_else() {
    let upgrade = Upgrade::new();
    let before = upgrade.listings();
    let ids = upgrade.expected["ids"].clone();
    assert_eq!(state_of(&before, &ids["pending"]), "posted");

    let mined = node_mines_the_pushed_sends(&upgrade);
    let synced = upgrade.run(&["wallet", "info"]);
    assert_eq!(synced["height"], mined.tip.height.value());
    let after = upgrade.listings();

    assert_eq!(state_of(&after, &ids["pending"]), "confirmed", "{after}");
    for kept in [&ids["mined"], &ids["cancelled"]] {
        assert_eq!(state_of(&after, kept), state_of(&before, kept), "tx {kept}");
        assert_eq!(
            after["tx_show"][kept.to_string()]["updated_at"],
            before["tx_show"][kept.to_string()]["updated_at"]
        );
    }
    // The two funding receives are as they were.
    for funding in ["1", "2"] {
        assert_eq!(
            after["tx_show"][funding], before["tx_show"][funding],
            "tx {funding}"
        );
    }
    assert_eq!(
        after["tx_list"]["transactions"].as_array().unwrap().len(),
        5,
        "{after}"
    );
    assert_eq!(after["contact_list"], before["contact_list"]);
    assert_eq!(after["wallet_address"], before["wallet_address"]);

    // The balance is what the chain holds: the outputs it shows unspent.
    let outputs = after["wallet_outputs"]["outputs"].as_array().unwrap();
    let mut on_chain = 0.0;
    for output in outputs {
        let commitment = output["commitment"].as_str().unwrap();
        let known = mined
            .outputs
            .iter()
            .find(|chain| chain.commitment.to_hex() == commitment)
            .unwrap_or_else(|| panic!("{commitment} is not on the chain"));
        assert_eq!(output["status"] == "spent", known.spent, "{output}");
        if !known.spent {
            on_chain += output["value"].as_str().unwrap().parse::<f64>().unwrap();
        }
    }
    let account = &after["wallet_info"]["accounts"][0];
    assert_eq!(
        account["total"].as_str().unwrap().parse::<f64>().unwrap(),
        on_chain,
        "{account}"
    );
    assert_eq!(account["awaiting_finalization"], "0.00000000", "{account}");
}

/// The id the payments API gives a transaction: the slate id of a send, and for a receive
/// found by the scan, an id made from the local transaction number.
fn payment_id(tx: &Value) -> String {
    match tx["slate_id"].as_str() {
        Some(slate) => slate.to_owned(),
        None => format!(
            "00000000-0000-0000-0000-{:012}",
            tx["tx_id"].as_u64().unwrap()
        ),
    }
}

#[test]
fn serve_lists_every_payment_of_a_0_4_0_wallet_and_answers_events() {
    let upgrade = Upgrade::new();
    let transactions = upgrade.expected["tx_list"]["transactions"]
        .as_array()
        .unwrap()
        .clone();
    serving(
        upgrade.host.without_interrupt(),
        &upgrade.wallet,
        |socket, _| {
            let payments = http(socket, "GET", "/api/v1/payments", None).ok();
            let items = payments["items"].as_array().unwrap();
            assert_eq!(items.len(), transactions.len(), "{payments}");
            for tx in &transactions {
                let id = payment_id(tx);
                let item = items
                    .iter()
                    .find(|item| item["id"] == id.as_str())
                    .unwrap_or_else(|| panic!("{id} is not listed: {payments}"));
                let direction = if tx["direction"] == "incoming" {
                    "in"
                } else {
                    "out"
                };
                assert_eq!(item["direction"], direction, "{item}");
                assert_eq!(item["state"], tx["state"], "{item}");
                assert_eq!(item["created_at"], tx["created_at"], "{item}");
                assert_eq!(item["fee"], tx["fee"], "{item}");
            }
            let events = http(socket, "GET", "/api/v1/events", None);
            assert_eq!(events.status, 200, "{events:?}");
        },
    );
}

#[test]
fn a_second_open_changes_nothing() {
    let upgrade = Upgrade::new();
    let first = upgrade.listings();
    let second = upgrade.listings();
    assert_eq!(first, second);
    assert!(upgrade.has_the_api_tables());
    assert_eq!(upgrade.listings(), first);
}
