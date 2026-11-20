// SPDX-License-Identifier: Apache-2.0
//! A wallet made by a released CLI opens with this code, is moved to the current schema, lists
//! its history again, syncs against a node and is served by `lepic serve`. The wallets are the
//! fixtures `testdata/upgrade/cli-0.4.0` (LEPIC 0.4.0, schema 16) and
//! `testdata/upgrade/cli-0.6.0` (the 2026-11-17 pre-release build, schema 17; not the 0.6.0 release); their READMEs say how they were made.
//! The 0.6.0 fixture also recorded the mailboxes the mock relay held for it: the tests at the end
//! post those messages again and run one inbox pass.

// Tests may unwrap, index and use plain arithmetic (docs/rules.md).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use crate::support;

use std::path::Path;
use std::time::Duration;

use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{Domain, EpicboxAddress, Network as RelayNetwork, RelayEndpoint, Security};
use lepic_keychain::Seed;
use lepic_node::mock::RecordedChain;
use lepic_store::{StoreError, WalletStore};
use lepic_wallet::{EncryptedSqliteStores, StoreOpener};
use serde_json::{Value, json};
use support::{Instance, SENDER_MNEMONIC, TestHost, http, serving};

/// A fixture directory and the password of the wallet in it.
#[derive(Clone, Copy)]
struct Fixture {
    dir: &'static str,
    password: &'static str,
}

const CLI_0_4_0: Fixture = Fixture {
    dir: concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/upgrade/cli-0.4.0"
    ),
    password: "upgrade fixture password",
};
const CLI_0_6_0: Fixture = Fixture {
    dir: concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/upgrade/cli-0.6.0"
    ),
    password: "upgrade fixture password",
};
/// The payer's side of the 0.6.0 fixture: the second wallet, kept in `payer/`.
const PAYER_PASSWORD: &str = "upgrade peer password";

impl Fixture {
    fn file(self, name: &str) -> String {
        std::fs::read_to_string(Path::new(self.dir).join(name)).unwrap()
    }
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
    fn new(fixture: Fixture) -> Self {
        Self::open(fixture, "wallet", fixture.password)
    }

    /// The wallet in `fixture`'s directory `dir`, opened with `password`.
    fn open(fixture: Fixture, dir: &str, password: &str) -> Self {
        let wallet = Instance::new(password);
        copy_dir(&Path::new(fixture.dir).join(dir), &wallet.data_dir());
        let recorded = RecordedChain::from_json(&fixture.file("chain.json")).unwrap();
        let host = TestHost::new();
        host.node
            .update_chain(|chain| *chain = recorded.chain.clone());
        let mut expected: Value = serde_json::from_str(&fixture.file("expected.json")).unwrap();
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

    /// The mailboxes the store watches, read as [`Self::has_the_api_tables`] reads its tables.
    fn watch_set(&self) -> Vec<lepic_store::WatchRow> {
        let seed = Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = EncryptedSqliteStores
            .open(
                &self.wallet.data_dir(),
                lepic_wallet::lifecycle::store_keys(&seed).unwrap(),
                &lepic_wallet::store_key(&seed).unwrap(),
            )
            .unwrap();
        store.read(|repos| repos.watch_set()).unwrap()
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
        // Listings the 0.6.0 generator recorded and the 0.4.0 one did not.
        if self.expected.get("invoice_list").is_some() {
            now.insert("invoice_list".to_owned(), self.run(&["invoice", "list"]));
        }
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

/// Fields an older build printed that this one dropped on purpose: a send is recovered, never
/// released, and a contact has no `native_slates`.
const REMOVED_FIELDS: [&str; 3] = ["releasable", "releasable_from", "native_slates"];

/// Fields an older build printed at one path that this one dropped on purpose: an account has
/// one epic1 address, so it is shown without an index.
const REMOVED_AT: [&str; 1] = ["epic1_address.stdout.index"];

/// A check that a listed value is well formed.
type WellFormed = fn(&Value) -> bool;

/// Values an older build printed that this one prints differently on purpose, by their path
/// in the listing: each must still be listed and pass its check.
const CHANGED_VALUES: [(&str, &str, WellFormed); 1] = [(
    "epic1_address.stdout.address",
    "the address carries its delivery key since the layout changed",
    is_a_floonet_address,
)];

/// `value` reads as an epic1 address of the fixture wallet's network.
fn is_a_floonet_address(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|text| lepic_wallet_contacts::epic1_testing::delivery_mailbox(text, "relay.test"))
        .is_some_and(|mailbox| mailbox.network() == RelayNetwork::Floonet)
}

/// `expected` is in `actual`: every key of an object, every element of an array in order,
/// every other value equal. Keys `actual` has beyond `expected` are fields added since; a key
/// in [`REMOVED_FIELDS`] or a path in [`REMOVED_AT`] must be gone, and a path in
/// [`CHANGED_VALUES`] must pass its check.
fn assert_holds(path: &str, expected: &Value, actual: &Value) {
    match (expected, actual) {
        (Value::Object(want), Value::Object(have)) => {
            for (key, value) in want {
                let here = format!("{path}.{key}");
                if REMOVED_FIELDS.contains(&key.as_str()) || REMOVED_AT.contains(&here.as_str()) {
                    assert!(have.get(key).is_none(), "{here} is still listed: {actual}");
                    continue;
                }
                let found = have
                    .get(key)
                    .unwrap_or_else(|| panic!("{here} is gone; now {actual}"));
                if let Some((_, why, well_formed)) =
                    CHANGED_VALUES.iter().find(|(path, ..)| *path == here)
                {
                    assert!(
                        well_formed(found),
                        "{here} ({why}) is not well formed: {found}"
                    );
                    continue;
                }
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

fn moved_to_the_current_schema_on_open(fixture: Fixture) {
    let upgrade = Upgrade::new(fixture);
    upgrade.run(&["wallet", "info"]);
    assert!(upgrade.has_the_api_tables());
}

#[test]
fn a_wallet_made_by_0_4_0_is_moved_to_the_current_schema_on_open() {
    moved_to_the_current_schema_on_open(CLI_0_4_0);
}

#[test]
fn a_wallet_made_by_0_6_0_is_moved_to_the_current_schema_on_open() {
    moved_to_the_current_schema_on_open(CLI_0_6_0);
}

/// Schema 18 fills the watch set from what 0.6.0 kept: the paired contact, the pending pairing
/// and the in-person invoice's mailbox (transaction 15). Its epic1 links and payments are not
/// carried over.
#[test]
fn a_0_6_0_wallet_watches_its_mailboxes_after_the_move_to_schema_18() {
    use lepic_store::MailClass;

    let upgrade = Upgrade::new(CLI_0_6_0);
    upgrade.run(&["wallet", "info"]);
    let rows = upgrade.watch_set();
    let ids = &upgrade.expected["ids"];
    let slate_of = |tx_id: u64| {
        let txs = upgrade.expected["tx_list"]["transactions"]
            .as_array()
            .unwrap();
        let tx = txs.iter().find(|tx| tx["tx_id"] == tx_id).unwrap();
        tx["slate_id"].as_str().unwrap().to_owned()
    };
    let wanted = [
        (
            format!("contact:{}", ids["contact"].as_str().unwrap()),
            MailClass::Contact,
        ),
        (
            format!("pairing:{}", ids["pending_contact"].as_str().unwrap()),
            MailClass::Pairing,
        ),
        (format!("inperson:{}", slate_of(15)), MailClass::InPerson),
    ];
    for (key_ref, class) in wanted {
        assert!(
            rows.iter()
                .any(|row| row.key_ref == key_ref && row.class == class && !row.relay.is_empty()),
            "no {class:?} row for {key_ref} in {rows:#?}"
        );
    }
    assert!(
        rows.iter()
            .all(|row| !matches!(row.class, MailClass::Address | MailClass::Reply)),
        "{rows:#?}"
    );
}

#[test]
fn a_wallet_made_by_0_4_0_lists_the_history_it_listed_before() {
    lists_the_history_it_listed_before(CLI_0_4_0);
}

#[test]
fn a_wallet_made_by_0_6_0_lists_the_history_it_listed_before() {
    lists_the_history_it_listed_before(CLI_0_6_0);
}

fn lists_the_history_it_listed_before(fixture: Fixture) {
    let upgrade = Upgrade::new(fixture);
    let now = upgrade.listings();
    for (name, expected) in upgrade.expected.as_object().unwrap() {
        // What the generator made and its ids, the second wallet's listings, and the pairing
        // requests and epic1 links this build no longer lists.
        if ["ids", "made", "payer", "contact_requests", "epic1_links"].contains(&name.as_str()) {
            continue;
        }
        if name == "contact_list" {
            assert_holds(
                "contact_list.contacts",
                &expected["contacts"],
                &now[name]["contacts"],
            );
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
    a_sync_confirms_the_mined_send(CLI_0_4_0);
}

#[test]
fn a_sync_of_a_0_6_0_wallet_confirms_the_send_the_node_mined_and_changes_nothing_else() {
    a_sync_confirms_the_mined_send(CLI_0_6_0);
}

/// The receives `wallet restore` found: incoming, with no slate.
fn funding_ids(expected: &Value) -> Vec<String> {
    expected["tx_list"]["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|tx| tx["direction"] == "incoming" && tx["slate_id"].is_null())
        .map(|tx| tx["tx_id"].to_string())
        .collect()
}

fn a_sync_confirms_the_mined_send(fixture: Fixture) {
    let upgrade = Upgrade::new(fixture);
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
    // The funding receives are as they were.
    let funding = funding_ids(&upgrade.expected);
    assert!(!funding.is_empty());
    for id in &funding {
        assert_eq!(after["tx_show"][id], before["tx_show"][id], "tx {id}");
    }
    assert_eq!(
        after["tx_list"]["transactions"].as_array().unwrap().len(),
        upgrade.expected["tx_list"]["transactions"]
            .as_array()
            .unwrap()
            .len(),
        "{after}"
    );
    assert_eq!(after["contact_list"], before["contact_list"]);
    assert_eq!(after["wallet_address"], before["wallet_address"]);

    // The balance is what the chain holds: the outputs it shows unspent.
    let outputs = after["wallet_outputs"]["outputs"].as_array().unwrap();
    let mut on_chain = 0.0;
    for output in outputs {
        let commitment = output["commitment"].as_str().unwrap();
        // An output of a transaction not posted yet is the wallet's own record, not on chain.
        let Some(known) = mined
            .outputs
            .iter()
            .find(|chain| chain.commitment.to_hex() == commitment)
        else {
            assert_eq!(
                output["status"], "unconfirmed",
                "{commitment} is not on the chain"
            );
            continue;
        };
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
    // The outputs of the open payments, none on chain, are the ones the wallet had before.
    let unposted_before: Vec<&Value> = before["wallet_outputs"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|output| {
            !mined
                .outputs
                .iter()
                .any(|chain| chain.commitment.to_hex() == output["commitment"].as_str().unwrap())
        })
        .collect();
    let unposted_after: Vec<&Value> = outputs
        .iter()
        .filter(|output| output["status"] == "unconfirmed")
        .collect();
    assert_eq!(unposted_after, unposted_before, "{after}");
    if unposted_after.is_empty() {
        assert_eq!(account["awaiting_finalization"], "0.00000000", "{account}");
    }
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
    serve_lists_every_payment(CLI_0_4_0);
}

#[test]
fn serve_lists_every_payment_of_a_0_6_0_wallet_and_answers_events() {
    serve_lists_every_payment(CLI_0_6_0);
}

fn serve_lists_every_payment(fixture: Fixture) {
    let upgrade = Upgrade::new(fixture);
    // Serve sweeps unpaid invoices at start, by the wall clock; the fixture's are older than
    // the default expiry, so a sweep that ran first would cancel them before the listing.
    let config = upgrade.wallet.home.path().join(".lepic");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("config.toml"),
        "invoice_expiry_hours = 876000\n",
    )
    .unwrap();
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
                assert_eq!(item["state"], api_state(&tx["state"]), "{item}");
                assert_eq!(item["created_at"], tx["created_at"], "{item}");
                assert_eq!(item["fee"], tx["fee"], "{item}");
            }
            let events = http(socket, "GET", "/api/v1/events", None);
            assert_eq!(events.status, 200, "{events:?}");
            // A 0.6.0 wallet's numbered link rows stand in the way of neither the address
            // nor a link made at it.
            let listed = http(socket, "GET", "/api/v1/addresses?type=epic1", None).ok();
            let address = listed["items"][0]["text"].as_str().unwrap();
            let link = http(socket, "POST", "/api/v1/links", Some(r#"{"amount":"1"}"#));
            assert_eq!(link.status, 200, "{link:?}");
            let text = link.json()["text"].as_str().unwrap().to_owned();
            assert!(text.starts_with(&format!("epic:{address}")), "{text}");
        },
    );
}

/// The payments API's name for a transaction state: one still waiting for the other side is
/// `awaiting_answer` (`serve/v1/payments/view.rs`); the other names are the same.
fn api_state(state: &Value) -> &str {
    match state.as_str().unwrap() {
        "sent" | "received" => "awaiting_answer",
        other => other,
    }
}

#[test]
fn a_second_open_changes_nothing() {
    a_second_open_changes_nothing_in(CLI_0_4_0);
}

#[test]
fn a_second_open_of_a_0_6_0_wallet_changes_nothing() {
    a_second_open_changes_nothing_in(CLI_0_6_0);
}

fn a_second_open_changes_nothing_in(fixture: Fixture) {
    let upgrade = Upgrade::new(fixture);
    let first = upgrade.listings();
    let second = upgrade.listings();
    assert_eq!(first, second);
    assert!(upgrade.has_the_api_tables());
    assert_eq!(upgrade.listings(), first);
}

/// A websocket text frame as a client sends it (RFC 6455): final, masked with a zero key, which
/// leaves the payload as it is.
fn client_text_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x81];
    match payload.len() {
        len @ 0..126 => frame.push(0x80 | u8::try_from(len).unwrap()),
        len @ 126..=0xffff => {
            frame.push(0x80 | 126);
            frame.extend(u16::try_from(len).unwrap().to_be_bytes());
        }
        len => {
            frame.push(0x80 | 127);
            frame.extend(u64::try_from(len).unwrap().to_be_bytes());
        }
    }
    frame.extend([0; 4]);
    frame.extend(payload);
    frame
}

/// Posts `messages` of a recorded mailbox to `to` on `relay` as `PostSlate` frames with
/// their recorded `from`, `str` and `signature`, byte for byte, and waits until the relay
/// holds them. The relay checks each signature as it would on a real post.
fn post_recorded(relay: &MockRelay, to: &EpicboxAddress, messages: &[&Value]) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let endpoint = RelayEndpoint::new(
            Domain::parse("127.0.0.1").unwrap(),
            Some(80),
            Security::Plain,
        );
        let mut stream = relay.connector().connect(&endpoint).await.unwrap();
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.extend(byte);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        let before = relay.pending(to);
        for message in messages {
            let frame = json!({
                "type": "PostSlate",
                "from": message["from"],
                "to": to.to_string(),
                "str": message["str"],
                "signature": message["signature"],
            })
            .to_string();
            stream
                .write_all(&client_text_frame(frame.as_bytes()))
                .await
                .unwrap();
        }
        stream.flush().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(10),
            relay.wait_until(|relay| relay.pending(to) == before + messages.len()),
        )
        .await
        .unwrap_or_else(|_| panic!("the relay did not take the recorded messages"));
    });
}

/// Puts the messages of `mailbox` (a recorded mailbox file of the 0.6.0 fixture) labelled
/// `labels` back on the relay, runs one `epicbox drain` of `upgrade`'s wallet and asserts
/// that it acknowledged every one: none is left for the address and the relay counted a `Made`
/// for each.
fn one_inbox_pass_takes(upgrade: &Upgrade, mailbox: &str, labels: &[&str]) {
    let recorded: Value = serde_json::from_str(&CLI_0_6_0.file(mailbox)).unwrap();
    let to = EpicboxAddress::parse(recorded["address"].as_str().unwrap(), RelayNetwork::Floonet)
        .unwrap();
    let messages: Vec<&Value> = recorded["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| labels.contains(&m["label"].as_str().unwrap()))
        .collect();
    assert_eq!(
        messages.len(),
        labels.len(),
        "{mailbox} lacks one of {labels:?}"
    );
    let relay = &upgrade.host.relay;
    post_recorded(relay, &to, &messages);
    let made = relay.received("Made");
    let drained = upgrade.wallet.run(&upgrade.host, &["epicbox", "drain"]);
    assert_eq!(
        relay.pending(&to),
        0,
        "left on the relay after one pass: {drained:?}"
    );
    assert_eq!(relay.received("Made") - made, messages.len(), "{drained:?}");
    assert_eq!(drained.code, 0, "{drained:?}");
}

// What one inbox pass of a 0.6.0 wallet does with the messages its relay held; see
// testdata/upgrade/cli-0.6.0/README.md for each message.

#[test]
fn a_0_6_0_open_marked_send_is_posted_with_its_recorded_reply() {
    let upgrade = Upgrade::new(CLI_0_6_0);
    let marked = upgrade.expected["ids"]["marked"].to_string();
    assert_eq!(upgrade.run(&["tx", "show", &marked])["state"], "sent");
    one_inbox_pass_takes(&upgrade, "mailbox.json", &["marked_reply"]);
    assert_eq!(upgrade.run(&["tx", "show", &marked])["state"], "posted");
    assert_eq!(upgrade.host.node.pushed_transactions().len(), 1);
}

#[test]
fn a_0_6_0_payer_receives_the_recorded_marked_send_and_answers_it() {
    let payer = Upgrade::open(CLI_0_6_0, "payer", PAYER_PASSWORD);
    let slate_id = payer.expected["ids"]["marked_slate"].clone();
    let sender: Value = serde_json::from_str(&CLI_0_6_0.file("mailbox.json")).unwrap();
    let sender =
        EpicboxAddress::parse(sender["address"].as_str().unwrap(), RelayNetwork::Floonet).unwrap();
    let answers = payer.host.relay.pending(&sender);
    one_inbox_pass_takes(&payer, "payer-mailbox.json", &["marked_s1"]);
    let list = payer.run(&["tx", "list"]);
    let received: Vec<&Value> = list["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|tx| tx["slate_id"] == slate_id)
        .collect();
    assert_eq!(received.len(), 1, "{list}");
    assert_eq!(received[0]["direction"], "incoming", "{list}");
    assert_eq!(received[0]["state"], "received", "{list}");
    assert_eq!(payer.host.relay.pending(&sender), answers + 1);
}

/// Asserts that `upgrade`'s wallet lists no invoice and holds no transaction of `slate_id`.
fn holds_no_invoice(upgrade: &Upgrade, slate_id: &Value) {
    let invoices = upgrade.run(&["invoice", "list"]);
    assert_eq!(invoices["invoices"], json!([]), "{invoices}");
    let list = upgrade.run(&["tx", "list"]);
    assert!(
        list["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tx| tx["slate_id"] != *slate_id),
        "{list}"
    );
}

#[test]
fn a_0_6_0_invoice_issuer_takes_the_recorded_incoming_invoice() {
    let issuer = Upgrade::new(CLI_0_6_0);
    one_inbox_pass_takes(&issuer, "mailbox.json", &["invoice_i1"]);
    holds_no_invoice(&issuer, &issuer.expected["ids"]["incoming_invoice_slate"]);
}

#[test]
fn a_0_6_0_invoice_payer_takes_the_recorded_open_invoice() {
    let payer = Upgrade::open(CLI_0_6_0, "payer", PAYER_PASSWORD);
    one_inbox_pass_takes(&payer, "payer-mailbox.json", &["invoice_i1"]);
    holds_no_invoice(&payer, &payer.expected["ids"]["open_invoice_slate"]);
}

/// The open Epicbox invoice (transaction 18) is never paid over Epicbox; the sweep of a drain
/// cancels it once it is older than the expiry. The fixture was made more than an hour ago,
/// so a one-hour expiry has passed.
#[test]
fn a_0_6_0_open_epicbox_invoice_ends_at_its_expiry() {
    let issuer = Upgrade::new(CLI_0_6_0);
    let tx_id = issuer.expected["made"]["open_invoice"]["tx_id"].clone();
    let open = tx_id.to_string();
    assert_eq!(issuer.run(&["tx", "show", &open])["state"], "received");
    let mut env = issuer.wallet.env();
    env.push(("LEPIC_INVOICE_EXPIRY_HOURS".to_owned(), "1".to_owned()));
    let drained = issuer
        .wallet
        .run_with(&issuer.host, &["epicbox", "drain"], env, "")
        .ok()
        .json();
    // The in-person invoice (transaction 15) is unpaid too and expires with it.
    assert!(
        drained["expired"]["cancelled"]
            .as_array()
            .unwrap()
            .contains(&tx_id),
        "{drained}"
    );
    assert_eq!(issuer.run(&["tx", "show", &open])["state"], "cancelled");
}

#[test]
fn a_0_6_0_wallet_takes_the_recorded_pair_request() {
    let upgrade = Upgrade::new(CLI_0_6_0);
    one_inbox_pass_takes(&upgrade, "mailbox.json", &["notice"]);
}

#[test]
fn a_0_6_0_wallet_takes_its_whole_recorded_mailbox() {
    let upgrade = Upgrade::new(CLI_0_6_0);
    one_inbox_pass_takes(
        &upgrade,
        "mailbox.json",
        &["sealed_slate", "notice", "invoice_i1", "marked_reply"],
    );
}
