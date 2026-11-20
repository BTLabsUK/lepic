// SPDX-License-Identifier: Apache-2.0
//! Generator of the `cli-0.4.0` upgrade fixture. Ignored: it runs by hand at the 0.4.0 commit
//! and writes the wallet a released CLI made into `$LEPIC_UPGRADE_OUT`.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::path::Path;

use lepic_node::LocatedKernel;
use lepic_node::mock::{ChainOutput, ChainState};
use lepic_primitives::amount::Height;
use lepic_primitives::ser::{ProtocolVersion, ser_vec};
use lepic_primitives::tx::Transaction;
use serde_json::{Value, json};
use support::{
    FUNDING, Instance, SENDER_MNEMONIC, TIP, TestHost, http, text, wait_for_socket, wait_until,
};

const SENDER_PASSWORD: &str = "upgrade fixture password";
const RECEIVER_PASSWORD: &str = "upgrade receiver password";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}

fn kernel_json(located: &LocatedKernel) -> Value {
    json!({
        "kernel": hex(&ser_vec(&located.kernel, ProtocolVersion::V2)),
        "height": located.height.value(),
        "mmr_index": located.mmr_index,
    })
}

/// The mock node's chain as the new tests read it back.
fn chain_json(chain: &ChainState, pushed: &[Transaction]) -> Value {
    json!({
        "version": {
            "node_version": chain.version.node_version,
            "block_header_version": chain.version.block_header_version,
        },
        "tip": {
            "height": chain.tip.height.value(),
            "last_block_pushed": chain.tip.last_block_pushed.to_hex(),
        },
        "outputs": chain.outputs.iter().map(|output| json!({
            "commitment": output.commitment.to_hex(),
            "features": output.features.as_u8(),
            "proof": output.proof.to_hex(),
            "height": output.height.value(),
            "mmr_index": output.mmr_index,
            "spent": output.spent,
        })).collect::<Vec<_>>(),
        "kernels": chain.kernels.iter().map(kernel_json).collect::<Vec<_>>(),
        "pool": chain.pool.iter()
            .map(|tx| hex(&ser_vec(tx, ProtocolVersion::V2)))
            .collect::<Vec<_>>(),
        "genesis_seconds": chain.genesis_time.as_second(),
        "header_times": chain.header_times.iter()
            .map(|(height, time)| json!([height.value(), time.as_second()]))
            .collect::<Vec<_>>(),
        "ready_for_txs": chain.ready_for_txs,
        "pushed": pushed.iter()
            .map(|tx| hex(&ser_vec(tx, ProtocolVersion::V2)))
            .collect::<Vec<_>>(),
    })
}

/// Puts every transaction pushed so far into a block at `height`, the new tip.
fn mine_pushed(host: &TestHost, height: u64) {
    let pushed = host.node.pushed_transactions();
    host.node.update_chain(|chain| {
        let height = Height::new(height);
        for transaction in &pushed {
            for input in transaction.inputs() {
                for output in &mut chain.outputs {
                    if output.commitment == input.commitment {
                        output.spent = true;
                    }
                }
            }
            for output in transaction.outputs() {
                let mmr_index = u64::try_from(chain.outputs.len()).unwrap() + 1;
                chain.outputs.push(ChainOutput {
                    commitment: output.commitment,
                    features: output.features,
                    proof: output.proof.clone(),
                    height,
                    mmr_index,
                    spent: false,
                });
            }
            for kernel in transaction.kernels() {
                let mmr_index = u64::try_from(chain.kernels.len()).unwrap() + 1;
                chain.kernels.push(LocatedKernel {
                    kernel: *kernel,
                    height,
                    mmr_index,
                });
            }
        }
        chain.tip.height = height;
    });
}

fn collect(instance: &Instance, host: &TestHost) -> Value {
    instance.run(host, &["contact", "collect"]).ok().json()
}

fn listed_state(instance: &Instance, host: &TestHost, contact_id: &str) -> String {
    let list = instance.run(host, &["contact", "list"]).ok().json();
    list["contacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|contact| contact["contact_id"] == contact_id)
        .map(|contact| contact["state"].as_str().unwrap().to_owned())
        .unwrap_or_default()
}

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

#[test]
#[ignore = "generator: run by hand with LEPIC_UPGRADE_OUT set"]
fn write_the_cli_fixture() {
    let out = std::path::PathBuf::from(std::env::var("LEPIC_UPGRADE_OUT").expect("LEPIC_UPGRADE_OUT"));
    let host = TestHost::new();
    host.fund(SENDER_MNEMONIC, 0, FUNDING, 1);
    host.fund(SENDER_MNEMONIC, 1, FUNDING, 2);
    let sender = Instance::new(SENDER_PASSWORD);
    let restored = sender.restore(&host, SENDER_MNEMONIC);
    assert_eq!(restored["scan"]["found"], 2, "{restored}");
    let receiver = Instance::new(RECEIVER_PASSWORD);
    receiver.run(&host, &["wallet", "init"]).ok();

    // A contact: the sender invites, the receiver accepts, both answer.
    let invite = sender
        .run(&host, &["contact", "invite", "--name", "Fixture friend"])
        .ok()
        .json();
    let joined = receiver
        .run(
            &host,
            &[
                "contact",
                "accept",
                text(&invite, "link"),
                "--name",
                "Fixture owner",
            ],
        )
        .ok()
        .json();
    let sender_side = text(&invite, "contact_id").to_owned();
    let receiver_side = text(&joined, "contact_id").to_owned();
    wait_until("both sides paired", || {
        collect(&sender, &host);
        collect(&receiver, &host);
        listed_state(&sender, &host, &sender_side) == "paired"
            && listed_state(&receiver, &host, &receiver_side) == "paired"
    });

    // Send A: mined and confirmed.
    let slate = sender.path("mined.slate");
    let sent = sender
        .run(
            &host,
            &[
                "tx",
                "send",
                "1.5",
                "--to-file",
                slate.to_str().unwrap(),
                "-m",
                "mined payment",
            ],
        )
        .ok()
        .json();
    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    sender
        .run(&host, &["tx", "finalize", text(&received, "reply_file")])
        .ok();
    mine_pushed(&host, TIP + 1);
    let shown = sender
        .run(&host, &["tx", "show", &sent["tx_id"].to_string(), "--refresh"])
        .ok()
        .json();
    assert_eq!(shown["state"], "confirmed", "{shown}");

    // Send C: made and cancelled, so its input is free again.
    let slate = sender.path("cancelled.slate");
    let cancelled = sender
        .run(
            &host,
            &[
                "tx",
                "send",
                "1",
                "--to-file",
                slate.to_str().unwrap(),
                "-m",
                "cancelled payment",
            ],
        )
        .ok()
        .json();
    let done = sender
        .run(&host, &["tx", "cancel", &cancelled["tx_id"].to_string()])
        .ok()
        .json();
    assert_eq!(done["state"], "cancelled");

    // Send B: pushed to the node and not mined when the generator stops.
    let slate = sender.path("pending.slate");
    let pending = sender
        .run(
            &host,
            &[
                "tx",
                "send",
                "2",
                "--to-file",
                slate.to_str().unwrap(),
                "-m",
                "pending payment",
            ],
        )
        .ok()
        .json();
    let received = receiver
        .run(&host, &["tx", "receive", slate.to_str().unwrap()])
        .ok()
        .json();
    let finalized = sender
        .run(&host, &["tx", "finalize", text(&received, "reply_file")])
        .ok()
        .json();
    assert_eq!(finalized["state"], "posted");
    assert_eq!(host.node.pushed_transactions().len(), 2);

    // What the build lists, through its own commands.
    let mut expected = serde_json::Map::new();
    let mut record = |name: &str, args: &[&str]| {
        let value = sender.run(&host, args).ok().json();
        expected.insert(name.to_owned(), value);
    };
    record("wallet_info", &["wallet", "info"]);
    record("wallet_address", &["wallet", "address"]);
    record("wallet_outputs", &["wallet", "outputs"]);
    record("tx_list", &["tx", "list"]);
    record("contact_list", &["contact", "list"]);
    let list = sender.run(&host, &["tx", "list"]).ok().json();
    let mut shown_all = serde_json::Map::new();
    for tx in list["transactions"].as_array().unwrap() {
        let id = tx["tx_id"].to_string();
        let shown = sender.run(&host, &["tx", "show", &id]).ok().json();
        shown_all.insert(id, shown);
    }
    expected.insert("tx_show".to_owned(), Value::Object(shown_all));
    let epic1 = sender.run(&host, &["epic1", "address"]);
    expected.insert(
        "epic1_address".to_owned(),
        json!({ "code": epic1.code, "stdout": epic1.stdout, "stderr": epic1.stderr }),
    );
    expected.insert(
        "ids".to_owned(),
        json!({
            "mined": sent["tx_id"],
            "mined_slate": sent["slate_id"],
            "cancelled": cancelled["tx_id"],
            "pending": pending["tx_id"],
            "pending_slate": pending["slate_id"],
            "contact": sender_side,
        }),
    );

    // The data directory must be quiet before it is copied; `serve` is not running.
    let _ = (http, wait_for_socket);
    let mut snapshot = None;
    host.node.update_chain(|chain| snapshot = Some(chain.clone()));
    let chain = chain_json(&snapshot.unwrap(), &host.node.pushed_transactions());

    std::fs::create_dir_all(&out).unwrap();
    copy_dir(&sender.data_dir(), &out.join("wallet"));
    std::fs::write(
        out.join("chain.json"),
        serde_json::to_string_pretty(&chain).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("expected.json"),
        serde_json::to_string_pretty(&Value::Object(expected)).unwrap(),
    )
    .unwrap();
}
