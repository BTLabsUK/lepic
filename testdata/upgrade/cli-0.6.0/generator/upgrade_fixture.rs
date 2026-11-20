// SPDX-License-Identifier: Apache-2.0
//! Generator of the `cli-0.6.0` upgrade fixture. Ignored: it runs by hand at the 0.6.0 tag,
//! with `mock_relay_waiting.patch` applied, and writes the stores a released CLI made, and
//! the mailboxes the mock relay held for them, into `$LEPIC_UPGRADE_OUT`.

use std::path::Path;

use lepic_epicbox::EpicboxAddress;
use lepic_epicbox::Network as RelayNetwork;
use lepic_node::LocatedKernel;
use lepic_node::mock::{ChainOutput, ChainState};
use lepic_primitives::amount::Height;
use lepic_primitives::ser::{ProtocolVersion, ser_vec};
use lepic_primitives::tx::Transaction;
use serde_json::{Value, json};

use crate::support::{
    FUNDING, Instance, Outcome, SENDER_MNEMONIC, TIP, TestHost, text, wait_until,
};

const SENDER_PASSWORD: &str = "upgrade fixture password";
const RECEIVER_PASSWORD: &str = "upgrade receiver password";
const PEER_PASSWORD: &str = "upgrade peer password";
/// Outputs funded for the main wallet: one per send that is open at the same time.
const FUNDED: u32 = 9;

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

/// Puts every transaction pushed and not yet mined into a block at `height`, the new tip.
fn mine_pushed(host: &TestHost, height: u64, mined: &mut usize) {
    let pushed = host.node.pushed_transactions();
    let fresh = pushed[*mined..].to_vec();
    *mined = pushed.len();
    host.node.update_chain(|chain| {
        let height = Height::new(height);
        for transaction in &fresh {
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

/// The instance's environment with `extra` set.
fn env_with(instance: &Instance, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut env = instance.env();
    for (name, value) in extra {
        env.retain(|(have, _)| have != name);
        env.push(((*name).to_owned(), (*value).to_owned()));
    }
    env
}

const NATIVE: (&str, &str) = ("LEPIC_NATIVE_DIRECT", "true");
/// The relay under a public name, so epic1 links and in-person codes can name it.
const PUBLIC: (&str, &str) = ("LEPIC_EPICBOX_RELAY", "wss://relay.example.org");

fn outcome_json(outcome: &Outcome) -> Value {
    json!({ "code": outcome.code, "stdout": outcome.stdout, "stderr": outcome.stderr })
}

/// A mailbox the mock relay holds, each message labelled by the step that put it there.
struct Mailbox {
    address: EpicboxAddress,
    labels: Vec<String>,
}

impl Mailbox {
    fn new(text: &str) -> Self {
        Self {
            address: EpicboxAddress::parse(text, RelayNetwork::Floonet).unwrap(),
            labels: Vec::new(),
        }
    }

    /// Labels every message that arrived since the last call.
    fn arrived(&mut self, host: &TestHost, label: &str) {
        let waiting = host.relay.waiting(&self.address).len();
        assert!(waiting > self.labels.len(), "no message for {label}");
        while self.labels.len() < waiting {
            self.labels.push(label.to_owned());
        }
    }

    fn json(&self, host: &TestHost) -> Value {
        let waiting = host.relay.waiting(&self.address);
        assert_eq!(waiting.len(), self.labels.len(), "unlabelled messages");
        json!({
            "address": self.address.to_string(),
            "messages": waiting.iter().zip(&self.labels).map(|((from, str, signature, txid), label)| json!({
                "label": label,
                "from": from,
                "str": str,
                "signature": signature,
                "txid": txid,
            })).collect::<Vec<_>>(),
        })
    }
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

#[test]
#[ignore = "generator: run by hand with LEPIC_UPGRADE_OUT set"]
// One story in order: splitting it would scatter the wallets the steps share.
#[allow(clippy::too_many_lines)]
fn write_the_cli_fixture() {
    let out =
        std::path::PathBuf::from(std::env::var("LEPIC_UPGRADE_OUT").expect("LEPIC_UPGRADE_OUT"));
    let host = TestHost::new();
    for child in 0..FUNDED {
        host.fund(SENDER_MNEMONIC, child, FUNDING, u64::from(child) + 1);
    }
    let mut mined = 0;
    let sender = Instance::new(SENDER_PASSWORD);
    let restored = sender.restore(&host, SENDER_MNEMONIC);
    assert_eq!(restored["scan"]["found"], FUNDED, "{restored}");
    let receiver = Instance::new(RECEIVER_PASSWORD);
    receiver.run(&host, &["wallet", "init"]).ok();
    let peer = Instance::new(PEER_PASSWORD);
    peer.run(&host, &["wallet", "init"]).ok();
    let address = |instance: &Instance| {
        let shown = instance.run(&host, &["wallet", "address"]).ok().json();
        text(&shown, "address").to_owned()
    };
    let sender_address = address(&sender);
    let peer_address = address(&peer);
    let mut sender_mail = Mailbox::new(&sender_address);
    let mut peer_mail = Mailbox::new(&peer_address);

    // A paired contact: the sender invites, the receiver accepts, both answer.
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

    // A pending pairing: an invite nobody accepts.
    let pending_invite = sender
        .run(&host, &["contact", "invite", "--name", "Pending friend"])
        .ok()
        .json();

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
    mine_pushed(&host, TIP + 1, &mut mined);
    let shown = sender
        .run(
            &host,
            &["tx", "show", &sent["tx_id"].to_string(), "--refresh"],
        )
        .ok()
        .json();
    assert_eq!(shown["state"], "confirmed", "{shown}");

    // An Epicbox payment to the peer, so each knows the other runs LEPIC.
    let paid = sender
        .run(
            &host,
            &[
                "tx",
                "send",
                "1",
                "--to",
                &peer_address,
                "-m",
                "epicbox payment",
            ],
        )
        .ok()
        .json();
    peer.run(&host, &["epicbox", "drain"]).ok();
    let drained = sender.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(drained["finalized"], 1, "{drained}");
    // An Epicbox payment to a fourth wallet, so it may ask the sender to pair later.
    let stranger = Instance::new("upgrade stranger password");
    stranger.run(&host, &["wallet", "init"]).ok();
    let stranger_address = address(&stranger);
    sender
        .run(
            &host,
            &[
                "tx",
                "send",
                "0.5",
                "--to",
                &stranger_address,
                "-m",
                "stranger payment",
            ],
        )
        .ok();
    stranger.run(&host, &["epicbox", "drain"]).ok();
    let drained = sender.run(&host, &["epicbox", "drain"]).ok().json();
    assert_eq!(drained["finalized"], 1, "{drained}");
    mine_pushed(&host, TIP + 2, &mut mined);

    // A pending pair request by Epicbox address.
    let request = sender
        .run(
            &host,
            &[
                "contact",
                "request",
                &peer_address,
                "--name",
                "Fixture peer",
            ],
        )
        .ok()
        .json();

    // A native send: its sealed answer waits in the sender's mailbox.
    let native = sender
        .run_with(
            &host,
            &[
                "tx",
                "send",
                "1",
                "--to",
                &peer_address,
                "-m",
                "native payment",
            ],
            env_with(&sender, &[NATIVE]),
            "",
        )
        .ok()
        .json();
    let peer_drained = peer
        .run_with(&host, &["epicbox", "drain"], env_with(&peer, &[NATIVE]), "")
        .ok()
        .json();
    sender_mail.arrived(&host, "sealed_slate");
    // A notice: the fourth wallet asks the sender to pair, by Epicbox address.
    let stranger_request = stranger
        .run(
            &host,
            &[
                "contact",
                "request",
                &sender_address,
                "--name",
                "Fixture sender",
            ],
        )
        .ok()
        .json();
    sender_mail.arrived(&host, "notice");

    // An I1 from the peer to the sender.
    let incoming_invoice = peer
        .run(&host, &["invoice", "issue", "1.5", "--to", &sender_address])
        .ok()
        .json();
    sender_mail.arrived(&host, "invoice_i1");

    // For the watch set: an epic1 link of the peer's paid by the sender (the sender's reply
    // mailbox), a link of the sender's own, and an in-person invoice of the sender's.
    let peer_link = peer.run_with(
        &host,
        &["epic1", "link", "--printed", "1"],
        env_with(&peer, &[PUBLIC]),
        "",
    );
    let epic1_pay = (peer_link.code == 0).then(|| {
        let link = peer_link.json()["link"].as_str().unwrap().to_owned();
        sender.run_with(
            &host,
            &["epic1", "pay", &link, "1"],
            env_with(&sender, &[PUBLIC]),
            "",
        )
    });
    let sender_link = sender.run_with(
        &host,
        &[
            "epic1",
            "link",
            "--printed",
            "2",
            "--message",
            "fixture link",
        ],
        env_with(&sender, &[PUBLIC]),
        "",
    );
    let in_person = sender.run_with(
        &host,
        &["in-person", "invoice", "1"],
        env_with(&sender, &[PUBLIC]),
        "",
    );

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

    // The open Epicbox invoice: issued here, its I1 waits unread in the peer's mailbox. LEPIC
    // 0.6.0 parks only a paired contact's invoice and refuses a plain Epicbox I1, so the payer
    // store holds nothing of it.
    let open_invoice = sender
        .run(&host, &["invoice", "issue", "1", "--to", &peer_address])
        .ok()
        .json();
    peer_mail.arrived(&host, "invoice_i1");

    // The payer store as it is before the open invoice and the marked send reach it.
    let peer_lists = json!({
        "invoice_list": peer.run(&host, &["invoice", "list"]).ok().json(),
        "contact_requests": peer.run(&host, &["contact", "requests"]).ok().json(),
        "tx_list": peer.run(&host, &["tx", "list"]).ok().json(),
    });
    std::fs::create_dir_all(&out).unwrap();
    copy_dir(&peer.data_dir(), &out.join("payer"));

    // The open marked send: an S1 to the peer's classic address, unanswered in the sender's
    // store. The peer's answer to it waits in the sender's mailbox.
    let marked = sender
        .run(
            &host,
            &[
                "tx",
                "send",
                "1.25",
                "--to",
                &peer_address,
                "-m",
                "marked payment",
            ],
        )
        .ok()
        .json();
    peer_mail.arrived(&host, "marked_s1");
    let payer_mailbox = peer_mail.json(&host);
    let answered = peer.run(&host, &["epicbox", "drain"]).ok().json();
    sender_mail.arrived(&host, "marked_reply");

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
    record("invoice_list", &["invoice", "list"]);
    record("contact_requests", &["contact", "requests"]);
    record("epic1_links", &["epic1", "links"]);
    let list = sender.run(&host, &["tx", "list"]).ok().json();
    let mut shown_all = serde_json::Map::new();
    for tx in list["transactions"].as_array().unwrap() {
        let id = tx["tx_id"].to_string();
        let shown = sender.run(&host, &["tx", "show", &id]).ok().json();
        shown_all.insert(id, shown);
    }
    expected.insert("tx_show".to_owned(), Value::Object(shown_all));
    let epic1 = sender.run(&host, &["epic1", "address"]);
    expected.insert("epic1_address".to_owned(), outcome_json(&epic1));
    expected.insert("payer".to_owned(), peer_lists);
    expected.insert(
        "made".to_owned(),
        json!({
            "pending_invite": pending_invite,
            "request": request,
            "open_invoice": open_invoice,
            "stranger_request": stranger_request,
            "native": native,
            "peer_drained": peer_drained,
            "incoming_invoice": incoming_invoice,
            "peer_link": outcome_json(&peer_link),
            "epic1_pay": epic1_pay.as_ref().map(outcome_json),
            "sender_link": outcome_json(&sender_link),
            "in_person": outcome_json(&in_person),
            "marked": marked,
            "answered": answered,
        }),
    );
    expected.insert(
        "ids".to_owned(),
        json!({
            "mined": sent["tx_id"],
            "mined_slate": sent["slate_id"],
            "epicbox": paid["tx_id"],
            "cancelled": cancelled["tx_id"],
            "pending": pending["tx_id"],
            "pending_slate": pending["slate_id"],
            "contact": sender_side,
            "pending_contact": pending_invite["contact_id"],
            "request_contact": request["contact_id"],
            "native": native["tx_id"],
            "native_slate": native["slate_id"],
            "marked": marked["tx_id"],
            "marked_slate": marked["slate_id"],
            "open_invoice_slate": open_invoice["slate_id"],
            "incoming_invoice_slate": incoming_invoice["slate_id"],
            "peer_address": peer_address,
        }),
    );

    // The data directories must be quiet before they are copied; `serve` is not running.
    let mut snapshot = None;
    host.node
        .update_chain(|chain| snapshot = Some(chain.clone()));
    let chain = chain_json(
        &snapshot.unwrap(),
        &host.node.pushed_transactions()[mined..],
    );
    copy_dir(&sender.data_dir(), &out.join("wallet"));
    write_json(&out.join("chain.json"), &chain);
    write_json(&out.join("expected.json"), &Value::Object(expected));
    write_json(&out.join("mailbox.json"), &sender_mail.json(&host));
    write_json(&out.join("payer-mailbox.json"), &payer_mailbox);
}
