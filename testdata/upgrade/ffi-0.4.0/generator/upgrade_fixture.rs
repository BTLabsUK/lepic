// SPDX-License-Identifier: Apache-2.0
//! Generator of the FFI upgrade fixtures. Ignored: it runs by hand at the old commit, with
//! `LEPIC_UPGRADE_OUT` set to a directory and `LEPIC_UPGRADE_KIND` set to `desktop` (the wallet
//! is made with `EpicWallet::create` and a password) or `mobile` (with
//! `EpicWallet::create_with_pin`). It writes the wallet a released build made.

use std::path::Path;
use std::sync::Arc;

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;
use lepic_node::LocatedKernel;
use lepic_node::mock::ChainState;
use lepic_primitives::ser::{ProtocolVersion, ser_vec};
use lepic_primitives::tx::Transaction;
use serde_json::{Value, json};

use crate::api::diagnostics::LogLevel;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{
    Chain, CollectTrigger, ContactKind, ContactRelayMode, InviteExpiry, PairingClass, TxStatus,
    WalletConfig,
};
use crate::api::wallet::EpicWallet;

const EPIC: u64 = 100_000_000;
const RELAY: &str = "relay.example.org";
const PASSWORD: &str = "upgrade fixture password";
const PIN: &str = "471100";
/// Every key the library keeps in the app's secret store.
const STORE_KEYS: [&str; 5] = [
    "lepic.vault",
    "lepic.vault-next",
    "lepic.pin-key",
    "lepic.pin-key-pending",
    "lepic.pin-failures",
];

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

fn config(dir: &Path) -> WalletConfig {
    WalletConfig {
        policy: Default::default(),
        data_dir: dir.to_string_lossy().into_owned(),
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

fn dbg<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "generator: run by hand with LEPIC_UPGRADE_OUT and LEPIC_UPGRADE_KIND set"]
#[allow(clippy::too_many_lines)]
async fn write_the_ffi_fixture() {
    let out = std::path::PathBuf::from(std::env::var("LEPIC_UPGRADE_OUT").unwrap());
    let kind = std::env::var("LEPIC_UPGRADE_KIND").unwrap();
    let mobile = match kind.as_str() {
        "desktop" => false,
        "mobile" => true,
        other => panic!("LEPIC_UPGRADE_KIND is desktop or mobile, not {other}"),
    };

    let chain = MockChain::new(1).unwrap();
    let mut runtime = chain.runtime(LogLevel::Warn).unwrap();
    let relay = MockRelay::new(RelayNetwork::Floonet);
    Arc::get_mut(&mut runtime.inner).unwrap().relay = Some(relay.connector());

    let wallet_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let store = AppSecretStore::in_memory();
    let (alice, sealed, phrase) = if mobile {
        let created = EpicWallet::create_with_pin(
            &runtime,
            config(wallet_dir.path()),
            &store,
            None,
            None,
            PIN.to_owned(),
        )
        .await
        .unwrap();
        let phrase = created
            .wallet
            .mnemonic_with_pin(PIN.to_owned(), created.sealed_password.clone())
            .await
            .unwrap();
        (created.wallet, Some(created.sealed_password), phrase)
    } else {
        let wallet = EpicWallet::create(
            &runtime,
            config(wallet_dir.path()),
            &store,
            None,
            None,
            PASSWORD.to_owned(),
        )
        .await
        .unwrap();
        let phrase = wallet.mnemonic(PASSWORD.to_owned()).await.unwrap();
        (wallet, None, phrase)
    };
    let bob = EpicWallet::create(
        &runtime,
        config(bob_dir.path()),
        &AppSecretStore::in_memory(),
        None,
        None,
        "password".to_owned(),
    )
    .await
    .unwrap();

    // A contact: Alice invites, Bob accepts, both answer.
    let online = ContactRelayMode::Online;
    let meeting = vec![RELAY.to_owned()];
    let invite = alice
        .pairing_invite(
            "Fixture friend".to_owned(),
            ContactKind::Person,
            InviteExpiry::OneDay,
            false,
            online,
            meeting,
            None,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    let answer = bob
        .pairing_accept(
            invite.link,
            "Fixture owner".to_owned(),
            false,
            online,
            PairingClass::Contact,
            None,
        )
        .await
        .unwrap();
    assert!(answer.posted);
    assert_eq!(
        alice
            .contacts_collect(CollectTrigger::Open, online, None)
            .await
            .unwrap()
            .paired,
        1
    );
    assert_eq!(
        bob.contacts_collect(CollectTrigger::Pull, online, None)
            .await
            .unwrap()
            .paired,
        1
    );
    alice
        .contacts_collect(CollectTrigger::Pull, online, None)
        .await
        .unwrap();

    // Two received outputs.
    chain
        .fund(phrase.clone(), Chain::Floonet, 10 * EPIC, 0)
        .unwrap();
    chain
        .fund(phrase.clone(), Chain::Floonet, 10 * EPIC, 1)
        .unwrap();
    chain.set_height(20);
    alice.session().scan_to_tip().await;

    // Send A: mined and confirmed.
    let slate = alice
        .create_send_slate(3 * EPIC / 2, 1, Some("mined payment".to_owned()), None)
        .await
        .unwrap();
    let reply = bob.receive_slate(slate.json.clone()).await.unwrap();
    let finalized = alice.finalize_and_post(reply.json).await.unwrap();
    assert!(finalized.posted);
    let mined = slate.tx_id;
    assert_eq!(chain.pushed_count(), 1);
    chain.mine_pushed();
    chain.set_height(30);
    alice.summary(true).await.unwrap();
    let tx = alice.transaction(mined).await.unwrap();
    assert_eq!(tx.status, TxStatus::Confirmed, "{tx:?}");

    // Send C: made and cancelled, so its inputs are free again.
    let slate = alice
        .create_send_slate(EPIC, 1, Some("cancelled payment".to_owned()), None)
        .await
        .unwrap();
    alice.cancel_transaction(slate.tx_id).await.unwrap();
    let cancelled = slate.tx_id;

    // Send B: pushed to the node and not mined when the generator stops.
    let slate = alice
        .create_send_slate(2 * EPIC, 1, Some("pending payment".to_owned()), None)
        .await
        .unwrap();
    let reply = bob.receive_slate(slate.json.clone()).await.unwrap();
    let finalized = alice.finalize_and_post(reply.json).await.unwrap();
    assert!(finalized.posted);
    assert_eq!(chain.pushed_count(), 2);
    let pending = slate.tx_id;

    let mut expected = listed(&alice).await;
    expected["ids"] = json!({
        "mined": mined,
        "cancelled": cancelled,
        "pending": pending,
        "contact": invite.contact_id,
    });
    expected["store_at_rest"] = json!(dbg(&alice.store_at_rest().await.unwrap()));

    let (snapshot, pushed) = chain.backend().snapshot();
    let chain_out = chain_json(&snapshot, &pushed);

    let mut secrets = serde_json::Map::new();
    for key in STORE_KEYS {
        if let Some(value) = store.read(key).await.unwrap() {
            secrets.insert(key.to_owned(), Value::String(value));
        }
    }
    let secrets = json!({ "store": secrets, "sealed_password": sealed, "pin": mobile.then_some(PIN) });

    // Close the wallet before its directory is copied.
    alice.lock();
    drop(alice);
    drop(bob);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    std::fs::create_dir_all(&out).unwrap();
    copy_dir(wallet_dir.path(), &out.join("wallet"));
    std::fs::write(
        out.join("chain.json"),
        serde_json::to_string_pretty(&chain_out).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("expected.json"),
        serde_json::to_string_pretty(&expected).unwrap(),
    )
    .unwrap();
    std::fs::write(
        out.join("secrets.json"),
        serde_json::to_string_pretty(&secrets).unwrap(),
    )
    .unwrap();
    std::fs::write(out.join("mnemonic.txt"), format!("{phrase}\n")).unwrap();
}
