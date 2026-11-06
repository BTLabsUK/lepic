// SPDX-License-Identifier: Apache-2.0
//! Invoices by file through the binding, between wallets on the mock node: issued to anyone as
//! text or a file, paid, finalized and posted with the calls of a send, the refusals of an
//! answer that is not the payment of an invoice this wallet issued, and an unpaid invoice
//! withdrawn.

use super::kind;
use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, SlateStage, TxDirection, TxFlow, TxStatus, WalletConfig};
use crate::api::wallet::{EpicWallet, inspect_slate};

const EPIC: u64 = 100_000_000;

struct World {
    chain: MockChain,
    runtime: LepicRuntime,
    dirs: Vec<tempfile::TempDir>,
}

impl World {
    fn new() -> Self {
        let chain = MockChain::new(1).unwrap();
        let runtime = chain.runtime(LogLevel::Warn).unwrap();
        Self {
            chain,
            runtime,
            dirs: Vec::new(),
        }
    }

    fn dir(&mut self) -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        self.dirs.push(dir);
        path
    }

    async fn wallet(&mut self) -> EpicWallet {
        let config = WalletConfig {
            policy: Default::default(),
            data_dir: self.dir().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: String::new(),
            epicbox_port: 443,
            onion_routes: Vec::new(),
            tuning: crate::tuning::shipped(),
            offline: false,
            tor_wanted: false,
            host_features: 0,
            profile: 0,
            domain: None,
        };
        EpicWallet::create(
            &self.runtime,
            config,
            &AppSecretStore::in_memory(),
            None,
            None,
            "password".to_owned(),
        )
        .await
        .unwrap()
    }

    async fn funded(&mut self) -> EpicWallet {
        let wallet = self.wallet().await;
        let phrase = wallet.mnemonic("password".to_owned()).await.unwrap();
        self.chain
            .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
            .unwrap();
        self.chain.set_height(20);
        wallet.session().scan_to_tip().await;
        wallet
    }
}

/// `json` with its amount replaced, in the form the slate gives it.
fn with_amount(json: &str, amount: u64) -> String {
    let mut slate: serde_json::Value = serde_json::from_str(json).unwrap();
    let field = slate.get_mut("amount").unwrap();
    *field = match field {
        serde_json::Value::String(_) => serde_json::Value::String(amount.to_string()),
        _ => serde_json::Value::from(amount),
    };
    slate.to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invoice_by_text_is_paid_finalized_and_posted() {
    let mut world = World::new();
    let shop = world.wallet().await;
    let ben = world.funded().await;

    let i1 = shop
        .issue_invoice_slate(2 * EPIC, Some("order 17".to_owned()))
        .await
        .unwrap();
    let info = inspect_slate(i1.json.clone(), Chain::Floonet).unwrap();
    assert_eq!(info.stage, SlateStage::I1);
    assert_eq!(info.slate_id, i1.slate_id);
    assert_eq!(info.amount, 2 * EPIC);
    let waiting = shop.transaction(i1.tx_id).await.unwrap();
    assert_eq!(
        (waiting.direction, waiting.status, waiting.flow),
        (TxDirection::Incoming, TxStatus::Received, TxFlow::Invoice)
    );
    // An I1 is not an answer to finalize.
    assert_eq!(
        kind(shop.finalize_and_post(i1.json.clone()).await),
        WalletErrorKind::InvalidSlate
    );

    assert_eq!(
        kind(
            ben.pay_invoice_slate(i1.json.clone(), EPIC, 1, None, None)
                .await
        ),
        WalletErrorKind::AmountMismatch
    );
    let paid = ben
        .pay_invoice_slate(i1.json.clone(), 2 * EPIC, 1, Some("paid".to_owned()), None)
        .await
        .unwrap();
    assert_eq!(paid.slate_id, i1.slate_id);
    assert_eq!(paid.amount, 2 * EPIC);
    assert!(paid.fee > 0);
    assert_eq!(
        inspect_slate(paid.json.clone(), Chain::Floonet)
            .unwrap()
            .stage,
        SlateStage::I2
    );
    assert_eq!(
        ben.transaction(paid.tx_id).await.unwrap().status,
        TxStatus::Sent
    );
    assert_eq!(
        kind(
            ben.pay_invoice_slate(i1.json, 2 * EPIC, 1, None, None)
                .await
        ),
        WalletErrorKind::InvoiceAlreadyPaid
    );

    let finalized = shop.finalize_and_post(paid.json.clone()).await.unwrap();
    assert_eq!(finalized.tx_id, i1.tx_id);
    assert_eq!(finalized.slate_id, i1.slate_id);
    assert_eq!(world.chain.pushed_count(), 1);
    assert_eq!(
        shop.transaction(i1.tx_id).await.unwrap().status,
        TxStatus::Posted
    );
    // The same answer again returns what was stored and posts nothing new.
    assert_eq!(
        shop.finalize_and_post(paid.json).await.unwrap().tx_id,
        i1.tx_id
    );
    assert_eq!(world.chain.pushed_count(), 1);
}

/// `json` with its TTL cutoff set to `cutoff`, as the V3 shape writes it.
fn with_ttl_cutoff(json: &str, cutoff: u64) -> String {
    let mut slate: serde_json::Value = serde_json::from_str(json).unwrap();
    slate["ttl_cutoff_height"] = serde_json::Value::String(cutoff.to_string());
    slate.to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_invoice_lives_a_day_and_one_for_another_chain_is_refused() {
    let mut world = World::new();
    let shop = world.wallet().await;
    let ben = world.funded().await;

    let before = ben.transactions().await.unwrap().len();
    let i1 = shop.issue_invoice_slate(2 * EPIC, None).await.unwrap();
    let slate: serde_json::Value = serde_json::from_str(&i1.json).unwrap();
    assert_eq!(slate["ttl_cutoff_height"], "1460", "tip 20 plus a day");

    // A mainnet request read on floonet: its cutoff lies far above this chain's tip.
    assert_eq!(
        kind(
            ben.pay_invoice_slate(
                with_ttl_cutoff(&i1.json, 3_771_440),
                2 * EPIC,
                1,
                None,
                None
            )
            .await
        ),
        WalletErrorKind::InvoiceNotForThisChain
    );
    assert_eq!(ben.transactions().await.unwrap().len(), before);

    let paid = ben
        .pay_invoice_slate(i1.json, 2 * EPIC, 1, None, None)
        .await
        .unwrap();
    let i2: serde_json::Value = serde_json::from_str(&paid.json).unwrap();
    assert_eq!(
        i2["ttl_cutoff_height"], "1460",
        "the payer keeps the issuer's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_finalizes_only_an_invoice_this_wallet_issued_unchanged() {
    let mut world = World::new();
    let shop = world.wallet().await;
    let carl = world.wallet().await;
    let ben = world.funded().await;
    let i1 = shop.issue_invoice_slate(2 * EPIC, None).await.unwrap();
    let paid = ben
        .pay_invoice_slate(i1.json, 2 * EPIC, 1, None, None)
        .await
        .unwrap();

    // Another wallet issued no invoice under that slate id.
    assert_eq!(
        kind(carl.finalize_and_post(paid.json.clone()).await),
        WalletErrorKind::InvalidSlate
    );
    for amount in [EPIC, 3 * EPIC] {
        assert_eq!(
            kind(
                shop.finalize_and_post(with_amount(&paid.json, amount))
                    .await
            ),
            WalletErrorKind::InvoiceChanged
        );
    }
    assert_eq!(world.chain.pushed_count(), 0);

    // The answer to a send still goes to the finalize of a send.
    let dana = world.funded().await;
    let s1 = dana.create_send_slate(EPIC, 1, None, None).await.unwrap();
    let s2 = carl.receive_slate(s1.json).await.unwrap();
    assert_eq!(
        kind(shop.finalize_and_post(s2.json.clone()).await),
        WalletErrorKind::InvalidSlate
    );
    assert_eq!(
        dana.finalize_and_post(s2.json).await.unwrap().tx_id,
        s1.tx_id
    );

    shop.finalize_and_post(paid.json).await.unwrap();
    assert_eq!(world.chain.pushed_count(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unpaid_invoice_by_file_is_withdrawn_and_a_late_payment_refused() {
    let mut world = World::new();
    let shop = world.wallet().await;
    let ben = world.funded().await;
    let path = world.dir().join("invoice.tx");
    let text = path.to_string_lossy().into_owned();

    let issued = shop
        .issue_invoice_file(EPIC, text.clone(), None)
        .await
        .unwrap();
    assert_eq!(issued.amount, EPIC);
    let info = inspect_slate(std::fs::read_to_string(&path).unwrap(), Chain::Floonet).unwrap();
    assert_eq!(info.stage, SlateStage::I1);
    assert_eq!(info.slate_id, issued.slate_id);

    let paid = ben
        .pay_invoice_file(text.clone(), EPIC, 1, None, None)
        .await
        .unwrap();
    let response = format!("{text}.response");
    assert_eq!(std::fs::read_to_string(&response).unwrap(), paid.json);

    shop.cancel_transaction(issued.tx_id).await.unwrap();
    assert_eq!(
        shop.transaction(issued.tx_id).await.unwrap().status,
        TxStatus::Cancelled
    );
    assert_eq!(
        kind(shop.finalize_file(response).await),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(world.chain.pushed_count(), 0);
    ben.cancel_transaction(paid.tx_id).await.unwrap();
    assert_eq!(
        ben.transaction(paid.tx_id).await.unwrap().status,
        TxStatus::Cancelled
    );

    assert_eq!(
        kind(shop.issue_invoice_slate(0, None).await),
        WalletErrorKind::InvalidArgument
    );
}
