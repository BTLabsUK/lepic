// SPDX-License-Identifier: Apache-2.0
//! A send over Epicbox whose delivery failed: reported as undelivered, and delivered again to
//! the address it was sent to with `resend_epicbox`.

use std::sync::Arc;

use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{EpicboxAddress, Network as RelayNetwork};

use super::kind;
use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, WalletConfig};
use crate::api::wallet::EpicWallet;

const EPIC: u64 = 100_000_000;

struct World {
    chain: MockChain,
    runtime: LepicRuntime,
    relay: MockRelay,
    _dirs: Vec<tempfile::TempDir>,
}

impl World {
    fn new() -> Self {
        let chain = MockChain::new(1).unwrap();
        let mut runtime = chain.runtime(LogLevel::Warn).unwrap();
        let relay = MockRelay::new(RelayNetwork::Floonet);
        Arc::get_mut(&mut runtime.inner).unwrap().relay = Some(relay.connector());
        Self {
            chain,
            runtime,
            relay,
            _dirs: Vec::new(),
        }
    }

    async fn wallet(&mut self) -> EpicWallet {
        let dir = tempfile::tempdir().unwrap();
        let config = WalletConfig {
            policy: Default::default(),
            data_dir: dir.path().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: "epicbox.example".to_owned(),
            epicbox_port: 443,
            onion_routes: Vec::new(),
            tuning: crate::tuning::shipped(),
            offline: false,
            tor_wanted: false,
            host_features: 0,
            profile: 0,
        };
        self._dirs.push(dir);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_send_is_undelivered_and_resend_epicbox_posts_it_to_the_same_address() {
    let mut world = World::new();
    let sender = world.funded().await;
    let refusing = world.wallet().await.epicbox_address().await.unwrap();
    world
        .relay
        .set_post_refused(&EpicboxAddress::parse(&refusing, RelayNetwork::Floonet).unwrap());

    let error = sender
        .send_epicbox(EPIC, 1, refusing, None, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind, WalletErrorKind::TransportFailed);
    let transactions = sender.transactions().await.unwrap();
    let tx = transactions
        .iter()
        .find(|tx| tx.direction == crate::api::types::TxDirection::Outgoing)
        .unwrap();
    assert!(tx.undelivered);
    let posts = world.relay.received("PostSlate");

    assert_eq!(
        kind(sender.resend_epicbox(tx.tx_id).await),
        WalletErrorKind::TransportFailed
    );
    assert_eq!(world.relay.received("PostSlate"), posts + 1);
    assert!(sender.transaction(tx.tx_id).await.unwrap().undelivered);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivered_send_is_not_undelivered_and_resend_epicbox_posts_it_again() {
    let mut world = World::new();
    let sender = world.funded().await;
    let receiver = world.wallet().await.epicbox_address().await.unwrap();

    let sent = sender
        .send_epicbox(EPIC, 1, receiver, None, None)
        .await
        .unwrap();
    assert!(!sender.transaction(sent.tx_id).await.unwrap().undelivered);
    let posts = world.relay.received("PostSlate");

    sender.resend_epicbox(sent.tx_id).await.unwrap();
    assert_eq!(world.relay.received("PostSlate"), posts + 1);
    assert_eq!(
        kind(sender.resend_epicbox(sent.tx_id + 100).await),
        WalletErrorKind::InvalidArgument
    );
}
