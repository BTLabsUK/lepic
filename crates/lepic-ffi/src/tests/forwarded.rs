// SPDX-License-Identifier: Apache-2.0
//! `notice_apply_forwarded` of a notice about a payment made over Epicbox, taken by a session
//! that has no relay configured: a declined send is cancelled and its inputs freed, and a
//! received payment its sender cancelled is reported.

use std::sync::Arc;

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;

use crate::api::diagnostics::LogLevel;
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, OutputStatus, TxStatus, WalletConfig};
use crate::api::wallet::EpicWallet;

const EPIC: u64 = 100_000_000;

const PASSWORD: &str = "password";

struct World {
    chain: MockChain,
    runtime: LepicRuntime,
    _relay: MockRelay,
}

/// A wallet's folder and store, to open it again with or without a relay.
struct Install {
    dir: tempfile::TempDir,
    store: AppSecretStore,
}

impl Install {
    fn config(&self, relay: bool) -> WalletConfig {
        WalletConfig {
            policy: Default::default(),
            data_dir: self.dir.path().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: if relay { "epicbox.example" } else { "" }.to_owned(),
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
            _relay: relay,
        }
    }

    /// A new wallet with the relay, and its install.
    async fn wallet(&self) -> (EpicWallet, Install) {
        let install = Install {
            dir: tempfile::tempdir().unwrap(),
            store: AppSecretStore::in_memory(),
        };
        let wallet = EpicWallet::create(
            &self.runtime,
            install.config(true),
            &install.store,
            None,
            None,
            PASSWORD.to_owned(),
        )
        .await
        .unwrap();
        (wallet, install)
    }

    async fn funded(&self) -> (EpicWallet, Install) {
        let (wallet, install) = self.wallet().await;
        let phrase = wallet.mnemonic(PASSWORD.to_owned()).await.unwrap();
        self.chain
            .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
            .unwrap();
        self.chain.set_height(20);
        wallet.session().scan_to_tip().await;
        (wallet, install)
    }

    /// `install` opened again with no relay configured.
    async fn without_relay(&self, install: &Install) -> EpicWallet {
        EpicWallet::open(
            &self.runtime,
            install.config(false),
            &install.store,
            PASSWORD.to_owned(),
        )
        .await
        .unwrap()
    }
}

fn notice(kind: &str, slate_id: &str) -> String {
    format!(r#"{{"lepic":1,"type":"{kind}","slate_id":"{slate_id}"}}"#)
}

async fn locked(wallet: &EpicWallet) -> usize {
    wallet
        .outputs()
        .await
        .unwrap()
        .iter()
        .filter(|output| output.status == OutputStatus::Locked)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarded_decline_cancels_an_epicbox_send_without_a_relay() {
    let world = World::new();
    let (sender, install) = world.funded().await;
    let (receiver, _receiver_install) = world.wallet().await;
    let to = receiver.epicbox_address().await.unwrap();
    let sent = sender
        .send_epicbox(EPIC, 1, to.clone(), None, None)
        .await
        .unwrap();
    drop(sender);

    let sender = world.without_relay(&install).await;
    assert!(locked(&sender).await > 0);
    assert!(
        sender
            .notice_apply_forwarded(to, notice("declined", &sent.slate_id))
            .await
            .unwrap()
    );
    assert_eq!(
        sender.transaction(sent.tx_id).await.unwrap().status,
        TxStatus::Cancelled
    );
    assert_eq!(locked(&sender).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forwarded_cancel_of_an_epicbox_payment_is_taken_without_a_relay() {
    let world = World::new();
    let (sender, _sender_install) = world.funded().await;
    let (receiver, install) = world.wallet().await;
    let (other, _other_install) = world.wallet().await;
    let from = sender.epicbox_address().await.unwrap();
    let stranger = other.epicbox_address().await.unwrap();
    let to = receiver.epicbox_address().await.unwrap();
    let sent = sender.send_epicbox(EPIC, 1, to, None, None).await.unwrap();
    assert_eq!(receiver.drain_epicbox().await.unwrap().received, 1);
    drop(receiver);

    let receiver = world.without_relay(&install).await;
    // Only the payment's sender is heard.
    assert!(
        !receiver
            .notice_apply_forwarded(stranger, notice("cancelled", &sent.slate_id))
            .await
            .unwrap()
    );
    assert!(
        receiver
            .notice_apply_forwarded(from, notice("cancelled", &sent.slate_id))
            .await
            .unwrap()
    );
}
