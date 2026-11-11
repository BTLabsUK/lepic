// SPDX-License-Identifier: Apache-2.0
//! A wallet opened with `WalletConfig::offline`: its node and relay refuse every call with
//! `Offline` before any connect, a send by slate text is made, answered by an online wallet and
//! finalized without a post, and its finished payment reads back as the S3 through
//! `inspect_slate` and the `ur:epic-slate` codec.

use std::sync::Arc;

use lepic_epicbox::Network as RelayNetwork;
use lepic_epicbox::mock_relay::MockRelay;

use super::kind;
use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, SlateStage, WalletConfig};
use crate::api::wallet::{EpicWallet, decode_ur_slate, encode_ur_slate, inspect_slate};

const EPIC: u64 = 100_000_000;

struct World {
    chain: MockChain,
    relay: MockRelay,
    runtime: LepicRuntime,
    dirs: Vec<tempfile::TempDir>,
}

impl World {
    fn new() -> Self {
        let chain = MockChain::new(1).unwrap();
        let mut runtime = chain.runtime(LogLevel::Warn).unwrap();
        let relay = MockRelay::new(RelayNetwork::Floonet);
        Arc::get_mut(&mut runtime.inner).unwrap().relay = Some(relay.connector());
        Self {
            chain,
            relay,
            runtime,
            dirs: Vec::new(),
        }
    }

    fn config(&mut self) -> WalletConfig {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().into_owned();
        self.dirs.push(dir);
        WalletConfig {
            policy: Default::default(),
            data_dir,
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
            domain: None,
        }
    }

    async fn create(&self, config: &WalletConfig, store: &AppSecretStore) -> EpicWallet {
        EpicWallet::create(
            &self.runtime,
            config.clone(),
            store,
            None,
            None,
            "password".to_owned(),
        )
        .await
        .unwrap()
    }

    async fn open(&self, config: &WalletConfig, store: &AppSecretStore) -> EpicWallet {
        EpicWallet::open(&self.runtime, config.clone(), store, "password".to_owned())
            .await
            .unwrap()
    }
}

/// A funded wallet that refreshed online, opened again offline.
async fn cold_wallet(world: &mut World) -> (EpicWallet, WalletConfig) {
    let config = world.config();
    let store = AppSecretStore::in_memory();
    let online = world.create(&config, &store).await;
    let phrase = online.mnemonic("password".to_owned()).await.unwrap();
    world
        .chain
        .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
        .unwrap();
    world.chain.set_height(20);
    online.session().scan_to_tip().await;
    online.summary(true).await.unwrap();
    drop(online);
    let offline = WalletConfig {
        offline: true,
        tor_wanted: false,
        host_features: 0,
        profile: 0,
        domain: None,
        ..config
    };
    (world.open(&offline, &store).await, offline)
}

#[tokio::test]
async fn an_offline_wallet_pays_by_slate_text_without_reaching_the_node_or_relay() {
    let mut world = World::new();
    let (cold, _) = cold_wallet(&mut world).await;
    let config = world.config();
    let receiver = world.create(&config, &AppSecretStore::in_memory()).await;
    // Any request that reaches the mock node from here on panics inside its operation.
    world.chain.panic_on_next_node_call();

    let s1 = cold.create_send_slate(EPIC, 1, None, None).await.unwrap();
    assert_eq!(
        kind(cold.summary(true).await),
        WalletErrorKind::Offline,
        "a refresh"
    );
    assert_eq!(
        kind(cold.drain_epicbox().await),
        WalletErrorKind::Offline,
        "an epicbox drain"
    );
    assert_eq!(world.relay.connections(), 0);
    // The online receiver's first node request takes the panic, so none of the offline
    // calls above reached the node.
    assert_eq!(
        kind(receiver.receive_slate(s1.json.clone()).await),
        WalletErrorKind::Panic
    );
    let s2 = receiver.receive_slate(s1.json).await.unwrap();

    let finalized = cold.finalize_and_post(s2.json).await.unwrap();

    assert_eq!(finalized.tx_id, s1.tx_id);
    assert!(!finalized.posted);
    assert_eq!(world.chain.pushed_count(), 0);
    let finished = cold.finished_payment(s1.tx_id).await.unwrap();
    let info = inspect_slate(finished.clone(), Chain::Floonet).unwrap();
    assert_eq!(info.stage, SlateStage::S3);
    assert_eq!(info.version, 3);
    assert_eq!(info.amount, EPIC);
    let parts = encode_ur_slate(finished.clone(), Chain::Floonet, 200, None).unwrap();
    let decoded = decode_ur_slate(parts).unwrap().json.unwrap();
    let read = inspect_slate(decoded, Chain::Floonet).unwrap();
    assert_eq!(
        (read.stage, read.slate_id, read.amount, read.fee),
        (info.stage, info.slate_id, info.amount, info.fee)
    );
}

#[tokio::test]
async fn an_online_wallet_posts_when_it_finalizes() {
    let mut world = World::new();
    let config = world.config();
    let store = AppSecretStore::in_memory();
    let sender = world.create(&config, &store).await;
    let phrase = sender.mnemonic("password".to_owned()).await.unwrap();
    world
        .chain
        .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
        .unwrap();
    world.chain.set_height(20);
    sender.session().scan_to_tip().await;
    let receiver_config = world.config();
    let receiver = world
        .create(&receiver_config, &AppSecretStore::in_memory())
        .await;

    let s1 = sender.create_send_slate(EPIC, 1, None, None).await.unwrap();
    let s2 = receiver.receive_slate(s1.json).await.unwrap();
    let finalized = sender.finalize_and_post(s2.json).await.unwrap();

    assert!(finalized.posted);
    assert_eq!(world.chain.pushed_count(), 1);
}

#[tokio::test]
async fn offline_changes_only_by_opening_the_wallet_again() {
    let mut world = World::new();
    let (cold, offline) = cold_wallet(&mut world).await;
    let online = WalletConfig {
        offline: false,
        tor_wanted: false,
        host_features: 0,
        profile: 0,
        domain: None,
        ..offline.clone()
    };

    assert_eq!(
        kind(cold.set_servers(online.clone()).await),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(cold.node_tip_for(online).await),
        WalletErrorKind::InvalidArgument
    );
    assert_eq!(
        kind(cold.node_tip_for(offline).await),
        WalletErrorKind::Offline
    );
}
