//! Moving an open wallet to another node or relay: calls running first, the next call on the
//! new node, the listener on the new relay with the new address, the old servers kept on a
//! refusal.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{
    Connector, EpicboxAddress, Network as RelayNetwork, RelayEndpoint, RelayStream,
};
use lepic_node::NodeApi as _;
use lepic_transport::transport::{Destination, Transport as _};
use lepic_wallet::slate::{MediaType, WireSlate};

use super::{eventually, kind};
use crate::api::diagnostics::LogLevel;
use crate::api::error::WalletErrorKind;
use crate::api::runtime::LepicRuntime;
use crate::api::secret_store::AppSecretStore;
use crate::api::testing::MockChain;
use crate::api::types::{Chain, ListenerEventKind, WalletConfig};
use crate::api::wallet::EpicWallet;
use crate::mock::MockBackend;
use crate::node::NodeSecret;
use crate::session::Session;

const EPIC: u64 = 100_000_000;
const OTHER_NODE: &str = "http://127.0.0.1:2";

/// Reaches the mock relay serving the endpoint's domain.
struct Relays(HashMap<String, Arc<dyn Connector>>);

impl Connector for Relays {
    fn connect<'a>(
        &'a self,
        endpoint: &'a RelayEndpoint,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn RelayStream>>> + Send + 'a>> {
        match self.0.get(endpoint.domain().as_str()) {
            Some(relay) => relay.connect(endpoint),
            None => Box::pin(async { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) }),
        }
    }
}

struct World {
    chain: MockChain,
    runtime: LepicRuntime,
    one: MockRelay,
    two: MockRelay,
    _dirs: Vec<tempfile::TempDir>,
}

impl World {
    fn new() -> Self {
        let chain = MockChain::new(1).unwrap();
        let mut runtime = chain.runtime(LogLevel::Warn).unwrap();
        let one = MockRelay::new(RelayNetwork::Floonet);
        let two = MockRelay::new(RelayNetwork::Floonet);
        let relays = Relays(HashMap::from([
            ("one.example".to_owned(), one.connector()),
            ("two.example".to_owned(), two.connector()),
        ]));
        Arc::get_mut(&mut runtime.inner).unwrap().relay = Some(Arc::new(relays));
        Self {
            chain,
            runtime,
            one,
            two,
            _dirs: Vec::new(),
        }
    }

    fn config(dir: &tempfile::TempDir, relay: &str) -> WalletConfig {
        WalletConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: relay.to_owned(),
            epicbox_port: 443,
        }
    }

    /// A new wallet on `relay` and the config it was created with.
    async fn wallet(&mut self, relay: &str) -> (EpicWallet, WalletConfig) {
        let dir = tempfile::tempdir().unwrap();
        let config = Self::config(&dir, relay);
        self._dirs.push(dir);
        let wallet = EpicWallet::create(
            &self.runtime,
            config.clone(),
            &AppSecretStore::in_memory(),
            None,
            "password".to_owned(),
        )
        .await
        .unwrap();
        (wallet, config)
    }

    /// A new wallet on `relay` holding 10 EPIC.
    async fn funded(&mut self, relay: &str) -> (EpicWallet, WalletConfig) {
        let (wallet, config) = self.wallet(relay).await;
        let phrase = wallet.mnemonic("password".to_owned()).await.unwrap();
        self.chain
            .fund(phrase, Chain::Floonet, 10 * EPIC, 0)
            .unwrap();
        self.chain.set_height(20);
        wallet.session().scan_to_tip().await;
        (wallet, config)
    }
}

async fn switch(
    session: &Session,
    config: &WalletConfig,
) -> Result<(), crate::api::error::WalletError> {
    let mut config = config.clone();
    let secret = NodeSecret::take(&mut config);
    session.set_servers(&config, &secret).await
}

fn address(session: &Session) -> EpicboxAddress {
    EpicboxAddress::parse(&session.epicbox_address().unwrap(), RelayNetwork::Floonet).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_waits_for_a_running_send_and_calls_after_it_wait_for_the_switch() {
    let mut world = World::new();
    let (wallet, config) = world.funded("").await;
    let wallet = Arc::new(wallet);
    let other = MockBackend::new(20).unwrap();
    world.chain.backend().serve_at(OTHER_NODE, &other);
    let ended = Arc::new(Mutex::new(Vec::new()));

    world.chain.set_node_stalled(true);
    let send = tokio::spawn({
        let (wallet, ended) = (Arc::clone(&wallet), Arc::clone(&ended));
        async move {
            let sent = wallet.create_send_slate(EPIC, 1, None, None).await;
            ended.lock().unwrap().push("send");
            sent
        }
    });
    assert!(eventually(|| world.chain.stalled_node_calls() > 0).await);
    let switched = tokio::spawn({
        let (wallet, ended) = (Arc::clone(&wallet), Arc::clone(&ended));
        let config = WalletConfig {
            node_url: OTHER_NODE.to_owned(),
            ..config
        };
        async move {
            let switched = wallet.set_servers(config).await;
            ended.lock().unwrap().push("switch");
            switched
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let later = tokio::spawn({
        let (wallet, ended) = (Arc::clone(&wallet), Arc::clone(&ended));
        async move {
            let summary = wallet.summary(false).await;
            ended.lock().unwrap().push("later");
            summary
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        ended.lock().unwrap().is_empty(),
        "nothing ends while the send is stalled"
    );

    world.chain.set_node_stalled(false);
    send.await.unwrap().unwrap();
    switched.await.unwrap().unwrap();
    later.await.unwrap().unwrap();
    assert_eq!(*ended.lock().unwrap(), ["send", "switch", "later"]);
    assert!(wallet.session().ensure_unlocked().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_a_node_switch_the_next_call_goes_to_the_new_node() {
    let mut world = World::new();
    let (wallet, config) = world.funded("").await;
    // Lower than the tip seen so far, which a client accepts from any node.
    let other = MockBackend::new(15).unwrap();
    world.chain.backend().serve_at(OTHER_NODE, &other);
    let session = wallet.session();
    assert_eq!(session.node().get_tip().await.unwrap().height.value(), 20);

    let moved = WalletConfig {
        node_url: OTHER_NODE.to_owned(),
        node_api_secret: Some("secret".to_owned()),
        ..config
    };
    wallet.set_servers(moved).await.unwrap();

    assert_eq!(session.node().get_tip().await.unwrap().height.value(), 15);
    assert!(session.ensure_unlocked().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_switch_keeps_the_node_and_the_relay_in_use() {
    let mut world = World::new();
    let (wallet, config) = world.wallet("one.example").await;
    world.chain.set_height(20);
    let session = wallet.session();
    let before = session.epicbox_address().unwrap();
    let refused = [
        WalletConfig {
            node_url: "ftp://node.example".to_owned(),
            epicbox_domain: "two.example".to_owned(),
            ..config.clone()
        },
        WalletConfig {
            node_url: OTHER_NODE.to_owned(),
            epicbox_domain: "not a host".to_owned(),
            ..config.clone()
        },
        WalletConfig {
            node_url: OTHER_NODE.to_owned(),
            epicbox_domain: String::new(),
            ..config.clone()
        },
        WalletConfig {
            chain: Chain::Mainnet,
            ..config.clone()
        },
        WalletConfig {
            data_dir: tempfile::tempdir()
                .unwrap()
                .path()
                .to_string_lossy()
                .into_owned(),
            ..config.clone()
        },
    ];
    let other = MockBackend::new(15).unwrap();
    world.chain.backend().serve_at(OTHER_NODE, &other);

    for config in refused {
        let described = format!("{config:?}");
        assert_eq!(
            kind(wallet.set_servers(config).await),
            WalletErrorKind::InvalidArgument,
            "{described}"
        );
        assert_eq!(session.epicbox_address().unwrap(), before, "{described}");
        assert_eq!(
            session.node().get_tip().await.unwrap().height.value(),
            20,
            "{described}"
        );
    }
}

/// Bob listens on relay one while a payment is in hand; the switch to relay two waits until it
/// is answered and acknowledged there, then the listener subscribes on relay two under Bob's
/// new address and receives the next payment, from a sender on that relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_moves_to_the_new_relay_after_the_payment_in_hand() {
    let mut world = World::new();
    let (bob, bob_config) = world.wallet("one.example").await;
    let (carol_one, _) = world.wallet("one.example").await;
    let (dave, _) = world.funded("two.example").await;
    // A second output, for the second send while the first one's input is locked.
    let phrase = dave.mnemonic("password".to_owned()).await.unwrap();
    world.chain.fund(phrase, Chain::Floonet, 10 * EPIC, 1).unwrap();
    dave.session().scan_to_tip().await;
    let bob = bob.session();
    let old_address = address(bob);
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../testdata/vectors/slates/send_epicbox_plain_s1_v3.json"
    ))
    .unwrap();
    let first = WireSlate::text(
        MediaType::JSON,
        vector["expected"]["json"].as_str().unwrap().to_owned(),
    );

    let seen = Arc::new(Mutex::new(Vec::new()));
    let all = Arc::new(Mutex::new(Vec::new()));
    let handle = bob.claim_listener().unwrap().unwrap();
    let listening = tokio::spawn({
        let (bob, seen, all) = (Arc::clone(bob), Arc::clone(&seen), Arc::clone(&all));
        async move {
            bob.listen(&handle, |event| {
                all.lock()
                    .unwrap()
                    .push(format!("{:?} {}", event.kind, event.message));
                if matches!(
                    event.kind,
                    ListenerEventKind::Received | ListenerEventKind::Repeated
                ) {
                    seen.lock().unwrap().push(event.kind);
                }
            })
            .await
        }
    });
    assert!(eventually(|| world.one.connections() == 1).await);

    world.chain.set_node_stalled(true);
    carol_one.session().epicbox_address().unwrap();
    let epicbox = carol_one.session().epicbox().unwrap();
    epicbox
        .outbound()
        .unwrap()
        .deliver(&Destination::new(old_address.to_string()), &first)
        .await
        .unwrap();
    assert!(eventually(|| world.chain.stalled_node_calls() > 0).await);
    let moved = WalletConfig {
        epicbox_domain: "two.example".to_owned(),
        ..bob_config
    };
    let switched = tokio::spawn({
        let (bob, moved) = (Arc::clone(bob), moved.clone());
        async move { switch(&bob, &moved).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !switched.is_finished(),
        "the switch waits for the payment in hand"
    );
    assert_eq!(world.one.pending(&old_address), 1);

    world.chain.set_node_stalled(false);
    tokio::time::timeout(Duration::from_secs(20), switched)
        .await
        .expect("the switch ended")
        .unwrap()
        .unwrap();
    assert_eq!(
        world.one.pending(&old_address),
        0,
        "answered and acknowledged"
    );
    assert_eq!(*seen.lock().unwrap(), [ListenerEventKind::Received]);

    let new_address = address(bob);
    assert_eq!(new_address.domain().as_str(), "two.example");
    assert_eq!(new_address.public_key(), old_address.public_key());
    assert!(eventually(|| world.two.connections() == 1 && world.one.connections() == 0).await);
    assert!(bob.listener_running());
    // Each mock relay numbers its messages from one, and Bob's inbox already holds the first
    // id from relay one; a real relay's ids do not repeat across relays.
    let elsewhere = format!(
        "{}@two.example:443",
        address(carol_one.session()).key_text()
    );
    dave.send_epicbox(EPIC, 1, elsewhere, None, None)
        .await
        .unwrap();
    dave.send_epicbox(EPIC, 1, new_address.to_string(), None, None)
        .await
        .unwrap();
    let heard = eventually(|| seen.lock().unwrap().len() == 2).await;
    assert!(heard, "{:?}", all.lock().unwrap());
    assert_eq!(
        *seen.lock().unwrap(),
        [ListenerEventKind::Received, ListenerEventKind::Received]
    );

    bob.stop_listener();
    tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();
    assert!(bob.ensure_unlocked().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_during_a_switch_stops_the_moved_listener() {
    let mut world = World::new();
    let (bob, bob_config) = world.wallet("one.example").await;
    let bob = bob.session();
    let handle = bob.claim_listener().unwrap().unwrap();
    let listening = tokio::spawn({
        let bob = Arc::clone(bob);
        async move { bob.listen(&handle, |_| {}).await }
    });
    assert!(eventually(|| world.one.connections() == 1).await);

    switch(
        bob,
        &WalletConfig {
            epicbox_domain: "two.example".to_owned(),
            ..bob_config
        },
    )
    .await
    .unwrap();
    assert!(eventually(|| world.two.connections() == 1).await);
    bob.lock();

    assert!(!bob.listener_running());
    tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();
    assert!(eventually(|| world.two.connections() == 0).await);
}
