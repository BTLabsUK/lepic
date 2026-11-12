// SPDX-License-Identifier: Apache-2.0
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
            policy: Default::default(),
            data_dir: dir.path().to_string_lossy().into_owned(),
            chain: Chain::Floonet,
            node_url: "http://127.0.0.1:1".to_owned(),
            node_api_secret: None,
            epicbox_domain: relay.to_owned(),
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
    // The new node holds every request until the end, so a call that reaches it before it
    // should shows up in its stalled calls instead of racing to finish. Which node a call
    // reached is decided under the gate; the order in which the spawned tasks see their
    // calls end is not, so it is not what this test checks.
    let other = MockBackend::new(20).unwrap();
    other.set_stalled(true);
    world.chain.backend().serve_at(OTHER_NODE, &other);

    world.chain.set_node_stalled(true);
    let send = tokio::spawn({
        let wallet = Arc::clone(&wallet);
        async move { wallet.create_send_slate(EPIC, 1, None, None).await }
    });
    assert!(eventually(|| world.chain.stalled_node_calls() > 0).await);
    let switched = tokio::spawn({
        let wallet = Arc::clone(&wallet);
        let config = WalletConfig {
            node_url: OTHER_NODE.to_owned(),
            ..config
        };
        async move { wallet.set_servers(config).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let later = tokio::spawn({
        let wallet = Arc::clone(&wallet);
        async move { wallet.summary(true).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !send.is_finished() && !switched.is_finished() && !later.is_finished(),
        "nothing ends while the send is stalled"
    );
    assert_eq!(other.stalled_calls(), 0, "nothing reaches the new node yet");

    // The send ends on the old node: had the switch gone first, it would wait on the new one.
    world.chain.set_node_stalled(false);
    send.await.unwrap().unwrap();
    switched.await.unwrap().unwrap();
    // The call made while the switch waited goes to the new node.
    assert!(eventually(|| other.stalled_calls() > 0).await);
    assert!(!later.is_finished());
    other.set_stalled(false);
    later.await.unwrap().unwrap();
    assert!(wallet.session().ensure_unlocked().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_cuts_off_a_call_the_old_node_never_answers() {
    let mut world = World::new();
    let (wallet, config) = world.funded("").await;
    let wallet = Arc::new(wallet);
    let other = MockBackend::new(15).unwrap();
    world.chain.backend().serve_at(OTHER_NODE, &other);

    // The node in use stops answering, as one behind a filtered network does, while a call
    // waits on it.
    world.chain.set_node_stalled(true);
    let waiting = tokio::spawn({
        let wallet = Arc::clone(&wallet);
        async move { wallet.summary(true).await }
    });
    assert!(eventually(|| world.chain.stalled_node_calls() > 0).await);

    let moved = WalletConfig {
        node_url: OTHER_NODE.to_owned(),
        ..config
    };
    let switched = tokio::time::timeout(
        // The grace (3 s) and some room; the old node would hold it for good.
        Duration::from_secs(8),
        wallet.set_servers(moved),
    )
    .await;
    assert!(
        matches!(switched, Ok(Ok(()))),
        "the switch ends once the call on the old node is cut off: {switched:?}"
    );
    // Cut off, it ends: with an error, or with balances not checked against the node.
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the call on the old node ends")
        .unwrap()
        .ok();
    let session = wallet.session();
    assert_eq!(session.node().get_tip().await.unwrap().height.value(), 15);
    world.chain.set_node_stalled(false);
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
#[allow(clippy::too_many_lines)] // A test reads best as one sequence of steps.
async fn the_listener_moves_to_the_new_relay_after_the_payment_in_hand() {
    let mut world = World::new();
    let (bob, bob_config) = world.wallet("one.example").await;
    let (carol_one, _) = world.wallet("one.example").await;
    let (dave, _) = world.funded("two.example").await;
    // A second output, for the second send while the first one's input is locked.
    let phrase = dave.mnemonic("password".to_owned()).await.unwrap();
    world
        .chain
        .fund(phrase, Chain::Floonet, 10 * EPIC, 1)
        .unwrap();
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

/// A listener that failed on its own reads as stopped: the switch hands nothing on, and a new
/// listener starts on the new relay and receives there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_that_ended_on_its_own_can_be_started_again_after_a_switch() {
    let mut world = World::new();
    let (bob, bob_config) = world.wallet("one.example").await;
    let (dave, _) = world.funded("two.example").await;
    let bob = bob.session();
    bob.fail_next_listen
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let handle = bob.claim_listener().unwrap().unwrap();
    assert!(bob.listen(&handle, |_| {}).await.is_err());
    assert!(!bob.listener_running());

    switch(
        bob,
        &WalletConfig {
            epicbox_domain: "two.example".to_owned(),
            ..bob_config
        },
    )
    .await
    .unwrap();
    assert!(!bob.listener_running(), "the switch started no listener");

    let received = Arc::new(Mutex::new(0));
    let handle = bob
        .claim_listener()
        .unwrap()
        .expect("a new listener starts");
    let listening = tokio::spawn({
        let (bob, received) = (Arc::clone(bob), Arc::clone(&received));
        async move {
            bob.listen(&handle, |event| {
                if event.kind == ListenerEventKind::Received {
                    *received.lock().unwrap() += 1;
                }
            })
            .await
        }
    });
    assert!(eventually(|| world.two.connections() == 1).await);
    dave.send_epicbox(EPIC, 1, address(bob).to_string(), None, None)
        .await
        .unwrap();
    assert!(eventually(|| *received.lock().unwrap() == 1).await);

    bob.stop_listener();
    tokio::time::timeout(Duration::from_secs(5), listening)
        .await
        .expect("the listener ended")
        .unwrap()
        .unwrap();
}

/// A SOCKS5 proxy that records the target of every `CONNECT` and refuses it.
#[cfg(feature = "tor")]
async fn recording_socks() -> (std::net::SocketAddr, Arc<Mutex<Vec<(String, u16)>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&targets);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                stream.read_exact(&mut greeting).await.ok()?;
                stream.write_all(&[5, 2]).await.ok()?;
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).await.ok()?;
                let mut user = vec![0u8; usize::from(length[1])];
                stream.read_exact(&mut user).await.ok()?;
                let mut pass_length = [0u8; 1];
                stream.read_exact(&mut pass_length).await.ok()?;
                let mut pass = vec![0u8; usize::from(pass_length[0])];
                stream.read_exact(&mut pass).await.ok()?;
                stream.write_all(&[1, 0]).await.ok()?;
                let mut head = [0u8; 5];
                stream.read_exact(&mut head).await.ok()?;
                let mut host = vec![0u8; usize::from(head[4])];
                stream.read_exact(&mut host).await.ok()?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await.ok()?;
                seen.lock()
                    .unwrap()
                    .push((String::from_utf8(host).ok()?, u16::from_be_bytes(port)));
                stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()
            });
        }
    });
    (address, targets)
}

/// Posts to the wallet's own address over its current relay; the post fails at the proxy.
/// Routes `host:443` to a made-up onion, as the app's settings would, and returns the onion.
#[cfg(feature = "tor")]
fn route_to_onion(session: &Session, host: &str, seed: u8) -> String {
    let onion = lepic_methods::tor::OnionAddress::from_public_key(&[seed; 32]).host();
    session
        .set_onion_routes(vec![crate::api::tor::OnionRoute {
            host: host.to_owned(),
            port: 443,
            onion: onion.clone(),
            onion_port: 443,
        }])
        .unwrap();
    onion
}

#[cfg(feature = "tor")]
async fn post_once(session: &Session) {
    let to = Destination::new(address(session).to_string());
    let wire = WireSlate::text(MediaType::JSON, "{}".to_owned());
    let posted = session
        .epicbox()
        .unwrap()
        .outbound()
        .unwrap()
        .deliver(&to, &wire)
        .await;
    assert!(posted.is_err(), "the proxy refuses every connection");
}

#[cfg(feature = "tor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_switched_to_while_over_tor_is_reached_through_tor() {
    let mut world = World::new();
    // The wallets' own connectors, not the mock relays.
    Arc::get_mut(&mut world.runtime.inner).unwrap().relay = None;
    let (wallet, config) = world.wallet("one.example").await;
    let session = wallet.session();
    let (socks, targets) = recording_socks().await;
    session.attach_relay_socks(socks);
    assert!(session.relay_through_tor());

    let onion = route_to_onion(session, "mapped.example", 3);
    let mapped = WalletConfig {
        epicbox_domain: "mapped.example".to_owned(),
        ..config.clone()
    };
    switch(session, &mapped).await.unwrap();
    post_once(session).await;
    assert_eq!(*targets.lock().unwrap(), [(onion, 443)]);

    let unmapped = WalletConfig {
        epicbox_domain: "two.example".to_owned(),
        ..config
    };
    switch(session, &unmapped).await.unwrap();
    targets.lock().unwrap().clear();
    post_once(session).await;
    assert_eq!(
        *targets.lock().unwrap(),
        [
            ("two.example".to_owned(), 443),
            ("two.example".to_owned(), 443)
        ],
        "its discovery document, then the relay itself, both through tor"
    );
}

#[cfg(feature = "tor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_switched_to_while_over_tor_is_reached_through_tor() {
    let mut world = World::new();
    Arc::get_mut(&mut world.runtime.inner).unwrap().nodes = crate::node::NodeFactory::Http;
    let (wallet, config) = world.wallet("one.example").await;
    let session = wallet.session();
    let (socks, targets) = recording_socks().await;
    session.attach_node_socks(socks);

    let onion = route_to_onion(session, "mappednode.example", 4);
    let mapped = WalletConfig {
        node_url: "https://mappednode.example".to_owned(),
        ..config.clone()
    };
    switch(session, &mapped).await.unwrap();
    assert!(session.node().get_tip().await.is_err());
    assert_eq!(targets.lock().unwrap()[0], (onion, 443));

    let unmapped = WalletConfig {
        node_url: "https://other.example:3413".to_owned(),
        ..config.clone()
    };
    switch(session, &unmapped).await.unwrap();
    targets.lock().unwrap().clear();
    assert!(session.node().get_tip().await.is_err());
    assert_eq!(
        targets.lock().unwrap()[0],
        ("other.example".to_owned(), 3413),
        "by name, so tor resolves it"
    );

    let plain = WalletConfig {
        node_url: "http://other.example".to_owned(),
        ..config
    };
    assert_eq!(
        kind(switch(session, &plain).await),
        WalletErrorKind::InvalidArgument,
        "plain http never leaves through an exit"
    );
}

#[cfg(feature = "tor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_tip_asked_while_over_tor_goes_through_tor() {
    let mut world = World::new();
    Arc::get_mut(&mut world.runtime.inner).unwrap().nodes = crate::node::NodeFactory::Http;
    let (wallet, config) = world.wallet("one.example").await;
    let (socks, targets) = recording_socks().await;
    wallet.session().attach_node_socks(socks);

    let onion = route_to_onion(wallet.session(), "mappednode.example", 4);
    let mapped = WalletConfig {
        node_url: "https://mappednode.example".to_owned(),
        node_api_secret: Some("secret".to_owned()),
        ..config.clone()
    };
    assert_eq!(
        kind(wallet.node_tip_for(mapped).await),
        WalletErrorKind::NodeUnreachable
    );
    assert_eq!(targets.lock().unwrap()[0], (onion, 443));

    targets.lock().unwrap().clear();
    let unmapped = WalletConfig {
        node_url: "https://other.example:3413".to_owned(),
        ..config
    };
    assert_eq!(
        kind(wallet.node_tip_for(unmapped).await),
        WalletErrorKind::NodeUnreachable
    );
    assert_eq!(
        targets.lock().unwrap()[0],
        ("other.example".to_owned(), 3413),
        "by name, so tor resolves it"
    );
    assert_eq!(
        wallet.session().node().get_tip().await.ok(),
        None,
        "the wallet's own node stays as it is"
    );
}

#[cfg(feature = "tor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_tip_without_a_wallet_takes_the_route_the_host_gives() {
    use crate::api::types::NodeRoute;
    let mut world = World::new();
    Arc::get_mut(&mut world.runtime.inner).unwrap().nodes = crate::node::NodeFactory::Http;
    let dir = tempfile::tempdir().unwrap();
    let config = WalletConfig {
        node_url: "https://other.example:3413".to_owned(),
        ..World::config(&dir, "one.example")
    };
    let (socks, targets) = recording_socks().await;
    let route = |socks: Option<String>| NodeRoute { socks };

    assert_eq!(
        kind(
            crate::api::wallet::node_tip(
                &world.runtime,
                config.clone(),
                route(Some(socks.to_string()))
            )
            .await
        ),
        WalletErrorKind::NodeUnreachable,
        "the proxy refuses, and nothing falls back to a direct connection"
    );
    let asked = targets.lock().unwrap().clone();
    assert!(!asked.is_empty());
    assert!(
        asked
            .iter()
            .all(|target| *target == ("other.example".to_owned(), 3413)),
        "by name, so the proxy resolves it: {asked:?}"
    );

    targets.lock().unwrap().clear();
    assert_eq!(
        kind(crate::api::wallet::node_tip(&world.runtime, config.clone(), route(None)).await),
        WalletErrorKind::NodeUnreachable
    );
    assert!(
        targets.lock().unwrap().is_empty(),
        "direct never uses the proxy"
    );

    for address in ["not an address", "localhost:9050", "10.0.0.1:9050"] {
        assert_eq!(
            kind(
                crate::api::wallet::node_tip(
                    &world.runtime,
                    config.clone(),
                    route(Some(address.to_owned()))
                )
                .await
            ),
            WalletErrorKind::InvalidArgument,
            "{address}"
        );
    }
    assert!(targets.lock().unwrap().is_empty());
}

#[cfg(feature = "tor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_tip_asked_of_a_loopback_node_while_over_tor_goes_directly() {
    let mut world = World::new();
    Arc::get_mut(&mut world.runtime.inner).unwrap().nodes = crate::node::NodeFactory::Http;
    let (wallet, config) = world.wallet("one.example").await;
    let (socks, targets) = recording_socks().await;
    wallet.session().attach_node_socks(socks);
    let node = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = node.local_addr().unwrap().port();
    let accepted = tokio::spawn(async move { node.accept().await.is_ok() });

    let local = WalletConfig {
        node_url: format!("http://127.0.0.1:{port}"),
        ..config
    };
    assert!(wallet.node_tip_for(local).await.is_err());
    assert!(accepted.await.unwrap());
    assert!(targets.lock().unwrap().is_empty(), "nothing went to tor");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_tip_is_refused_on_a_locked_wallet() {
    let mut world = World::new();
    let (wallet, config) = world.wallet("one.example").await;
    wallet.lock();
    assert_eq!(
        kind(wallet.node_tip_for(config).await),
        WalletErrorKind::Locked
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_switch_does_not_wait_for_a_node_tip_asked_of_another_node() {
    let mut world = World::new();
    let (wallet, config) = world.wallet("").await;
    let wallet = Arc::new(wallet);
    // The probed node takes every request and never answers, as a dead one behind a filtered
    // network does; the probe goes through its own backend, which a switch does not cut.
    let probed = MockBackend::new(20).unwrap();
    probed.set_stalled(true);
    world
        .chain
        .backend()
        .serve_at("http://127.0.0.1:3", &probed);
    let other = MockBackend::new(15).unwrap();
    world.chain.backend().serve_at(OTHER_NODE, &other);

    let probe = tokio::spawn({
        let wallet = Arc::clone(&wallet);
        let config = WalletConfig {
            node_url: "http://127.0.0.1:3".to_owned(),
            ..config.clone()
        };
        async move { wallet.node_tip_for(config).await }
    });
    assert!(eventually(|| probed.stalled_calls() > 0).await);

    let moved = WalletConfig {
        node_url: OTHER_NODE.to_owned(),
        ..config
    };
    let switched = tokio::time::timeout(
        // The grace (3 s) and some room; the probe would hold it for good.
        Duration::from_secs(5),
        wallet.set_servers(moved),
    )
    .await;
    assert!(
        matches!(switched, Ok(Ok(()))),
        "the switch does not wait for the probe: {switched:?}"
    );
    assert!(!probe.is_finished(), "the probe still waits on its node");
    let session = wallet.session();
    assert_eq!(session.node().get_tip().await.unwrap().height.value(), 15);
    probed.set_stalled(false);
    probe.abort();
}
