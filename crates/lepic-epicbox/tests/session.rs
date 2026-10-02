//! Session setup against the mock relay: version gating, keepalive and the TCP connector.

#![allow(clippy::unwrap_used, clippy::panic)]

mod client_support;

use std::sync::Arc;
use std::time::Duration;

use client_support::{
    ALICE, BOB, address, client, client_with, reach, sealed, settings, until, within,
};
use lepic_epicbox::mock_relay::MockRelay;
use lepic_epicbox::{
    ClientError, ConnectionState, Domain, EpicboxClient, Identity, Network, ProtocolVersion,
    RelayEndpoint, Security, TcpConnector,
};
use lepic_transport::transport::Inbound;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const LONG: Duration = Duration::from_secs(5);

#[tokio::test]
async fn relay_reporting_a_later_version_is_used_at_the_baseline() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_version(Some("3.1.0"));
    let bob = client(&relay, BOB).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    assert_eq!(
        bob.relay_version(),
        Some(ProtocolVersion {
            major: 3,
            minor: 1,
            patch: 0
        })
    );
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn relay_that_does_not_report_a_version_is_used_at_the_baseline() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_version(None);
    let mut quick = settings();
    quick.response_timeout = Duration::from_millis(300);
    relay.store(&address(ALICE), &address(BOB), &sealed(ALICE, BOB, "slate"));
    let bob = client_with(&relay, BOB, quick).drain().unwrap();
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(bob.relay_version(), None);
    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    within(LONG, bob.finished()).await.unwrap();
}

#[tokio::test]
async fn relay_older_than_the_baseline_is_refused() {
    let relay = MockRelay::new(Network::Mainnet);
    relay.set_version(Some("2.0.0"));
    let bob = client(&relay, BOB).drain().unwrap();
    assert!(matches!(
        within(LONG, bob.finished()).await,
        Err(ClientError::UnsupportedRelayVersion { version }) if version.major == 2
    ));
    assert_eq!(relay.received("Subscribe"), 0);
    assert!(matches!(
        within(LONG, client(&relay, ALICE).post(&address(BOB), "slate")).await,
        Err(ClientError::UnsupportedRelayVersion { .. })
    ));
    assert_eq!(relay.received("PostSlate"), 0);
}

#[tokio::test]
async fn listener_sends_websocket_pings() {
    let relay = MockRelay::new(Network::Mainnet);
    let mut chatty = settings();
    chatty.ping_interval = Duration::from_millis(30);
    let bob = client_with(&relay, BOB, chatty).listen().unwrap();
    reach(&bob, |s| s == ConnectionState::Subscribed).await;
    until(|| relay.pings() >= 3).await;
    assert_eq!(*bob.state().borrow(), ConnectionState::Subscribed);
    // Pings are websocket frames, never the JSON `ping` whose answer is not JSON.
    assert_eq!(relay.received("ping"), 0);
    bob.stop().await.unwrap();
}

#[tokio::test]
async fn tcp_connector_reaches_a_plain_relay() {
    let relay = MockRelay::new(Network::Mainnet);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = relay.serve(listener).unwrap();

    let tls = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(RootCertStore::empty())
    .with_no_client_auth();
    let mut over_tcp = settings();
    over_tcp.endpoint = RelayEndpoint::new(
        Domain::parse("127.0.0.1").unwrap(),
        Some(port),
        Security::Plain,
    );
    let connect = |byte| {
        let identity = Identity::new(client_support::secret(byte), address(byte)).unwrap();
        EpicboxClient::new(
            over_tcp.clone(),
            identity,
            Arc::new(TcpConnector::new(Arc::new(tls.clone()))),
        )
    };

    within(LONG, connect(ALICE).post(&address(BOB), "over tcp"))
        .await
        .unwrap();
    let bob = connect(BOB).drain().unwrap();
    let envelope = within(LONG, bob.next_envelope()).await.unwrap().unwrap();
    assert_eq!(envelope.wire().as_text(), Some("over tcp"));
    within(LONG, bob.acknowledge(envelope.ack_token()))
        .await
        .unwrap();
    within(LONG, bob.finished()).await.unwrap();
    assert_eq!(relay.pending(&address(BOB)), 0);
    server.abort();
}
