//! The Tor transport against a fake SOCKS5 server on loopback that forwards to an in-process
//! foreign API listener, so a whole S1 → S2 exchange runs offline.

// Helpers outside #[test] functions unwrap and index too; a failure there is a test failure.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lepic_foreign::{Exposure, ListenSettings, ReceiveHandler, Refusal, RpcError, listen};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_tor::{
    FixedSocks, OnionAddress, OnionClient, OnionClientSettings, OnionError, SendFailure,
    SocksError, SocksReply, TorSendError, TorTransport,
};
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const S1: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000"}"#;
const S2: &str =
    r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[]}"#;

struct Answering;

impl ReceiveHandler for Answering {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async move {
            assert_eq!(slate.as_text(), Some(S1));
            Ok(WireSlate::text(MediaType::JSON, S2.to_owned()))
        })
    }
}

fn onion() -> OnionAddress {
    OnionAddress::from_public_key(&[42; 32])
}

fn s1() -> WireSlate {
    WireSlate::text(MediaType::JSON, S1.to_owned())
}

/// What the fake SOCKS server does after the CONNECT request.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Replies success with a domain-type bound address and forwards to this address.
    Forward(SocketAddr),
    /// Replies with this failure code.
    Fail(u8),
    /// Accepts the TCP connection and never answers.
    Silent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    username: String,
    host: String,
    port: u16,
}

struct FakeSocks {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    connections: Arc<Mutex<usize>>,
}

async fn fake_socks(behaviour: Behaviour) -> FakeSocks {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(Mutex::new(0));
    let (seen_by_server, connections_by_server) = (seen.clone(), connections.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            *connections_by_server.lock().unwrap() += 1;
            let seen = seen_by_server.clone();
            tokio::spawn(serve_socks(stream, behaviour, seen));
        }
    });
    FakeSocks {
        address,
        seen,
        connections,
    }
}

async fn serve_socks(mut stream: TcpStream, behaviour: Behaviour, seen: Arc<Mutex<Vec<Seen>>>) {
    if matches!(behaviour, Behaviour::Silent) {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return;
    }
    let mut greeting = [0u8; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 2]);
    stream.write_all(&[5, 2]).await.unwrap();
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 1);
    let mut username = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut username).await.unwrap();
    let mut length = [0u8; 1];
    stream.read_exact(&mut length).await.unwrap();
    let mut password = vec![0u8; usize::from(length[0])];
    stream.read_exact(&mut password).await.unwrap();
    stream.write_all(&[1, 0]).await.unwrap();
    let mut request = [0u8; 5];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request[..4], [5, 1, 0, 3], "connect with a domain name");
    let mut host = vec![0u8; usize::from(request[4])];
    stream.read_exact(&mut host).await.unwrap();
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.unwrap();
    seen.lock().unwrap().push(Seen {
        username: String::from_utf8(username).unwrap(),
        host: String::from_utf8(host).unwrap(),
        port: u16::from_be_bytes(port),
    });
    match behaviour {
        Behaviour::Fail(code) => {
            stream
                .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        }
        Behaviour::Forward(target) => {
            stream
                .write_all(&[5, 0, 0, 3, 4, b'h', b'o', b's', b't', 0, 80])
                .await
                .unwrap();
            let mut upstream = TcpStream::connect(target).await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        }
        Behaviour::Silent => {}
    }
}

fn transport_through(socks: SocketAddr, settings: OnionClientSettings) -> TorTransport {
    let transport = TorTransport::new(OnionClient::new(settings));
    transport.attach(Arc::new(FixedSocks(socks)));
    transport
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_an_s1_over_socks_and_holds_the_s2() {
    let listener = listen(
        ListenSettings::new(Exposure::LocalOnly, 0),
        Arc::new(Answering),
    )
    .await
    .unwrap();
    let socks = fake_socks(Behaviour::Forward(listener.local_addr())).await;
    let transport = transport_through(socks.address, OnionClientSettings::default());
    let to = Destination::new(format!("http://{}:3415/", onion()));
    transport.deliver(&to, &s1()).await.unwrap();
    let reply = transport
        .take_reply("0436430C-2B02-624C-2032-570501212B00")
        .unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b00"),
        None
    );

    let seen = socks.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "check_version, then receive_tx");
    for request in &seen {
        assert_eq!(request.host, onion().host());
        assert_eq!(request.port, 80);
    }
    assert_eq!(seen[0].username, seen[1].username, "one circuit per send");

    transport.send(&onion().to_string(), &s1()).await.unwrap();
    let seen = socks.seen.lock().unwrap().clone();
    assert_ne!(
        seen[2].username, seen[0].username,
        "a new circuit for the next send"
    );
    listener.shutdown().await;
}

#[tokio::test]
async fn tor_failure_replies_become_typed_errors() {
    for (code, reply, class) in [
        (0xF0, SocksReply::OnionNotFound, SendFailure::Unreachable),
        (
            0xF2,
            SocksReply::OnionIntroductionFailed,
            SendFailure::Unreachable,
        ),
        (
            0xF6,
            SocksReply::OnionAddressInvalid,
            SendFailure::InvalidAddress,
        ),
        (
            0xF4,
            SocksReply::OnionMissingClientAuth,
            SendFailure::ClientAuth,
        ),
        (0xF3, SocksReply::OnionRendezvousFailed, SendFailure::Broken),
        (0x01, SocksReply::GeneralFailure, SendFailure::Broken),
    ] {
        let socks = fake_socks(Behaviour::Fail(code)).await;
        let transport = transport_through(socks.address, OnionClientSettings::default());
        let error = transport
            .send(&onion().to_string(), &s1())
            .await
            .unwrap_err();
        assert!(
            matches!(&error, TorSendError::Socks(SocksError::Refused(r)) if *r == reply),
            "{code:#x}: {error:?}"
        );
        assert_eq!(error.class(), class, "{code:#x}");
    }
}

#[tokio::test]
async fn a_connect_that_never_answers_times_out_after_one_retry() {
    let socks = fake_socks(Behaviour::Silent).await;
    let settings = OnionClientSettings {
        connect_timeout: Duration::from_millis(200),
        ..OnionClientSettings::default()
    };
    let transport = transport_through(socks.address, settings);
    let error = transport
        .send(&onion().to_string(), &s1())
        .await
        .unwrap_err();
    assert!(
        matches!(error, TorSendError::Socks(SocksError::Timeout)),
        "{error:?}"
    );
    assert_eq!(error.class(), SendFailure::Unreachable);
    assert_eq!(*socks.connections.lock().unwrap(), 2);
}

#[tokio::test]
async fn refuses_to_send_without_tor() {
    let transport = TorTransport::new(OnionClient::default());
    let error = transport
        .send(&onion().to_string(), &s1())
        .await
        .unwrap_err();
    assert!(matches!(error, TorSendError::NotRunning));
    assert_eq!(error.class(), SendFailure::TorOff);

    transport.attach(Arc::new(FixedSocks("127.0.0.1:9".parse().unwrap())));
    transport.detach();
    assert!(matches!(
        transport.send(&onion().to_string(), &s1()).await,
        Err(TorSendError::NotRunning)
    ));
}

#[tokio::test]
async fn a_closed_socks_port_means_tor_is_off() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let transport = transport_through(address, OnionClientSettings::default());
    let error = transport
        .send(&onion().to_string(), &s1())
        .await
        .unwrap_err();
    assert!(
        matches!(error, TorSendError::Socks(SocksError::ProxyUnreachable(_))),
        "{error:?}"
    );
    assert_eq!(error.class(), SendFailure::TorOff);
}

#[tokio::test]
async fn refuses_an_invalid_onion_before_connecting() {
    let socks = fake_socks(Behaviour::Fail(0)).await;
    let transport = transport_through(socks.address, OnionClientSettings::default());
    let mut typo = onion().service_id().to_owned();
    typo.replace_range(0..1, if typo.starts_with('a') { "b" } else { "a" });
    let error = transport.send(&typo, &s1()).await.unwrap_err();
    assert!(
        matches!(error, TorSendError::Address(OnionError::Checksum)),
        "{error:?}"
    );
    assert!(matches!(
        transport.send("http://example.com", &s1()).await,
        Err(TorSendError::Address(OnionError::Format))
    ));
    assert_eq!(*socks.connections.lock().unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn something_that_is_not_a_wallet_is_not_epic() {
    let web = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_address = web.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = web.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
            });
        }
    });
    let socks = fake_socks(Behaviour::Forward(web_address)).await;
    let transport = transport_through(socks.address, OnionClientSettings::default());
    let error = transport
        .send(&onion().to_string(), &s1())
        .await
        .unwrap_err();
    assert_eq!(error.class(), SendFailure::NotEpic, "{error:?}");
}

/// Answers every `receive_tx` with this slate, whatever was sent.
struct AnsweringWith(&'static str);

impl ReceiveHandler for AnsweringWith {
    fn receive(&self, _slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async move { Ok(WireSlate::text(MediaType::JSON, self.0.to_owned())) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_for_another_slate_is_refused_and_not_held() {
    const OTHER_S1: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b01","amount":"1"}"#;
    const FORGED_S2: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"1"}"#;
    let honest = listen(
        ListenSettings::new(Exposure::LocalOnly, 0),
        Arc::new(Answering),
    )
    .await
    .unwrap();
    let socks = fake_socks(Behaviour::Forward(honest.local_addr())).await;
    let transport = transport_through(socks.address, OnionClientSettings::default());
    transport.send(&onion().to_string(), &s1()).await.unwrap();

    let other = listen(
        ListenSettings::new(Exposure::LocalOnly, 0),
        Arc::new(AnsweringWith(FORGED_S2)),
    )
    .await
    .unwrap();
    let other_socks = fake_socks(Behaviour::Forward(other.local_addr())).await;
    transport.attach(Arc::new(FixedSocks(other_socks.address)));
    let error = transport
        .send(
            &onion().to_string(),
            &WireSlate::text(MediaType::JSON, OTHER_S1.to_owned()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, TorSendError::Rpc(RpcError::Malformed)),
        "{error:?}"
    );
    assert_eq!(error.class(), SendFailure::NotEpic);
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b01"),
        None
    );
    let held = transport
        .take_reply("0436430c-2b02-624c-2032-570501212b00")
        .unwrap();
    assert_eq!(held.as_text(), Some(S2), "the earlier answer survives");
    honest.shutdown().await;
    other.shutdown().await;
}

#[tokio::test]
async fn a_slate_without_an_id_is_not_sent() {
    let socks = fake_socks(Behaviour::Fail(0)).await;
    let transport = transport_through(socks.address, OnionClientSettings::default());
    let error = transport
        .send(
            &onion().to_string(),
            &WireSlate::text(MediaType::JSON, "[]".to_owned()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, TorSendError::Rpc(RpcError::NotJson)),
        "{error:?}"
    );
    assert_eq!(*socks.connections.lock().unwrap(), 0);
}

#[test]
fn the_transport_hands_nothing_out_inbound() {
    let transport = TorTransport::new(OnionClient::default());
    assert!(Transport::inbound(&transport).is_none());
}
