// SPDX-License-Identifier: Apache-2.0
//! Sends to HTTP listeners in the native dialect (ADR 0052): the payer's S1 sealed to the
//! listener's key and posted to its `/v1/peer/slates`, the S2 sealed back to the slate's reply
//! key, and the key pinned once the exchange is in. The legacy dialect is taken without
//! `native_direct`, for a listener that advertises no endpoint and when asked for; a pinned
//! listener that fails is a stop, never a legacy send.

// Tests may unwrap, index and panic (docs/rules.md), including in helpers that clippy does not
// treat as test code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;
#[path = "epicbox_invoices/world.rs"]
mod world;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use lepic_keychain::{Identifier, Keychain};
use lepic_methods::http::{
    Advert, ClientSettings, DirectPeer, Exposure, Host, Http, HttpPeer, ListenLimits,
    ListenSettings, MAX_BODY_LEN, PeerClient, PeerClientError, PeerClientSettings, PeerEndpoint,
    Receiver, Refusal, RpcClient, listen_with, refuse, webpki_tls_config,
};
use lepic_methods::method::Method;
use lepic_methods::transport::{BoxFuture, Destination};
use lepic_node::Propagation;
use lepic_primitives::amount::Amount;
use lepic_primitives::params::Network;
use lepic_slate::codec::WireSlate;
use lepic_slate::model::ProofAddress;
use lepic_store::TxId;
use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};
use lepic_wallet::finalize::Finalized;
use lepic_wallet::namespace::SealKeyKind;
use lepic_wallet::selection::SelectionStrategy;
use lepic_wallet::send::{SendRequest, SentSlate};
use lepic_wallet::{ProofKey, ReceiveRequest, Received, SharedRng, WalletPolicy};
use lepic_wallet_contacts::{
    Dialect, DirectError, DirectHandler, DirectSent, NativeFailure, WalletContacts,
};
use rand::SeedableRng;
use world::{ACCOUNT, AMOUNT, ISSUER_MNEMONIC, PAYER_MNEMONIC, World};

/// The issuer's wallet as the host of its listener, receiving as `lepic listen` does.
struct Listening(Arc<World>);

impl Host for Listening {
    fn receive(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> BoxFuture<'_, Result<Received, Refusal>> {
        let method = Arc::clone(method);
        let wire = wire.clone();
        Box::pin(async move {
            self.0
                .issuer
                .wallet
                .receive_unsolicited(&method, &wire, request)
                .await
                .map_err(|error| refuse(&error))
        })
    }

    fn build_coinbase(
        &self,
        _request: CoinbaseRequest,
    ) -> BoxFuture<'_, Result<Coinbase, Refusal>> {
        Box::pin(async { Err(Refusal::Unavailable) })
    }

    fn received(&self, _received: &Received) {}

    fn refused(&self, _refusal: Refusal) {}
}

/// The payer with `native_direct` as `native` says; the issuer listens.
fn world(native: bool) -> Arc<World> {
    Arc::new(World::with_native(false, native, WalletPolicy::default()))
}

fn http() -> Http {
    let settings = ClientSettings {
        connect_timeout: Duration::from_secs(10),
        request_timeout: Duration::from_secs(30),
        max_response_bytes: MAX_BODY_LEN,
    };
    Http::new(RpcClient::new(settings, webpki_tls_config().unwrap()))
}

/// The way to native endpoints a test uses: posts may reach this computer.
fn peer(http: &Http) -> HttpPeer {
    HttpPeer::new(
        http.clone(),
        PeerClient::new(PeerClientSettings::default(), webpki_tls_config().unwrap()),
    )
}

fn listen_limits() -> ListenLimits {
    ListenLimits {
        max_connections: 16,
        max_connections_per_address: 4,
        header_timeout: Duration::from_secs(10),
        body_timeout: Duration::from_secs(15),
        request_timeout: Duration::from_secs(60),
        answer_timeout: Duration::from_secs(10),
        requests_per_minute: 120,
        receives_per_minute: 30,
    }
}

/// The issuer listening on a local port, with the native endpoint under its web listener key
/// when `endpoint` is set. Returns the listener's address and its key.
fn listening(world: &Arc<World>, endpoint: bool) -> (String, [u8; 32]) {
    let method: Arc<dyn Method> = Arc::new(http());
    let host = Arc::new(Listening(Arc::clone(world)));
    let receiver = Arc::new(Receiver::new(
        Arc::clone(&host),
        Arc::clone(&method),
        ProofKey::Payments,
    ));
    let key = world
        .issuer
        .wallet
        .listener_seal_key(SealKeyKind::Web)
        .unwrap();
    let seal = *key.public_key().as_bytes();
    let endpoint = endpoint.then(|| {
        let handler = DirectHandler::new(
            host,
            method,
            ProofKey::Payments,
            key,
            Network::Floonet,
            SharedRng::new(rand::rngs::StdRng::seed_from_u64(9)),
        );
        Arc::new(PeerEndpoint::new(Arc::new(handler), seal, Network::Floonet))
    });
    let settings = ListenSettings::new(Exposure::LocalOnly, 0, listen_limits());
    let handle = world
        .block_on(listen_with(settings, receiver, endpoint))
        .unwrap();
    // The listener stays up for the rest of the test.
    let address = format!("http://{}", handle.local_addr());
    std::mem::forget(handle);
    (address, seal)
}

fn request() -> SendRequest {
    SendRequest {
        minimum_confirmations: 1,
        strategy: SelectionStrategy::Smallest,
        ..SendRequest::new(ACCOUNT, Amount::new(AMOUNT))
    }
}

fn proof_address(mnemonic: &str) -> ProofAddress {
    let key = Keychain::from_mnemonic(mnemonic, Network::Floonet)
        .unwrap()
        .payment_proof_key(&Identifier::new(2, [0, 0, 0, 0]).unwrap(), 0)
        .unwrap();
    ProofAddress::from_bytes(key.public_key()).unwrap()
}

fn send(
    world: &World,
    peer: &HttpPeer,
    http: &Http,
    to: &str,
    request: SendRequest,
    legacy: bool,
) -> Result<DirectSent<SentSlate>, DirectError> {
    let method: Arc<dyn Method> = Arc::new(http.clone());
    world.block_on(world.payer.wallet.contact_book().direct_send(
        peer,
        &method,
        request,
        Destination::new(to.to_owned()),
        legacy,
    ))
}

fn finalize(world: &World, http: &Http, reply: &WireSlate) -> Finalized {
    let method: Arc<dyn Method> = Arc::new(http.clone());
    world
        .block_on(
            world
                .payer
                .wallet
                .finalize(&method, reply, Propagation::Fluff),
        )
        .unwrap()
}

/// The key the payer pinned for the listener at `to`.
fn pinned(world: &World, peer: &HttpPeer, to: &str) -> Option<[u8; 32]> {
    let origin = peer
        .origin(&Destination::new(to.to_owned()))
        .unwrap()
        .to_string();
    world
        .payer
        .wallet
        .peer_pin(ACCOUNT, &origin)
        .unwrap()
        .map(|pin| pin.seal_key)
}

fn pin(world: &World, peer: &HttpPeer, to: &str, seal: [u8; 32]) {
    let origin = peer
        .origin(&Destination::new(to.to_owned()))
        .unwrap()
        .to_string();
    world.payer.wallet.pin_peer(ACCOUNT, &origin, seal).unwrap();
}

#[test]
fn a_native_send_is_answered_finalized_and_pins_the_key() {
    let world = world(true);
    let (to, seal) = listening(&world, true);
    let http = http();
    let peer = peer(&http);
    assert_eq!(pinned(&world, &peer, &to), None);

    let sent = send(&world, &peer, &http, &to, request(), false).unwrap();
    assert_eq!(sent.dialect, Dialect::Native);
    assert!(!undelivered(&world, sent.sent.tx_id));
    let finalized = finalize(&world, &http, sent.reply.as_ref().unwrap());
    assert_eq!(finalized.tx_id, sent.sent.tx_id);
    assert!(finalized.pushed);
    assert_eq!(pinned(&world, &peer, &to), Some(seal));
    // The foreign API kept no answer: the slate never went through it.
    assert!(http.take_reply(&sent.sent.slate_id.to_string()).is_none());
}

#[test]
fn a_native_send_carries_the_listeners_payment_proof() {
    let world = world(true);
    let (to, _) = listening(&world, true);
    let http = http();
    let peer = peer(&http);
    let request = SendRequest {
        payment_proof_recipient: Some(proof_address(ISSUER_MNEMONIC)),
        ..request()
    };

    let sent = send(&world, &peer, &http, &to, request, false).unwrap();
    assert_eq!(sent.dialect, Dialect::Native);
    let finalized = finalize(&world, &http, sent.reply.as_ref().unwrap());
    let proof = finalized.slate.payment_proof().unwrap();
    assert_eq!(proof.receiver_address, proof_address(ISSUER_MNEMONIC));
    assert!(proof.receiver_signature.is_some());
}

#[test]
fn a_payment_proof_for_another_address_is_refused_and_pins_nothing() {
    let world = world(true);
    let (to, _) = listening(&world, true);
    let http = http();
    let peer = peer(&http);
    let request = SendRequest {
        payment_proof_recipient: Some(proof_address(PAYER_MNEMONIC)),
        ..request()
    };

    let error = send(&world, &peer, &http, &to, request, false).unwrap_err();
    assert!(
        matches!(
            error,
            DirectError::Native {
                source: NativeFailure::Post(PeerClientError::Refused),
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(pinned(&world, &peer, &to), None);
}

#[test]
fn without_native_direct_the_send_is_legacy_and_pins_nothing() {
    let world = world(false);
    let (to, _) = listening(&world, true);
    let http = http();
    let peer = peer(&http);

    let sent = send(&world, &peer, &http, &to, request(), false).unwrap();
    assert_eq!(sent.dialect, Dialect::Legacy);
    assert!(sent.reply.is_none());
    let reply = http.take_reply(&sent.sent.slate_id.to_string()).unwrap();
    finalize(&world, &http, &reply);
    assert_eq!(pinned(&world, &peer, &to), None);
}

#[test]
fn a_listener_without_an_endpoint_gets_a_legacy_send() {
    let world = world(true);
    let (to, _) = listening(&world, false);
    let http = http();
    let peer = peer(&http);

    let sent = send(&world, &peer, &http, &to, request(), false).unwrap();
    assert_eq!(sent.dialect, Dialect::Legacy);
    let reply = http.take_reply(&sent.sent.slate_id.to_string()).unwrap();
    finalize(&world, &http, &reply);
    assert_eq!(pinned(&world, &peer, &to), None);
}

#[test]
fn a_pinned_listener_without_an_endpoint_stops_the_send() {
    let world = world(true);
    let (to, _) = listening(&world, false);
    let http = http();
    let peer = peer(&http);
    pin(&world, &peer, &to, [9; 32]);

    let error = send(&world, &peer, &http, &to, request(), false).unwrap_err();
    assert!(
        matches!(error, DirectError::PinnedNoAdvert { .. }),
        "{error:?}"
    );
}

#[test]
fn a_pinned_key_that_changed_stops_the_send_naming_both_keys() {
    let world = world(true);
    let (to, seal) = listening(&world, true);
    let http = http();
    let peer = peer(&http);
    pin(&world, &peer, &to, [9; 32]);

    let error = send(&world, &peer, &http, &to, request(), false).unwrap_err();
    match error {
        DirectError::PinChanged { pinned, shown, .. } => {
            assert_eq!(pinned, [9; 32]);
            assert_eq!(shown, seal);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(pinned(&world, &peer, &to), Some([9; 32]));
}

#[test]
fn the_legacy_flag_sends_legacy_to_a_pinned_listener() {
    let world = world(true);
    let (to, seal) = listening(&world, true);
    let http = http();
    let peer = peer(&http);
    pin(&world, &peer, &to, seal);

    let sent = send(&world, &peer, &http, &to, request(), true).unwrap();
    assert_eq!(sent.dialect, Dialect::Legacy);
    let reply = http.take_reply(&sent.sent.slate_id.to_string()).unwrap();
    finalize(&world, &http, &reply);
}

#[test]
fn a_native_post_never_reaches_this_computer() {
    let world = world(true);
    let (to, _) = listening(&world, true);
    let http = http();
    let peer = HttpPeer::new(
        http.clone(),
        PeerClient::to_other_computers(PeerClientSettings::default(), webpki_tls_config().unwrap()),
    );

    let error = send(&world, &peer, &http, &to, request(), false).unwrap_err();
    assert!(
        matches!(
            error,
            DirectError::Native {
                source: NativeFailure::Post(PeerClientError::ThisComputer { .. }),
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(pinned(&world, &peer, &to), None);
}

/// How the fake listener answers a post to its native endpoint.
#[derive(Clone, Copy)]
enum Answer {
    Status(u16),
    /// The connection closes once the request is read.
    Close,
}

/// A listener that advertises an endpoint under `seal`, if any, and answers posts to it as
/// `answer` says, counting the `check_version` and `receive_tx` calls its foreign API gets.
struct Fake {
    address: String,
    versions: Arc<AtomicU32>,
    receives: Arc<AtomicU32>,
    posts: Arc<AtomicU32>,
}

fn fake(seal: Option<[u8; 32]>, answer: Answer) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let versions = Arc::new(AtomicU32::new(0));
    let receives = Arc::new(AtomicU32::new(0));
    let posts = Arc::new(AtomicU32::new(0));
    let counted_versions = Arc::clone(&versions);
    let (counted_receives, counted_posts) = (Arc::clone(&receives), Arc::clone(&posts));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some((path, body)) = read_request(&stream) else {
                continue;
            };
            if path == "/v2/foreign" {
                let call: serde_json::Value = serde_json::from_slice(&body).unwrap();
                if call["method"] == "receive_tx" {
                    counted_receives.fetch_add(1, Ordering::SeqCst);
                    write_answer(&mut stream, 500, b"");
                    continue;
                }
                counted_versions.fetch_add(1, Ordering::SeqCst);
                let mut answered = serde_json::json!({
                    "foreign_api_version": 2,
                    "supported_slate_versions": ["V3", "V2"],
                });
                if let Some(seal) = seal {
                    answered["lepic"] = Advert::new(seal).to_json();
                }
                let version = serde_json::json!({
                    "id": call["id"],
                    "jsonrpc": "2.0",
                    "result": {"Ok": answered},
                });
                write_answer(&mut stream, 200, version.to_string().as_bytes());
            } else {
                counted_posts.fetch_add(1, Ordering::SeqCst);
                match answer {
                    Answer::Status(status) => write_answer(&mut stream, status, b""),
                    Answer::Close => drop(stream),
                }
            }
        }
    });
    Fake {
        address,
        versions,
        receives,
        posts,
    }
}

/// The path and body of the request on `stream`.
fn read_request(stream: &TcpStream) -> Option<(String, Vec<u8>)> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let path = line.split(' ').nth(1)?.to_owned();
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some((path, body))
}

fn write_answer(stream: &mut TcpStream, status: u16, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status} Answer\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

/// A send to a pinned listener whose endpoint answers as `answer` says: a stop, with no
/// legacy `receive_tx` made, and the stored send shown as undelivered.
fn failing_post(answer: Answer) -> PeerClientError {
    let world = world(true);
    let http = http();
    let peer = peer(&http);
    let fake = fake(Some([4; 32]), answer);
    pin(&world, &peer, &fake.address, [4; 32]);

    let error = send(&world, &peer, &http, &fake.address, request(), false).unwrap_err();
    assert_eq!(fake.posts.load(Ordering::SeqCst), 1);
    assert_eq!(fake.receives.load(Ordering::SeqCst), 0);
    match error {
        DirectError::Native {
            tx_id,
            source: NativeFailure::Post(error),
            ..
        } => {
            assert!(undelivered(&world, tx_id));
            error
        }
        other => panic!("{other:?}"),
    }
}

/// Whether the payer's send `tx_id` waits for a delivery.
fn undelivered(world: &World, tx_id: TxId) -> bool {
    world
        .block_on(world.payer.wallet.transaction_details(tx_id))
        .unwrap()
        .undelivered
}

#[test]
fn a_pinned_listener_answering_415_stops_the_send() {
    let error = failing_post(Answer::Status(415));
    assert!(
        matches!(error, PeerClientError::UnsupportedFormat),
        "{error:?}"
    );
}

#[test]
fn a_pinned_listener_answering_503_stops_the_send() {
    let error = failing_post(Answer::Status(503));
    assert!(
        matches!(error, PeerClientError::NotReady { .. }),
        "{error:?}"
    );
}

#[test]
fn a_pinned_listener_closing_the_connection_stops_the_send() {
    let error = failing_post(Answer::Close);
    assert!(
        matches!(error, PeerClientError::Unreachable(_)),
        "{error:?}"
    );
}

#[test]
fn a_legacy_send_after_a_probe_asks_the_listener_for_its_version_once() {
    let world = world(true);
    let http = http();
    let peer = peer(&http);
    let fake = fake(None, Answer::Status(503));

    // The fake listener refuses every `receive_tx`, so the legacy send fails once it is made.
    let error = send(&world, &peer, &http, &fake.address, request(), false).unwrap_err();
    assert!(matches!(error, DirectError::Send(_)), "{error:?}");
    assert_eq!(fake.versions.load(Ordering::SeqCst), 1);
    assert_eq!(fake.receives.load(Ordering::SeqCst), 1);
    assert_eq!(fake.posts.load(Ordering::SeqCst), 0);
}
