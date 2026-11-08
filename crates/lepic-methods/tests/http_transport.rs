// SPDX-License-Identifier: Apache-2.0
//! The HTTP method against the foreign API listener on loopback, with a wallet that answers
//! every S1 with a fixed S2.

// Helpers outside #[test] functions unwrap too; a failure there is a test failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use lepic_foreign::testing::{client_settings, listen_limits};
use lepic_methods::http::{
    ClientError, Exposure, ForeignClient, ForeignUrl, Http, ListenSettings, PlainHttp,
    ReceiveHandler, Refusal, RpcError, listen, webpki_tls_config,
};
use lepic_slate::codec::{MediaType, WireSlate};
use lepic_transport::error::TransportError;
use lepic_transport::transport::{BoxFuture, Destination, Outbound, Transport};

const S1: &str = r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[{"id":"0"}]}"#;
const S2: &str =
    r#"{"id":"0436430c-2b02-624c-2032-570501212b00","amount":"60000000000","participant_data":[]}"#;

struct Answering {
    answer: String,
}

impl ReceiveHandler for Answering {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async move {
            if slate.as_text() != Some(S1) {
                return Err(Refusal::Rejected);
            }
            Ok(WireSlate::text(MediaType::JSON, self.answer.clone()))
        })
    }
}

fn handler() -> Arc<Answering> {
    answering(S2.to_owned())
}

fn answering(answer: String) -> Arc<Answering> {
    Arc::new(Answering { answer })
}

fn client() -> ForeignClient {
    ForeignClient::new(client_settings(), webpki_tls_config().unwrap())
}

fn url(port: u16) -> ForeignUrl {
    ForeignUrl::parse(&format!("http://127.0.0.1:{port}"), PlainHttp::LoopbackOnly).unwrap()
}

fn s1() -> WireSlate {
    WireSlate::text(MediaType::JSON, S1.to_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_holds_the_answer_for_its_slate() {
    let listener = listen(
        ListenSettings::new(Exposure::LocalOnly, 0, listen_limits()),
        handler(),
    )
    .await
    .unwrap();
    let transport = Http::new(client());
    let to = Destination::new(url(listener.local_addr().port()).as_uri());
    transport.deliver(&to, &s1()).await.unwrap();
    assert_eq!(transport.take_reply("other"), None);
    let reply = transport
        .take_reply("0436430C-2B02-624C-2032-570501212B00")
        .unwrap();
    assert_eq!(reply.as_text(), Some(S2));
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b00"),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_refuses_an_answer_for_another_slate() {
    let other = S2.replace("212b00", "212b01");
    let listener = listen(
        ListenSettings::new(Exposure::LocalOnly, 0, listen_limits()),
        answering(other),
    )
    .await
    .unwrap();
    let transport = Http::new(client());
    let to = Destination::new(url(listener.local_addr().port()).as_uri());

    let error = transport.deliver(&to, &s1()).await.unwrap_err();

    let TransportError::Backend { source, .. } = error else {
        panic!("{error:?}");
    };
    assert!(matches!(
        source.downcast_ref::<ClientError>(),
        Some(ClientError::Rpc(RpcError::Malformed))
    ));
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b01"),
        None
    );
    assert_eq!(
        transport.take_reply("0436430c-2b02-624c-2032-570501212b00"),
        None
    );
}

#[test]
fn transport_hands_nothing_out_inbound() {
    let transport = Http::new(client());
    assert!(Transport::inbound(&transport).is_none());
}
