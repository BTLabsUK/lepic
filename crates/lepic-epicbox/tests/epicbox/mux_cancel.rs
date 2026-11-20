// SPDX-License-Identifier: Apache-2.0
//! The `txcancel/1` extension of the mux/1 session against the mock mux relay.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::client_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_support::{ALICE, BOB, CAROL, address, sealed, secret, settings, until, within};
use lepic_epicbox::mock_mux::MuxMockRelay;
use lepic_epicbox::mock_relay::CancelForm;
use lepic_epicbox::{
    EpicboxTxId, Handled, Identity, MailboxHandler, MailboxMessage, MuxCancelOutcome, MuxCode,
    MuxError, MuxEvent, MuxOptions, MuxSession, MuxState, Network, TXCANCEL_EXTENSION,
};
use lepic_transport::transport::BoxFuture;

const LONG: Duration = Duration::from_secs(5);

fn identity(byte: u8) -> Identity {
    Identity::new(secret(byte), address(byte)).unwrap()
}

fn txid() -> EpicboxTxId {
    EpicboxTxId::generate().unwrap()
}

#[derive(Clone, Default)]
struct Txids {
    seen: Arc<Mutex<Vec<Option<EpicboxTxId>>>>,
}

impl MailboxHandler for Txids {
    fn handle(&mut self, message: MailboxMessage) -> BoxFuture<'_, Handled> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push(message.epicbox_txid().cloned());
            Handled::Stored
        })
    }
}

fn start(relay: &MuxMockRelay, identities: Vec<Identity>) -> (MuxSession, Txids) {
    let handler = Txids::default();
    let options = MuxOptions::default()
        .with_ack_window(Duration::from_millis(10))
        .with_waiting_every(None)
        .with_hold(Duration::from_secs(2));
    let session = MuxSession::start(
        settings(),
        relay.connector(),
        identities,
        handler.clone(),
        options,
    )
    .unwrap();
    (session, handler)
}

async fn attached(session: &MuxSession) {
    let mut state = session.state();
    within(LONG, state.wait_for(|state| *state == MuxState::Attached))
        .await
        .unwrap();
}

async fn cancelled_event(
    events: &mut tokio::sync::broadcast::Receiver<MuxEvent>,
) -> (usize, EpicboxTxId) {
    within(LONG, async {
        loop {
            if let MuxEvent::Cancelled { mailbox, txid } = events.recv().await.unwrap() {
                return (mailbox, txid);
            }
        }
    })
    .await
}

#[tokio::test]
async fn txcancel_is_negotiated_when_the_relay_offers_it() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, _) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    assert!(relay.cancel_negotiated());
    let details = relay.frames("ClientDetails");
    assert_eq!(
        details[0]["ext"],
        serde_json::json!([
            "mux/1",
            TXCANCEL_EXTENSION,
            "epicbox-cancel/1",
            "epicbox-attach/1"
        ])
    );
}

#[tokio::test]
async fn cancel_over_mux_is_confirmed_by_transaction_cancelled() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let id = txid();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        id.as_str(),
    );
    let (session, _) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    let outcome = within(LONG, session.cancel(&identity(BOB), &id))
        .await
        .unwrap();
    assert_eq!(outcome, MuxCancelOutcome::Cancelled);
    let frames = relay.frames("CancelTx");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["epicboxtxid"], id.as_str());
    assert_eq!(frames[0]["address"], address(BOB).key_text());
    assert_eq!(relay.unacked_cancels(&address(ALICE)), 1);
}

#[tokio::test]
async fn a_relay_that_offers_the_separated_form_gets_the_separated_signature_over_mux() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_cancel_form(true);
    let id = txid();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        id.as_str(),
    );
    let (session, _) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    let outcome = within(LONG, session.cancel(&identity(BOB), &id))
        .await
        .unwrap();
    assert_eq!(outcome, MuxCancelOutcome::Cancelled);
    assert_eq!(relay.cancel_forms(), [CancelForm::Separated]);
}

#[tokio::test]
async fn a_relay_that_does_not_offer_it_gets_the_bare_signature_over_mux() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let id = txid();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        id.as_str(),
    );
    let (session, _) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    let outcome = within(LONG, session.cancel(&identity(BOB), &id))
        .await
        .unwrap();
    assert_eq!(outcome, MuxCancelOutcome::Cancelled);
    assert_eq!(relay.cancel_forms(), [CancelForm::Bare]);
}

#[tokio::test]
async fn cancel_over_mux_of_an_unknown_txid_is_the_ambiguous_ok() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let (session, _) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    let outcome = within(LONG, session.cancel(&identity(BOB), &txid()))
        .await
        .unwrap();
    assert_eq!(outcome, MuxCancelOutcome::NotFoundOrNotParticipant);
}

#[tokio::test]
async fn cancel_over_mux_by_a_stranger_cancels_nothing() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let id = txid();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        id.as_str(),
    );
    let (session, _) = start(&relay, vec![identity(CAROL)]);
    attached(&session).await;
    let outcome = within(LONG, session.cancel(&identity(CAROL), &id))
        .await
        .unwrap();
    assert_eq!(outcome, MuxCancelOutcome::NotFoundOrNotParticipant);
    assert_eq!(relay.unacked_cancels(&address(ALICE)), 0);
}

#[tokio::test]
async fn cancel_over_mux_surfaces_the_relays_error_code() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.set_cancel_error(Some("cancel_failed"));
    let (session, _) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    let result = within(LONG, session.cancel(&identity(BOB), &txid())).await;
    assert!(matches!(
        result,
        Err(MuxError::Refused {
            code: Some(MuxCode::CancelFailed)
        })
    ));
}

#[tokio::test]
async fn without_the_extension_cancel_is_unsupported_and_nothing_is_sent() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.offer_cancel(false);
    let id = txid();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        id.as_str(),
    );
    let (session, handler) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    assert!(!relay.cancel_negotiated());
    let outcome = within(LONG, session.cancel(&identity(BOB), &id))
        .await
        .unwrap();
    assert_eq!(outcome, MuxCancelOutcome::Unsupported);
    assert_eq!(relay.received("CancelTx"), 0);
    // Mail still arrives, without a txid, as on a relay that never heard of the extension.
    until(|| !handler.seen.lock().unwrap().is_empty()).await;
    assert_eq!(handler.seen.lock().unwrap()[0], None);
}

#[tokio::test]
async fn mail_carries_the_txid_when_the_relay_negotiated_the_extension() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let id = txid();
    relay.store_with_txid(
        &address(ALICE),
        &address(BOB),
        &sealed(ALICE, BOB, "slate"),
        id.as_str(),
    );
    let (session, handler) = start(&relay, vec![identity(BOB)]);
    attached(&session).await;
    until(|| !handler.seen.lock().unwrap().is_empty()).await;
    assert_eq!(handler.seen.lock().unwrap()[0].as_ref(), Some(&id));
}

#[tokio::test]
async fn a_cancellation_is_pushed_as_an_event_and_acknowledged_on_request() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let id = txid();
    relay.store_with_txid(
        &address(BOB),
        &address(ALICE),
        &sealed(BOB, ALICE, "slate"),
        id.as_str(),
    );
    let (session, _) = start(&relay, vec![identity(ALICE)]);
    let mut events = session.events();
    attached(&session).await;
    assert!(relay.cancel_as(&address(BOB), id.as_str()));
    let (mailbox, got) = cancelled_event(&mut events).await;
    assert_eq!((mailbox, &got), (0, &id));
    assert_eq!(relay.unacked_cancels(&address(ALICE)), 1);

    session.ack_cancelled(mailbox, &got).unwrap();
    until(|| relay.unacked_cancels(&address(ALICE)) == 0).await;
    assert_eq!(relay.frames("CancelAck").len(), 1);
}

#[tokio::test]
async fn an_unacknowledged_cancellation_is_pushed_again_after_a_resume() {
    let relay = MuxMockRelay::new(Network::Mainnet);
    let id = txid();
    relay.store_with_txid(
        &address(BOB),
        &address(ALICE),
        &sealed(BOB, ALICE, "slate"),
        id.as_str(),
    );
    let (session, _) = start(&relay, vec![identity(ALICE)]);
    let mut events = session.events();
    attached(&session).await;
    assert!(relay.cancel_as(&address(BOB), id.as_str()));
    cancelled_event(&mut events).await;
    assert_eq!(relay.cancel_pushes(id.as_str()), 1);

    relay.drop_sockets();
    let (_, again) = cancelled_event(&mut events).await;
    assert_eq!(again, id);
    assert_eq!(relay.cancel_pushes(id.as_str()), 2);
}

#[tokio::test]
async fn a_pushed_cancellation_without_a_valid_txid_is_dropped_and_the_session_carries_on() {
    // 31 characters: not an id Epicmail takes, so there is nothing to acknowledge.
    const NOT_A_TXID: &str = "0123456789abcdef0123456789abcde";
    let relay = MuxMockRelay::new(Network::Mainnet);
    relay.store_with_txid(
        &address(BOB),
        &address(ALICE),
        &sealed(BOB, ALICE, "first"),
        NOT_A_TXID,
    );
    let (session, handler) = start(&relay, vec![identity(ALICE)]);
    let mut events = session.events();
    attached(&session).await;
    until(|| handler.seen.lock().unwrap().len() == 1).await;
    assert!(relay.cancel_as(&address(BOB), NOT_A_TXID));
    until(|| relay.cancel_pushes(NOT_A_TXID) == 1).await;

    let id = txid();
    relay.store_with_txid(
        &address(BOB),
        &address(ALICE),
        &sealed(BOB, ALICE, "second"),
        id.as_str(),
    );
    until(|| handler.seen.lock().unwrap().len() == 2).await;
    assert_eq!(handler.seen.lock().unwrap()[1].as_ref(), Some(&id));
    assert_eq!(*session.state().borrow(), MuxState::Attached);
    while let Ok(event) = events.try_recv() {
        assert!(!matches!(event, MuxEvent::Cancelled { .. }), "{event:?}");
    }
    assert_eq!(relay.unacked_cancels(&address(ALICE)), 1);
}

/// A cancellation of a transaction id Epicmail takes but LEPIC never makes (any 32 characters of
/// `[A-Za-z0-9_-]`, here 32 hex digits that are not a version 4 UUID, and one that is not hex)
/// is acknowledged at once with the id as the relay sent it. The consumer never sees it.
#[tokio::test]
async fn a_pushed_cancellation_of_an_id_not_of_ours_is_acknowledged_as_sent() {
    const FOREIGN: [&str; 2] = [
        "0123456789abcdef0123456789abcdef",
        "AbC_-0123456789abcdefghijklmnopq",
    ];
    let relay = MuxMockRelay::new(Network::Mainnet);
    for (n, txid) in FOREIGN.iter().enumerate() {
        relay.store_with_txid(
            &address(BOB),
            &address(ALICE),
            &sealed(BOB, ALICE, &format!("slate {n}")),
            txid,
        );
    }
    let (session, handler) = start(&relay, vec![identity(ALICE)]);
    let mut events = session.events();
    attached(&session).await;
    until(|| handler.seen.lock().unwrap().len() == FOREIGN.len()).await;
    for txid in FOREIGN {
        assert!(relay.cancel_as(&address(BOB), txid));
    }

    until(|| relay.unacked_cancels(&address(ALICE)) == 0).await;
    let echoed: Vec<String> = relay
        .frames("CancelAck")
        .iter()
        .map(|frame| frame["epicboxtxid"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(echoed, FOREIGN);
    assert_eq!(*session.state().borrow(), MuxState::Attached);
    while let Ok(event) = events.try_recv() {
        assert!(!matches!(event, MuxEvent::Cancelled { .. }), "{event:?}");
    }
}
