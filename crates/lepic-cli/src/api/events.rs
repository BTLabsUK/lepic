// SPDX-License-Identifier: Apache-2.0
//! `GET /v1/events`: the engine's events as server-sent events.

use std::convert::Infallible;

use futures_util::stream;
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::{Bytes, Frame};
use lepic_wallet::event::{Connection, Event, SessionState, TransportState};
use lepic_wallet::state::state_name;
use serde::Serialize;
use tokio::sync::{broadcast, watch};
use utoipa::ToSchema;

use super::{Body, InFlight};
use crate::amount::format_amount;

/// One engine event. `kind` names it, as does the event's SSE `event` field; the other fields
/// are present when the event carries them.
#[derive(Debug, Default, Serialize, ToSchema)]
pub(crate) struct EventReport {
    #[schema(value_type = String)]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slate_id: Option<String>,
    /// EPIC, as a decimal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    /// The account index.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<String>,
    /// A transaction's state before the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'static str>,
    /// A transaction's state after the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<&'static str>,
    /// A session's or a transport listener's state.
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u64>,
    /// The height a sync works towards.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Events this stream fell behind by and lost: `lagged` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    missed: Option<u64>,
}

impl EventReport {
    fn of(kind: &'static str) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    fn payment(kind: &'static str, tx_id: Option<u32>, slate_id: String) -> Self {
        Self {
            tx_id,
            slate_id: Some(slate_id),
            ..Self::of(kind)
        }
    }

    fn contact(kind: &'static str, contact_id: String) -> Self {
        Self {
            contact_id: Some(contact_id),
            ..Self::of(kind)
        }
    }
}

impl From<&Event> for EventReport {
    #[expect(clippy::too_many_lines, reason = "one arm per event")]
    fn from(event: &Event) -> Self {
        let payment = Self::payment;
        match event {
            Event::Session(state) => Self {
                state: Some(match state {
                    SessionState::Unlocked => "unlocked",
                    SessionState::Locked => "locked",
                    SessionState::Closed => "closed",
                }),
                ..Self::of("session")
            },
            Event::Balance(balance) => Self {
                account: Some(balance.account.0),
                height: Some(balance.height.value()),
                ..Self::of("balance")
            },
            Event::Transaction(change) => Self {
                tx_id: Some(change.tx_id.0),
                from: Some(state_name(change.from)),
                to: Some(state_name(change.to)),
                ..Self::of("transaction")
            },
            Event::Received(received) => Self {
                tx_id: Some(received.tx_id.0),
                slate_id: Some(received.slate_id.to_string()),
                account: Some(received.account.0),
                amount: Some(format_amount(received.amount)),
                transport: Some(received.transport.as_str().to_owned()),
                ..Self::of("received")
            },
            Event::SelfSent(sent) => Self {
                tx_id: Some(sent.tx_id.0),
                account: Some(sent.account.0),
                amount: Some(format_amount(sent.amount)),
                ..Self::of("self_sent")
            },
            Event::AnsweredAgain(answered) => Self {
                transport: Some(answered.transport.as_str().to_owned()),
                ..payment(
                    "answered_again",
                    Some(answered.tx_id.0),
                    answered.slate_id.to_string(),
                )
            },
            Event::ReplyUndelivered(reply) => payment(
                "reply_undelivered",
                Some(reply.tx_id.0),
                reply.slate_id.to_string(),
            ),
            Event::Sync(sync) => Self {
                height: Some(sync.height.value()),
                target: Some(sync.target.value()),
                ..Self::of("sync")
            },
            Event::Transport(status) => Self {
                transport: Some(status.transport.as_str().to_owned()),
                state: transport_state(status.state),
                ..Self::of(match status.connection {
                    Connection::Listener => "transport",
                    Connection::PaymentsDrain => "transport_drain",
                })
            },
            Event::TransportDisconnected(disconnect) => Self {
                transport: Some(disconnect.transport.as_str().to_owned()),
                reason: Some(disconnect.reason.clone()),
                ..Self::of("transport_disconnected")
            },
            Event::InvoiceParked(parked) => Self {
                slate_id: Some(parked.slate_id.to_string()),
                amount: Some(format_amount(parked.amount)),
                ..Self::of("invoice_parked")
            },
            Event::InvoiceFinalized(invoice) => payment(
                "invoice_finalized",
                Some(invoice.tx_id.0),
                invoice.slate_id.to_string(),
            ),
            Event::InvoiceExpired(invoice) => payment(
                "invoice_expired",
                invoice.tx_id.map(|tx_id| tx_id.0),
                invoice.slate_id.to_string(),
            ),
            Event::InvoicePosted(invoice) => payment(
                "invoice_posted",
                Some(invoice.tx_id.0),
                invoice.slate_id.to_string(),
            ),
            Event::InvoiceDeclined(invoice) => payment(
                "invoice_declined",
                Some(invoice.tx_id.0),
                invoice.slate_id.to_string(),
            ),
            Event::InvoiceWithdrawn(invoice) => payment(
                "invoice_withdrawn",
                invoice.tx_id.map(|tx_id| tx_id.0),
                invoice.slate_id.to_string(),
            ),
            Event::InvoiceBounced(invoice) => payment(
                "invoice_bounced",
                Some(invoice.tx_id.0),
                invoice.slate_id.to_string(),
            ),
            Event::UnknownSlate(unknown) => {
                payment("unknown_slate", None, unknown.slate_id.to_string())
            }
            Event::NoticeUnmatched(unmatched) => payment(
                "notice_unmatched",
                None,
                unmatched.notice.slate_id.to_string(),
            ),
            Event::ReceiveSuperseded(receive) => payment(
                "receive_superseded",
                Some(receive.tx_id.0),
                receive.slate_id.to_string(),
            ),
            Event::PaymentPosted(posted) => payment(
                "payment_posted",
                Some(posted.tx_id.0),
                posted.slate_id.to_string(),
            ),
            Event::PaymentCancelled(cancelled) => payment(
                "payment_cancelled",
                Some(cancelled.tx_id.0),
                cancelled.slate_id.to_string(),
            ),
            Event::PaymentDeclined(declined) => payment(
                "payment_declined",
                Some(declined.tx_id.0),
                declined.slate_id.to_string(),
            ),
            Event::NotPosted(not_posted) => Self {
                reason: Some(not_posted.reason.clone()),
                ..payment(
                    "not_posted",
                    Some(not_posted.tx_id.0),
                    not_posted.slate_id.to_string(),
                )
            },
            Event::PairingReplied(news) => {
                Self::contact("pairing_replied", news.contact_id.to_string())
            }
            Event::PairingConfirmed(news) => {
                Self::contact("pairing_confirmed", news.contact_id.to_string())
            }
            Event::PairingFailed(failed) => {
                Self::contact("pairing_failed", failed.contact_id.to_string())
            }
            Event::PairingRequested(_) => Self::of("pairing_requested"),
            Event::ContactUpdated(update) => {
                Self::contact("contact_updated", update.contact_id.to_string())
            }
            Event::ContactRelayMoveRequested(request) => Self::contact(
                "contact_relay_move_requested",
                request.contact_id.to_string(),
            ),
            Event::HomeRelayUnreachable(_) => Self::of("home_relay_unreachable"),
            Event::ContactKeysRestored(news) => {
                Self::contact("contact_keys_restored", news.contact_id.to_string())
            }
            Event::ContactKeysChanged(news) => {
                Self::contact("contact_keys_changed", news.contact_id.to_string())
            }
            Event::ContactUnpaired(news) => {
                Self::contact("contact_unpaired", news.contact_id.to_string())
            }
            Event::InvoiceFromContact(invoice) => Self {
                slate_id: Some(invoice.slate_id.to_string()),
                amount: Some(format_amount(invoice.amount)),
                ..Self::contact("invoice_from_contact", invoice.contact_id.to_string())
            },
            Event::WithdrawalFromContact(slate) => Self {
                tx_id: Some(slate.tx_id.0),
                slate_id: Some(slate.slate_id.to_string()),
                amount: Some(format_amount(slate.amount)),
                ..Self::contact("withdrawal_from_contact", slate.contact_id.to_string())
            },
            Event::SealedReceived(slate) => Self {
                tx_id: Some(slate.tx_id.0),
                slate_id: Some(slate.slate_id.to_string()),
                amount: Some(format_amount(slate.amount)),
                ..Self::contact("sealed_received", slate.contact_id.to_string())
            },
            Event::SealedUnopenable(news) => {
                Self::contact("sealed_unopenable", news.contact_id.to_string())
            }
            Event::OutboxDelivered(news) => Self {
                slate_id: Some(news.slate_id.to_string()),
                ..Self::contact("outbox_delivered", news.contact_id.to_string())
            },
            Event::OutboxStuck(news) => Self {
                slate_id: Some(news.slate_id.to_string()),
                ..Self::contact("outbox_stuck", news.contact_id.to_string())
            },
            Event::ContactPaymentFinalized(slate) => Self {
                tx_id: Some(slate.tx_id.0),
                slate_id: Some(slate.slate_id.to_string()),
                amount: Some(format_amount(slate.amount)),
                ..Self::contact("contact_payment_finalized", slate.contact_id.to_string())
            },
            Event::ContactPayload(news) => {
                Self::contact("contact_payload", news.contact_id.to_string())
            }
            Event::ContactPayloadsParked(news) => {
                Self::contact("contact_payloads_parked", news.contact_id.to_string())
            }
            Event::InPersonAnswer(answer) => payment(
                "in_person_answer",
                Some(answer.tx_id.0),
                answer.slate_id.to_string(),
            ),
            _ => Self::of("other"),
        }
    }
}

const fn transport_state(state: TransportState) -> Option<&'static str> {
    match state {
        TransportState::Connecting => Some("connecting"),
        TransportState::Connected => Some("connected"),
        TransportState::Disconnected => Some("disconnected"),
        TransportState::Stopped => Some("stopped"),
        _ => None,
    }
}

/// The state of the Epicbox listener that `event` reports, if it reports one.
pub(crate) fn epicbox_state(event: &Event) -> Option<&'static str> {
    match event {
        Event::Transport(status)
            if status.transport == lepic_epicbox::TRANSPORT_ID
                && status.connection == Connection::Listener =>
        {
            transport_state(status.state)
        }
        _ => None,
    }
}

/// The stream: one SSE event per engine event, until the engine stops or `closing` turns true.
/// A stream that falls behind gets a `lagged` event and goes on with the oldest event it still
/// holds.
pub(crate) fn stream(
    events: broadcast::Receiver<Event>,
    closing: watch::Receiver<bool>,
    guard: InFlight,
) -> Body {
    let state = (events, closing, guard);
    let frames = stream::unfold(state, |(mut events, mut closing, guard)| async move {
        let report = tokio::select! {
            event = events.recv() => match event {
                Ok(event) => EventReport::from(&event),
                Err(broadcast::error::RecvError::Lagged(missed)) => EventReport {
                    missed: Some(missed),
                    ..EventReport::of("lagged")
                },
                Err(broadcast::error::RecvError::Closed) => return None,
            },
            _ = closing.wait_for(|closing| *closing) => return None,
        };
        let frame = Frame::data(sse(&report));
        Some((Ok::<_, Infallible>(frame), (events, closing, guard)))
    });
    StreamBody::new(frames).boxed_unsync()
}

fn sse(report: &EventReport) -> Bytes {
    // Serializing this plain struct cannot fail.
    let data = serde_json::to_string(report).unwrap_or_default();
    Bytes::from(format!("event: {}\ndata: {data}\n\n", report.kind))
}
